package xhttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tearsful/outbound/netproxy"
)

// XHTTPConfig 定义 XHTTP 传输层配置
type XHTTPConfig struct {
	Host               string
	Path               string
	Headers            map[string]string
	MaxEachPostBytes   int64
	MinPostsIntervalMs int64
	Mode               string // auto, stream-one, stream-up, stream-down, packet-up
	DownloadSettings   *XHTTPConfig
	Xmux               *XmuxConfig
	OnNfsPKeys         func(keys [][]byte)
}

type XmuxConfig struct {
	Enabled              bool
	Concurrency          int32
	IdleTimeout          int32
	HKeepAlivePeriod     int32
	MaxConcurrentStreams int32
}

type XHTTPDialer struct {
	config *XHTTPConfig
	client *http.Client
}

func NewXHTTPDialer(config *XHTTPConfig) (*XHTTPDialer, error) {
	if config == nil {
		config = &XHTTPConfig{
			Path:             "/",
			MaxEachPostBytes: 32 * 1024,
			Mode:             "auto",
		}
	}
	if config.Path == "" {
		config.Path = "/"
	}
	if config.MaxEachPostBytes <= 0 {
		config.MaxEachPostBytes = 32 * 1024
	}
	if config.Mode == "" {
		config.Mode = "auto"
	}
	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  true,
			MaxIdleConnsPerHost: 10,
			ForceAttemptHTTP2:   true,
		},
	}

	return &XHTTPDialer{config: config, client: client}, nil
}

func (d *XHTTPDialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	hostPort, err := resolveXHTTPHostPort(d.config, address)
	if err != nil {
		return nil, err
	}

	requestURL := &url.URL{
		Scheme: "https",
		Host:   hostPort,
		Path:   d.config.Path,
	}
	if len(d.config.Headers) > 0 {
		query := requestURL.Query()
		for key, value := range d.config.Headers {
			query.Set(key, value)
		}
		requestURL.RawQuery = query.Encode()
	}

	switch strings.ToLower(d.config.Mode) {
	case "stream-one", "stream-up":
		return d.dialBidirectionalStream(ctx, requestURL.String())
	case "stream-down":
		return d.dialStreamDown(ctx, requestURL.String())
	case "packet-up", "auto":
		return d.dialPacketMode(ctx, requestURL.String())
	default:
		return d.dialPacketMode(ctx, requestURL.String())
	}
}

func resolveXHTTPHostPort(config *XHTTPConfig, address string) (string, error) {
	hostPort := address
	if config != nil && config.Host != "" {
		hostPort = config.Host
		if _, _, err := net.SplitHostPort(hostPort); err != nil {
			if _, port, splitErr := net.SplitHostPort(address); splitErr == nil {
				hostPort = net.JoinHostPort(config.Host, port)
			}
		}
	}
	if _, _, err := net.SplitHostPort(hostPort); err != nil {
		return "", fmt.Errorf("invalid xhttp host/address: %v", err)
	}
	return hostPort, nil
}

func (d *XHTTPDialer) applyHeaders(req *http.Request) {
	for key, value := range d.config.Headers {
		req.Header.Set(key, value)
	}
}

func (d *XHTTPDialer) maybeNotifyNfsKeys(header http.Header) {
	if d.config == nil || d.config.OnNfsPKeys == nil {
		return
	}
	if nfs := header.Get("X-NfsPKeys"); nfs != "" {
		if keys, err := parseNfsPKeysCSVBase64(nfs); err == nil && len(keys) > 0 {
			d.config.OnNfsPKeys(keys)
		}
	}
}

type streamDialResult struct {
	body io.ReadCloser
	err  error
}

// dialBidirectionalStream uploads via the request body and downloads via the
// response body. The HTTP round-trip starts asynchronously so Write() can
// begin before response headers arrive.
func (d *XHTTPDialer) dialBidirectionalStream(ctx context.Context, requestURL string) (netproxy.Conn, error) {
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, pr)
	if err != nil {
		_ = pw.Close()
		return nil, fmt.Errorf("failed to create stream request: %w", err)
	}
	d.applyHeaders(req)
	req.Header.Set("Content-Type", "application/octet-stream")

	ch := make(chan streamDialResult, 1)
	go func() {
		resp, err := d.client.Do(req)
		if err != nil {
			_ = pr.CloseWithError(err)
			ch <- streamDialResult{err: err}
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			_ = resp.Body.Close()
			err := fmt.Errorf("unexpected stream status %d: %s", resp.StatusCode, string(body))
			_ = pr.CloseWithError(err)
			ch <- streamDialResult{err: err}
			return
		}
		d.maybeNotifyNfsKeys(resp.Header)
		ch <- streamDialResult{body: resp.Body}
	}()

	return &xhttpStreamConn{
		writer: pw,
		ready:  ch,
		ctx:    ctx,
	}, nil
}

func (d *XHTTPDialer) dialStreamDown(ctx context.Context, requestURL string) (netproxy.Conn, error) {
	return d.dialPacketMode(ctx, requestURL)
}

func (d *XHTTPDialer) dialPacketMode(ctx context.Context, requestURL string) (netproxy.Conn, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create download request: %w", err)
	}
	d.applyHeaders(req)

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download stream failed: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		return nil, fmt.Errorf("unexpected download status %d: %s", resp.StatusCode, string(body))
	}
	d.maybeNotifyNfsKeys(resp.Header)

	return &xhttpPacketConn{
		download: resp.Body,
		url:      requestURL,
		client:   d.client,
		config:   d.config,
		ctx:      ctx,
	}, nil
}

type xhttpStreamConn struct {
	writer *io.PipeWriter
	ready  <-chan streamDialResult
	ctx    context.Context

	readerOnce sync.Once
	reader     io.ReadCloser
	readerErr  error
	closeOnce  sync.Once
}

func (c *xhttpStreamConn) waitReader() error {
	c.readerOnce.Do(func() {
		select {
		case <-c.ctx.Done():
			c.readerErr = c.ctx.Err()
		case res := <-c.ready:
			if res.err != nil {
				c.readerErr = res.err
				return
			}
			c.reader = res.body
		}
	})
	return c.readerErr
}

func (c *xhttpStreamConn) Read(b []byte) (int, error) {
	if err := c.waitReader(); err != nil {
		return 0, err
	}
	return c.reader.Read(b)
}

func (c *xhttpStreamConn) Write(b []byte) (int, error) { return c.writer.Write(b) }

func (c *xhttpStreamConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if e := c.writer.Close(); e != nil {
			err = e
		}
		_ = c.waitReader()
		if c.reader != nil {
			if e := c.reader.Close(); e != nil && err == nil {
				err = e
			}
		}
	})
	return err
}

func (c *xhttpStreamConn) CloseWrite() error                 { return c.writer.Close() }
func (c *xhttpStreamConn) LocalAddr() net.Addr               { return &net.TCPAddr{} }
func (c *xhttpStreamConn) RemoteAddr() net.Addr              { return &net.TCPAddr{} }
func (c *xhttpStreamConn) SetDeadline(t time.Time) error     { return nil }
func (c *xhttpStreamConn) SetReadDeadline(t time.Time) error { return nil }
func (c *xhttpStreamConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type xhttpPacketConn struct {
	download io.ReadCloser
	url      string
	client   *http.Client
	config   *XHTTPConfig
	ctx      context.Context
	mu       sync.Mutex
	closed   bool
	lastPost time.Time
}

func (c *xhttpPacketConn) Read(b []byte) (int, error) { return c.download.Read(b) }

func (c *xhttpPacketConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	if len(b) == 0 {
		return 0, nil
	}

	max := int(c.config.MaxEachPostBytes)
	if max <= 0 {
		max = 32 * 1024
	}
	written := 0
	for written < len(b) {
		if c.config.MinPostsIntervalMs > 0 && !c.lastPost.IsZero() {
			wait := time.Duration(c.config.MinPostsIntervalMs)*time.Millisecond - time.Since(c.lastPost)
			if wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-c.ctx.Done():
					timer.Stop()
					return written, c.ctx.Err()
				case <-timer.C:
				}
			}
		}

		end := written + max
		if end > len(b) {
			end = len(b)
		}
		chunk := b[written:end]
		req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, c.url, bytes.NewReader(chunk))
		if err != nil {
			return written, err
		}
		for key, value := range c.config.Headers {
			req.Header.Set(key, value)
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := c.client.Do(req)
		if err != nil {
			return written, err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return written, fmt.Errorf("upload status %d", resp.StatusCode)
		}
		c.lastPost = time.Now()
		written = end
	}
	return written, nil
}

func (c *xhttpPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.download != nil {
		return c.download.Close()
	}
	return nil
}

func (c *xhttpPacketConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *xhttpPacketConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *xhttpPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *xhttpPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *xhttpPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func ParseXHTTPConfig(rawURL string) (*XHTTPConfig, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}
	config := &XHTTPConfig{
		Host:    u.Host,
		Path:    u.Path,
		Headers: make(map[string]string),
	}
	query := u.Query()
	if path := query.Get("path"); path != "" {
		config.Path = path
	}
	if mode := query.Get("mode"); mode != "" {
		config.Mode = mode
	}
	if maxBytes := query.Get("maxEachPostBytes"); maxBytes != "" {
		if val, err := strconv.ParseInt(maxBytes, 10, 64); err == nil {
			config.MaxEachPostBytes = val
		}
	}
	if minInterval := query.Get("minPostsIntervalMs"); minInterval != "" {
		if val, err := strconv.ParseInt(minInterval, 10, 64); err == nil {
			config.MinPostsIntervalMs = val
		}
	}
	if headers := query.Get("headers"); headers != "" {
		for _, pair := range strings.Split(headers, ",") {
			if kv := strings.SplitN(pair, ":", 2); len(kv) == 2 {
				config.Headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}
	return config, nil
}

func parseNfsPKeysCSVBase64(csv string) ([][]byte, error) {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil, nil
	}
	parts := strings.Split(csv, ",")
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if b, err := base64.RawURLEncoding.DecodeString(p); err == nil {
			out = append(out, b)
			continue
		}
		if b, err := base64.StdEncoding.DecodeString(p); err == nil {
			out = append(out, b)
		}
	}
	return out, nil
}
