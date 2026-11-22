package xhttp

import (
	"bytes"
	"context"
	"crypto/tls"
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
	// TLS knobs used when the underlay is plain TCP (not Reality/TLS).
	ServerName    string
	AllowInsecure bool
	// UseH3 enables HTTP/3 (QUIC). Incompatible with TCP underlays (e.g. Reality).
	UseH3 bool
}

type XmuxConfig struct {
	Enabled              bool
	Concurrency          int32
	IdleTimeout          int32
	HKeepAlivePeriod     int32
	MaxConcurrentStreams int32
}

// DialerOptions wires an underlay dialer (TCP / TLS / Reality) into the HTTP client.
type DialerOptions struct {
	Underlay   netproxy.Dialer
	AlreadyTLS bool // underlay already completed TLS (e.g. Reality)
	Mark       uint32
	Mptcp      bool
}

type XHTTPDialer struct {
	config *XHTTPConfig
	client *http.Client
	opts   DialerOptions
}

func NewXHTTPDialer(config *XHTTPConfig) (*XHTTPDialer, error) {
	return NewXHTTPDialerWithOptions(config, nil)
}

func NewXHTTPDialerWithOptions(config *XHTTPConfig, opts *DialerOptions) (*XHTTPDialer, error) {
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

	d := &XHTTPDialer{config: config}
	if opts != nil {
		d.opts = *opts
	}
	tr, err := d.buildRoundTripper()
	if err != nil {
		return nil, err
	}
	d.client = &http.Client{
		Timeout:   0, // long-lived streams
		Transport: tr,
	}
	return d, nil
}

func (d *XHTTPDialer) tlsConfig() *tls.Config {
	sni := d.config.ServerName
	if sni == "" {
		if host := d.config.Headers["Host"]; host != "" {
			sni = host
		} else if h, _, err := net.SplitHostPort(d.config.Host); err == nil {
			sni = h
		} else {
			sni = d.config.Host
		}
	}
	return &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: d.config.AllowInsecure, //nolint:gosec // user-configured
		NextProtos:         []string{"h2", "http/1.1"},
	}
}

func (d *XHTTPDialer) applyXmux(tr *http.Transport) {
	xmux := d.config.Xmux
	if xmux == nil || !xmux.Enabled {
		return
	}
	if xmux.Concurrency > 0 {
		tr.MaxIdleConnsPerHost = int(xmux.Concurrency)
		tr.MaxConnsPerHost = int(xmux.Concurrency)
	}
	if xmux.IdleTimeout > 0 {
		tr.IdleConnTimeout = time.Duration(xmux.IdleTimeout) * time.Second
	}
}

func (d *XHTTPDialer) buildRoundTripper() (http.RoundTripper, error) {
	if d.config.UseH3 {
		if d.opts.Underlay != nil {
			return nil, fmt.Errorf("xhttp: HTTP/3 is incompatible with TCP underlay dialers")
		}
		return newH3RoundTripper(d.tlsConfig()), nil
	}

	tr := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		MaxIdleConnsPerHost: 10,
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     d.tlsConfig(),
	}
	d.applyXmux(tr)

	if d.opts.Underlay == nil {
		return tr, nil
	}

	dialUnderlay := func(ctx context.Context, addr string) (net.Conn, error) {
		tcpNetwork := netproxy.MagicNetwork{
			Network: "tcp",
			Mark:    d.opts.Mark,
			Mptcp:   d.opts.Mptcp,
		}.Encode()
		c, err := d.opts.Underlay.DialContext(ctx, tcpNetwork, addr)
		if err != nil {
			return nil, err
		}
		return &netproxy.FakeNetConn{Conn: c}, nil
	}

	if d.opts.AlreadyTLS {
		// Reality/TLS underlay: HTTP speaks over the already-secured conn.
		tr.DialTLSContext = func(ctx context.Context, _network, addr string) (net.Conn, error) {
			return dialUnderlay(ctx, addr)
		}
	} else {
		tr.DialContext = func(ctx context.Context, _network, addr string) (net.Conn, error) {
			return dialUnderlay(ctx, addr)
		}
	}
	return tr, nil
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

	switch strings.ToLower(d.config.Mode) {
	case "stream-one":
		return d.dialBidirectionalStream(ctx, requestURL.String())
	case "stream-up":
		return d.dialStreamUp(ctx, requestURL.String())
	case "stream-down":
		// Long-lived GET download + chunked POST uploads.
		return d.dialPacketMode(ctx, requestURL.String())
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
		if strings.EqualFold(key, "Host") {
			req.Host = value
			continue
		}
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

// dialStreamUp uses a dedicated GET download stream plus a POST upload stream
// (Xray stream-up). Unlike stream-one, the two directions are separate requests.
func (d *XHTTPDialer) dialStreamUp(ctx context.Context, requestURL string) (netproxy.Conn, error) {
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream-up download request: %w", err)
	}
	d.applyHeaders(getReq)

	getResp, err := d.client.Do(getReq)
	if err != nil {
		return nil, fmt.Errorf("stream-up download failed: %w", err)
	}
	if getResp.StatusCode < 200 || getResp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(getResp.Body, 512))
		_ = getResp.Body.Close()
		return nil, fmt.Errorf("unexpected stream-up download status %d: %s", getResp.StatusCode, string(body))
	}
	d.maybeNotifyNfsKeys(getResp.Header)

	pr, pw := io.Pipe()
	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, pr)
	if err != nil {
		_ = pw.Close()
		_ = getResp.Body.Close()
		return nil, fmt.Errorf("failed to create stream-up upload request: %w", err)
	}
	d.applyHeaders(postReq)
	postReq.Header.Set("Content-Type", "application/octet-stream")

	ch := make(chan streamDialResult, 1)
	go func() {
		resp, err := d.client.Do(postReq)
		if err != nil {
			_ = pr.CloseWithError(err)
			ch <- streamDialResult{err: err}
			return
		}
		// Upload response body is unused; drain and close.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			err := fmt.Errorf("unexpected stream-up upload status %d", resp.StatusCode)
			_ = pr.CloseWithError(err)
			ch <- streamDialResult{err: err}
			return
		}
		ch <- streamDialResult{}
	}()

	return &xhttpSplitConn{
		reader: getResp.Body,
		writer: pw,
		ready:  ch,
		ctx:    ctx,
	}, nil
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
			// Drain async result so a late success does not leak the body.
			go func() {
				res := <-c.ready
				if res.body != nil {
					_ = res.body.Close()
				}
			}()
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

// xhttpSplitConn is stream-up: Read from GET body, Write to POST pipe.
type xhttpSplitConn struct {
	reader io.ReadCloser
	writer *io.PipeWriter
	ready  <-chan streamDialResult
	ctx    context.Context

	uploadOnce sync.Once
	uploadErr  error
	closeOnce  sync.Once
}

func (c *xhttpSplitConn) waitUpload() error {
	c.uploadOnce.Do(func() {
		select {
		case <-c.ctx.Done():
			c.uploadErr = c.ctx.Err()
			go func() {
				res := <-c.ready
				_ = res
			}()
		case res := <-c.ready:
			c.uploadErr = res.err
		}
	})
	return c.uploadErr
}

func (c *xhttpSplitConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
func (c *xhttpSplitConn) Write(b []byte) (int, error) {
	return c.writer.Write(b)
}
func (c *xhttpSplitConn) CloseWrite() error { return c.writer.Close() }
func (c *xhttpSplitConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if e := c.writer.Close(); e != nil {
			err = e
		}
		if e := c.reader.Close(); e != nil && err == nil {
			err = e
		}
		_ = c.waitUpload()
		if c.uploadErr != nil && err == nil {
			err = c.uploadErr
		}
	})
	return err
}
func (c *xhttpSplitConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *xhttpSplitConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *xhttpSplitConn) SetDeadline(t time.Time) error      { return nil }
func (c *xhttpSplitConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *xhttpSplitConn) SetWriteDeadline(t time.Time) error { return nil }

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
			if strings.EqualFold(key, "Host") {
				req.Host = value
				continue
			}
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

// ParseXHTTPConfig accepts absolute URLs or bare host:port[?query][/path] forms
// used by VLESS ProxyAddress.
func ParseXHTTPConfig(rawURL string) (*XHTTPConfig, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, fmt.Errorf("invalid URL: empty")
	}

	var (
		u   *url.URL
		err error
	)
	if strings.Contains(rawURL, "://") {
		u, err = url.Parse(rawURL)
	} else {
		// host:port, host:port/path, host:port?query — force absolute form.
		u, err = url.Parse("https://" + rawURL)
	}
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
	if host := query.Get("host"); host != "" {
		config.Headers["Host"] = host
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
	if h3 := query.Get("h3"); h3 == "1" || strings.EqualFold(h3, "true") {
		config.UseH3 = true
	}
	if alpn := query.Get("alpn"); strings.EqualFold(alpn, "h3") {
		config.UseH3 = true
	}
	if xmux := query.Get("xmux"); xmux == "1" || strings.EqualFold(xmux, "true") {
		config.Xmux = &XmuxConfig{Enabled: true}
	}
	if c := query.Get("xmuxConcurrency"); c != "" {
		if config.Xmux == nil {
			config.Xmux = &XmuxConfig{Enabled: true}
		}
		if v, err := strconv.ParseInt(c, 10, 32); err == nil {
			config.Xmux.Concurrency = int32(v)
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

func (d *XHTTPDialer) UnwrapDialer() netproxy.Dialer {
	return d.opts.Underlay
}
