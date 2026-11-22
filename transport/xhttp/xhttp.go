package xhttp

import (
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
	Host               string            // 主机名
	Path               string            // 路径
	Headers            map[string]string // 自定义头部
	MaxEachPostBytes   int64             // 每次POST最大字节数
	MinPostsIntervalMs int64             // 最小POST间隔（毫秒）
	Mode               string            // 模式：auto, stream-one, stream-up, stream-down, packet-up
	DownloadSettings   *XHTTPConfig      // 下载设置
	Xmux               *XmuxConfig       // Xmux配置
	// 当服务端通过响应头返回 NfsPKeys（逗号分隔的 base64url 列表）时回调
	OnNfsPKeys func(keys [][]byte)
}

// XmuxConfig 定义 Xmux 多路复用配置
type XmuxConfig struct {
	Enabled              bool  // 是否启用
	Concurrency          int32 // 并发数
	IdleTimeout          int32 // 空闲超时（秒）
	HKeepAlivePeriod     int32 // 保持连接周期（秒）
	MaxConcurrentStreams int32 // 最大并发流
}

// XHTTPDialer 实现 XHTTP 传输层拨号器
type XHTTPDialer struct {
	config *XHTTPConfig
	client *http.Client
}

// NewXHTTPDialer 创建新的 XHTTP 拨号器
func NewXHTTPDialer(config *XHTTPConfig) (*XHTTPDialer, error) {
	if config == nil {
		config = &XHTTPConfig{
			Path:               "/",
			MaxEachPostBytes:   32 * 1024, // 32KB
			MinPostsIntervalMs: 0,
			Mode:               "auto",
		}
	}

	// 设置默认值
	if config.Path == "" {
		config.Path = "/"
	}
	if config.MaxEachPostBytes == 0 {
		config.MaxEachPostBytes = 32 * 1024
	}
	if config.Mode == "" {
		config.Mode = "auto"
	}

	// 创建 HTTP 客户端
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// 根据配置决定使用 HTTP/1.1, HTTP/2 或 HTTP/3
	// 这里简化实现，实际应该根据 TLS 配置决定
	client.Transport = &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		DisableCompression:  true,
		MaxIdleConnsPerHost: 10,
	}

	return &XHTTPDialer{
		config: config,
		client: client,
	}, nil
}

// DialContext 实现 netproxy.Dialer 接口
func (d *XHTTPDialer) DialContext(ctx context.Context, network, address string) (netproxy.Conn, error) {
	hostPort := address
	if d.config != nil && d.config.Host != "" {
		hostPort = d.config.Host
		if _, _, err := net.SplitHostPort(hostPort); err != nil {
			// Host may be hostname without port; keep caller address port if present.
			if _, port, splitErr := net.SplitHostPort(address); splitErr == nil {
				hostPort = net.JoinHostPort(d.config.Host, port)
			}
		}
	}
	if _, _, err := net.SplitHostPort(hostPort); err != nil {
		return nil, fmt.Errorf("invalid xhttp host/address: %v", err)
	}

	// 构建请求 URL（连到代理入口，而不是最终目标地址）
	requestURL := &url.URL{
		Scheme: "https",
		Host:   hostPort,
		Path:   d.config.Path,
	}

	// 添加查询参数
	if d.config.Headers != nil {
		query := requestURL.Query()
		for key, value := range d.config.Headers {
			query.Set(key, value)
		}
		requestURL.RawQuery = query.Encode()
	}

	// 根据模式创建连接
	switch d.config.Mode {
	case "stream-one", "stream-up", "stream-down":
		return nil, fmt.Errorf("xhttp mode %q is not implemented for bidirectional proxying", d.config.Mode)
	case "packet-up", "auto":
		return d.dialPacketMode(ctx, requestURL.String())
	default:
		return d.dialPacketMode(ctx, requestURL.String())
	}
}

// dialStreamMode 实现流模式连接
func (d *XHTTPDialer) dialStreamMode(ctx context.Context, requestURL string) (netproxy.Conn, error) {
	// 创建 HTTP 请求
	req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// 添加自定义头部
	if d.config.Headers != nil {
		for key, value := range d.config.Headers {
			req.Header.Set(key, value)
		}
	}

	// 执行请求
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %v", err)
	}

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// 尝试从响应头提取服务端 NfsPKeys
	if d.config != nil && d.config.OnNfsPKeys != nil {
		if nfs := resp.Header.Get("X-NfsPKeys"); nfs != "" {
			if keys, err := parseNfsPKeysCSVBase64(nfs); err == nil && len(keys) > 0 {
				d.config.OnNfsPKeys(keys)
			}
		}
	}

	// 创建流连接
	return &XHTTPStreamConn{
		body:   resp.Body,
		header: resp.Header,
		url:    requestURL,
	}, nil
}

// dialPacketMode 实现数据包模式连接
func (d *XHTTPDialer) dialPacketMode(ctx context.Context, requestURL string) (netproxy.Conn, error) {
	// 创建管道
	reader, writer := io.Pipe()

	// 创建数据包连接
	conn := &XHTTPPacketConn{
		reader: reader,
		writer: writer,
		url:    requestURL,
		client: d.client,
		config: d.config,
		ctx:    ctx,
	}

	// 启动上传协程
	go conn.startUpload()

	return conn, nil
}

// XHTTPStreamConn 实现流模式连接
type XHTTPStreamConn struct {
	body   io.ReadCloser
	header http.Header
	url    string
}

func (c *XHTTPStreamConn) Read(b []byte) (n int, err error) {
	return c.body.Read(b)
}

func (c *XHTTPStreamConn) Write(b []byte) (n int, err error) {
	// 流模式通常不支持写入
	return 0, fmt.Errorf("write not supported in stream mode")
}

func (c *XHTTPStreamConn) Close() error {
	return c.body.Close()
}

func (c *XHTTPStreamConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *XHTTPStreamConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *XHTTPStreamConn) SetDeadline(t time.Time) error {
	return fmt.Errorf("set deadline not supported")
}

func (c *XHTTPStreamConn) SetReadDeadline(t time.Time) error {
	return fmt.Errorf("set read deadline not supported")
}

func (c *XHTTPStreamConn) SetWriteDeadline(t time.Time) error {
	return fmt.Errorf("set write deadline not supported")
}

// XHTTPPacketConn 实现数据包模式连接
type XHTTPPacketConn struct {
	reader io.ReadCloser
	writer io.WriteCloser
	url    string
	client *http.Client
	config *XHTTPConfig
	ctx    context.Context
	closed bool
	mutex  sync.Mutex
}

func (c *XHTTPPacketConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

func (c *XHTTPPacketConn) Write(b []byte) (n int, err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		return 0, fmt.Errorf("connection closed")
	}

	return c.writer.Write(b)
}

func (c *XHTTPPacketConn) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true

	if c.reader != nil {
		c.reader.Close()
	}
	if c.writer != nil {
		c.writer.Close()
	}

	return nil
}

func (c *XHTTPPacketConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *XHTTPPacketConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *XHTTPPacketConn) SetDeadline(t time.Time) error {
	return fmt.Errorf("set deadline not supported")
}

func (c *XHTTPPacketConn) SetReadDeadline(t time.Time) error {
	return fmt.Errorf("set read deadline not supported")
}

func (c *XHTTPPacketConn) SetWriteDeadline(t time.Time) error {
	return fmt.Errorf("set write deadline not supported")
}

// startUpload 启动上传协程
func (c *XHTTPPacketConn) startUpload() {
	// 这里应该实现数据包上传逻辑
	// 简化实现，实际应该根据 Xray-core 的 XHTTP 协议实现
}

// ParseXHTTPConfig 从 URL 解析 XHTTP 配置
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

	// 解析查询参数
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

	// 解析头部
	if headers := query.Get("headers"); headers != "" {
		headerPairs := strings.Split(headers, ",")
		for _, pair := range headerPairs {
			if kv := strings.SplitN(pair, ":", 2); len(kv) == 2 {
				config.Headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}

	return config, nil
}

// parseNfsPKeysCSVBase64 解析以逗号分隔的 base64url 列表
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
		// 先尝试 base64url
		if b, err := base64.RawURLEncoding.DecodeString(p); err == nil {
			out = append(out, b)
			continue
		}
		// 再尝试标准 base64
		if b, err := base64.StdEncoding.DecodeString(p); err == nil {
			out = append(out, b)
			continue
		}
	}
	return out, nil
}
