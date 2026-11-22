package quic

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/quic-go"
	"github.com/tearsful/outbound/dialer"
	"github.com/tearsful/outbound/netproxy"
)

// QuicConfig 定义 QUIC 传输配置
type QuicConfig struct {
	Host                    string
	Port                    int
	Key                     string
	Security                string
	HeaderType              string
	ServiceName             string
	Mode                    string
	Seed                    string
	Congestion              bool
	IdleTimeout             time.Duration
	KeepAlivePeriod         time.Duration
	MaxIncomingStreams      int64
	DisablePathMTUDiscovery bool
}

// Quic 是 QUIC 传输层实现
type Quic struct {
	dialer    netproxy.Dialer
	config    *QuicConfig
	tlsConfig *tls.Config
}

// NewQuic 创建新的 QUIC 传输层
func NewQuic(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid quic link: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "quic") || u.Hostname() == "" {
		return nil, nil, fmt.Errorf("invalid quic link: scheme must be quic with a host")
	}

	config := &QuicConfig{
		Host:               u.Hostname(),
		Port:               443,
		Security:           "none",
		HeaderType:         "none",
		IdleTimeout:        30 * time.Second,
		KeepAlivePeriod:    10 * time.Second,
		MaxIncomingStreams: 1000,
	}

	// 解析端口
	if portStr := u.Port(); portStr != "" {
		if port, err := strconv.Atoi(portStr); err == nil {
			config.Port = port
		}
	}

	// 解析查询参数
	query := u.Query()
	if security := query.Get("security"); security != "" {
		config.Security = security
	}
	if key := query.Get("key"); key != "" {
		config.Key = key
	}
	if headerType := query.Get("headerType"); headerType != "" {
		config.HeaderType = headerType
	}
	if serviceName := query.Get("serviceName"); serviceName != "" {
		config.ServiceName = serviceName
	}
	if mode := query.Get("mode"); mode != "" {
		config.Mode = mode
	}
	if seed := query.Get("seed"); seed != "" {
		config.Seed = seed
	}
	if congestion := query.Get("congestion"); congestion == "true" {
		config.Congestion = true
	}
	if idleTimeout := query.Get("idleTimeout"); idleTimeout != "" {
		if duration, err := time.ParseDuration(idleTimeout); err == nil {
			config.IdleTimeout = duration
		}
	}
	if keepAlive := query.Get("keepAlivePeriod"); keepAlive != "" {
		if duration, err := time.ParseDuration(keepAlive); err == nil {
			config.KeepAlivePeriod = duration
		}
	}
	if maxStreams := query.Get("maxIncomingStreams"); maxStreams != "" {
		if streams, err := strconv.ParseInt(maxStreams, 10, 64); err == nil {
			config.MaxIncomingStreams = streams
		}
	}
	if disablePathMTU := query.Get("disablePathMTUDiscovery"); disablePathMTU == "true" {
		config.DisablePathMTUDiscovery = true
	}

	// 创建 TLS 配置
	tlsConfig := &tls.Config{
		ServerName:         config.Host,
		InsecureSkipVerify: config.Security == "none",
	}

	// 根据安全配置设置 TLS
	switch config.Security {
	case "tls":
		// 标准 TLS 配置
	case "reality":
		// Reality 协议配置
		if publicKey := query.Get("publicKey"); publicKey != "" {
			// 这里需要实现 Reality 协议的具体逻辑
			// 暂时使用标准 TLS
		}
	}

	quic := &Quic{
		dialer:    nextDialer,
		config:    config,
		tlsConfig: tlsConfig,
	}

	property := &dialer.Property{
		Name:     fmt.Sprintf("quic-%s:%d", config.Host, config.Port),
		Address:  fmt.Sprintf("%s:%d", config.Host, config.Port),
		Protocol: "quic",
		Link:     link,
	}

	return quic, property, nil
}

// DialContext 实现 netproxy.Dialer 接口
func (q *Quic) DialContext(ctx context.Context, network string, addr string) (netproxy.Conn, error) {
	// 创建 QUIC 连接
	address := fmt.Sprintf("%s:%d", q.config.Host, q.config.Port)

	// 配置 QUIC 选项
	quicConfig := &quic.Config{
		MaxIncomingStreams:      q.config.MaxIncomingStreams,
		DisablePathMTUDiscovery: q.config.DisablePathMTUDiscovery,
	}

	// 建立 QUIC 连接
	conn, err := quic.DialAddr(ctx, address, q.tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial quic: %w", err)
	}

	// 创建流
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	return &QuicConn{
		Stream: stream,
		Conn:   conn,
		config: q.config,
	}, nil
}

// QuicConn 实现 netproxy.Conn 接口
type QuicConn struct {
	quic.Stream
	Conn   quic.Connection
	config *QuicConfig
}

func (qc *QuicConn) Close() error {
	if qc.Stream != nil {
		qc.Stream.Close()
	}
	if qc.Conn != nil {
		return qc.Conn.CloseWithError(0, "")
	}
	return nil
}

func (qc *QuicConn) LocalAddr() net.Addr {
	if qc.Conn != nil {
		return qc.Conn.LocalAddr()
	}
	return nil
}

func (qc *QuicConn) RemoteAddr() net.Addr {
	if qc.Conn != nil {
		return qc.Conn.RemoteAddr()
	}
	return nil
}

// 注册 QUIC 传输层
func init() {
	// 注意：这里需要根据实际的dialer包API来调整
	// dialer.RegisterTransport("quic", NewQuic)
}
