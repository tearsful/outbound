package kcp

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"github.com/tearsful/outbound/dialer"
	"github.com/tearsful/outbound/netproxy"
)

// KcpConfig 定义 mKCP 传输配置
type KcpConfig struct {
	Seed            string
	HeaderType      string
	Congestion      bool
	ReadBufferSize  int
	WriteBufferSize int
	MTU             int
	DataShard       int
	ParityShard     int
	NoDelay         int
	Interval        int
	Resend          int
	NoCongestion    int
	RcvWnd          int
	SndWnd          int
}

// Kcp 是 mKCP 传输层实现
type Kcp struct {
	dialer netproxy.Dialer
	config *KcpConfig
}

// NewKcp 创建新的 mKCP 传输层
func NewKcp(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid kcp link: %w", err)
	}

	config := &KcpConfig{
		Seed:            "",
		HeaderType:      "none",
		Congestion:      false,
		ReadBufferSize:  16777216,
		WriteBufferSize: 16777216,
		MTU:             1350,
		DataShard:       10,
		ParityShard:     3,
		NoDelay:         1,
		Interval:        40,
		Resend:          2,
		NoCongestion:    1,
		RcvWnd:          1024,
		SndWnd:          1024,
	}

	// 解析查询参数
	query := u.Query()
	if seed := query.Get("seed"); seed != "" {
		config.Seed = seed
	}
	if headerType := query.Get("headerType"); headerType != "" {
		config.HeaderType = headerType
	}
	if congestion := query.Get("congestion"); congestion == "true" {
		config.Congestion = true
	}
	if readBufferSize := query.Get("readBufferSize"); readBufferSize != "" {
		if val, err := strconv.Atoi(readBufferSize); err == nil {
			config.ReadBufferSize = val
		}
	}
	if writeBufferSize := query.Get("writeBufferSize"); writeBufferSize != "" {
		if val, err := strconv.Atoi(writeBufferSize); err == nil {
			config.WriteBufferSize = val
		}
	}
	if mtu := query.Get("mtu"); mtu != "" {
		if val, err := strconv.Atoi(mtu); err == nil {
			config.MTU = val
		}
	}
	if dataShard := query.Get("dataShard"); dataShard != "" {
		if val, err := strconv.Atoi(dataShard); err == nil {
			config.DataShard = val
		}
	}
	if parityShard := query.Get("parityShard"); parityShard != "" {
		if val, err := strconv.Atoi(parityShard); err == nil {
			config.ParityShard = val
		}
	}
	if noDelay := query.Get("noDelay"); noDelay != "" {
		if val, err := strconv.Atoi(noDelay); err == nil {
			config.NoDelay = val
		}
	}
	if interval := query.Get("interval"); interval != "" {
		if val, err := strconv.Atoi(interval); err == nil {
			config.Interval = val
		}
	}
	if resend := query.Get("resend"); resend != "" {
		if val, err := strconv.Atoi(resend); err == nil {
			config.Resend = val
		}
	}
	if noCongestion := query.Get("noCongestion"); noCongestion != "" {
		if val, err := strconv.Atoi(noCongestion); err == nil {
			config.NoCongestion = val
		}
	}
	if rcvWnd := query.Get("rcvWnd"); rcvWnd != "" {
		if val, err := strconv.Atoi(rcvWnd); err == nil {
			config.RcvWnd = val
		}
	}
	if sndWnd := query.Get("sndWnd"); sndWnd != "" {
		if val, err := strconv.Atoi(sndWnd); err == nil {
			config.SndWnd = val
		}
	}

	kcp := &Kcp{
		dialer: nextDialer,
		config: config,
	}

	property := &dialer.Property{
		Name:     fmt.Sprintf("kcp-%s", u.Host),
		Address:  u.Host,
		Protocol: "kcp",
		Link:     link,
	}

	return kcp, property, nil
}

// DialContext 实现 netproxy.Dialer 接口
func (k *Kcp) DialContext(ctx context.Context, network string, addr string) (netproxy.Conn, error) {
	// 这里需要实现 mKCP 的具体连接逻辑
	// 由于 mKCP 是一个复杂的协议，这里提供一个基础框架
	conn, err := k.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial kcp: %w", err)
	}

	return &KcpConn{
		Conn:   conn,
		config: k.config,
	}, nil
}

// KcpConn 实现 netproxy.Conn 接口
type KcpConn struct {
	netproxy.Conn
	config *KcpConfig
}

func (kc *KcpConn) Close() error {
	return kc.Conn.Close()
}

// 注册 mKCP 传输层
func init() {
	// 注意：这里需要根据实际的dialer包API来调整
	// dialer.RegisterTransport("kcp", NewKcp)
}
