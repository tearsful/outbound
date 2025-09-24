package vless

import (
	"fmt"
	"net"
	"strings"

	"github.com/daeuniverse/outbound/netproxy"
)

// FallbackManager 管理 VLESS 协议的回退机制
type FallbackManager struct {
	fallbacks []Fallback
}

// NewFallbackManager 创建新的回退管理器
func NewFallbackManager(fallbacks []Fallback) *FallbackManager {
	return &FallbackManager{
		fallbacks: fallbacks,
	}
}

// SelectFallback 根据连接信息选择合适的回退配置
func (fm *FallbackManager) SelectFallback(alpn, path string) (*Fallback, error) {
	if len(fm.fallbacks) == 0 {
		return nil, fmt.Errorf("no fallback configured")
	}

	// 优先匹配 ALPN 和路径
	for _, fb := range fm.fallbacks {
		if fb.Alpn != "" && fb.Alpn == alpn {
			if fb.Path == "" || strings.HasPrefix(path, fb.Path) {
				return &fb, nil
			}
		}
	}

	// 匹配路径
	for _, fb := range fm.fallbacks {
		if fb.Path != "" && strings.HasPrefix(path, fb.Path) {
			return &fb, nil
		}
	}

	// 使用默认回退
	for _, fb := range fm.fallbacks {
		if fb.Name == "default" || (fb.Alpn == "" && fb.Path == "") {
			return &fb, nil
		}
	}

	// 返回第一个回退配置
	return &fm.fallbacks[0], nil
}

// HandleFallback 处理回退连接
func (fm *FallbackManager) HandleFallback(conn netproxy.Conn, alpn, path string) (netproxy.Conn, error) {
	fallback, err := fm.SelectFallback(alpn, path)
	if err != nil {
		return nil, err
	}

	if fallback.Dest == "" {
		return nil, fmt.Errorf("fallback destination not configured")
	}

	// 连接到回退目标
	destConn, err := net.Dial("tcp", fallback.Dest)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to fallback destination %s: %w", fallback.Dest, err)
	}

	// 创建回退连接包装器
	return &FallbackConn{
		Conn:     conn,
		destConn: destConn,
		fallback: fallback,
	}, nil
}

// FallbackConn 包装回退连接
type FallbackConn struct {
	netproxy.Conn
	destConn net.Conn
	fallback *Fallback
}

// Close 关闭回退连接
func (fc *FallbackConn) Close() error {
	if fc.destConn != nil {
		fc.destConn.Close()
	}
	return fc.Conn.Close()
}

// Read 从回退连接读取数据
func (fc *FallbackConn) Read(b []byte) (n int, err error) {
	if fc.destConn != nil {
		return fc.destConn.Read(b)
	}
	return fc.Conn.Read(b)
}

// Write 向回退连接写入数据
func (fc *FallbackConn) Write(b []byte) (n int, err error) {
	if fc.destConn != nil {
		return fc.destConn.Write(b)
	}
	return fc.Conn.Write(b)
}

// GetFallbackInfo 获取回退信息
func (fc *FallbackConn) GetFallbackInfo() *Fallback {
	return fc.fallback
}
