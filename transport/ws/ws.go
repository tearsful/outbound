package ws

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tearsful/outbound/dialer"
	"github.com/tearsful/outbound/netproxy"
	transportTls "github.com/tearsful/outbound/transport/tls"
	"github.com/gorilla/websocket"
)

func parseRange(str string) (min, max int64, err error) {
	stringArr := strings.Split(str, "-")
	if len(stringArr) != 2 {
		return 0, 0, fmt.Errorf("invalid range: %s", str)
	}
	min, err = strconv.ParseInt(stringArr[0], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	max, err = strconv.ParseInt(stringArr[1], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	return min, max, nil
}

// parseCustomHeaders 解析自定义头部字符串
// 格式: "key1:value1,key2:value2"
func parseCustomHeaders(header http.Header, headersStr string) {
	if headersStr == "" {
		return
	}

	headers := strings.Split(headersStr, ",")
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if key != "" && value != "" {
				header.Set(key, value)
			}
		}
	}
}

// Ws is a base Ws struct
type Ws struct {
	dialer              netproxy.Dialer
	wsAddr              string
	header              http.Header
	tlsClientConfig     *tls.Config
	passthroughUdp      bool
	tlsFragmentation    bool
	fragmentMinLength   int64
	fragmentMaxLength   int64
	fragmentMinInterval int64
	fragmentMaxInterval int64
	// 新增 xray-core 兼容的高级参数
	maxEarlyData         int
	earlyDataHeaderName  string
	earlyDataHeaderValue string
	pingInterval         time.Duration
	pingTimeout          time.Duration
	readBufferSize       int
	writeBufferSize      int
	enableCompression    bool
	checkOrigin          func(r *http.Request) bool
}

// NewWs returns a Ws infra.
func NewWs(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, fmt.Errorf("NewWs: %w", err)
	}

	t := &Ws{
		dialer: nextDialer,
		// 设置默认值
		maxEarlyData:        0,
		earlyDataHeaderName: "Sec-WebSocket-Protocol",
		pingInterval:        30 * time.Second,
		pingTimeout:         10 * time.Second,
		readBufferSize:      4096,
		writeBufferSize:     4096,
		enableCompression:   false,
	}

	query := u.Query()
	host := query.Get("host")
	if host == "" {
		host = u.Hostname()
	}
	t.header = http.Header{}
	t.header.Set("Host", host)

	// 解析自定义头部
	if headers := query.Get("headers"); headers != "" {
		parseCustomHeaders(t.header, headers)
	}

	// 解析早期数据参数
	if maxEarlyData := query.Get("maxEarlyData"); maxEarlyData != "" {
		if val, err := strconv.Atoi(maxEarlyData); err == nil {
			t.maxEarlyData = val
		}
	}

	// 解析早期数据头部
	if earlyDataHeaderName := query.Get("earlyDataHeaderName"); earlyDataHeaderName != "" {
		t.earlyDataHeaderName = earlyDataHeaderName
	}
	if earlyDataHeaderValue := query.Get("earlyDataHeaderValue"); earlyDataHeaderValue != "" {
		t.earlyDataHeaderValue = earlyDataHeaderValue
	}

	// 解析ping参数
	if pingInterval := query.Get("pingInterval"); pingInterval != "" {
		if val, err := time.ParseDuration(pingInterval); err == nil {
			t.pingInterval = val
		}
	}
	if pingTimeout := query.Get("pingTimeout"); pingTimeout != "" {
		if val, err := time.ParseDuration(pingTimeout); err == nil {
			t.pingTimeout = val
		}
	}

	// 解析缓冲区大小
	if readBufferSize := query.Get("readBufferSize"); readBufferSize != "" {
		if val, err := strconv.Atoi(readBufferSize); err == nil {
			t.readBufferSize = val
		}
	}
	if writeBufferSize := query.Get("writeBufferSize"); writeBufferSize != "" {
		if val, err := strconv.Atoi(writeBufferSize); err == nil {
			t.writeBufferSize = val
		}
	}

	// 解析压缩选项
	if enableCompression := query.Get("enableCompression"); enableCompression == "true" {
		t.enableCompression = true
	}

	t.passthroughUdp, _ = strconv.ParseBool(u.Query().Get("passthroughUdp"))

	wsUrl := url.URL{
		Scheme: u.Scheme,
		Host:   u.Host,
	}
	t.wsAddr = wsUrl.String() + u.Path
	if u.Scheme == "wss" {
		allowInsecure, _ := strconv.ParseBool(u.Query().Get("allowInsecure"))
		if !allowInsecure {
			allowInsecure, _ = strconv.ParseBool(u.Query().Get("allow_insecure"))
		}
		if !allowInsecure {
			allowInsecure, _ = strconv.ParseBool(u.Query().Get("allowinsecure"))
		}
		if !allowInsecure {
			allowInsecure, _ = strconv.ParseBool(u.Query().Get("skipVerify"))
		}
		// TODO: utls
		t.tlsClientConfig = &tls.Config{
			ServerName:         query.Get("sni"),
			InsecureSkipVerify: allowInsecure || option.AllowInsecure,
		}
		if len(query.Get("alpn")) > 0 {
			t.tlsClientConfig.NextProtos = strings.Split(query.Get("alpn"), ",")
		}

		if option.TlsFragment {
			t.tlsFragmentation = true
			minLen, maxLen, err := parseRange(option.TlsFragmentLength)
			if err != nil {
				return nil, nil, err
			}
			t.fragmentMinLength = minLen
			t.fragmentMaxLength = maxLen
			minInterval, maxInterval, err := parseRange(option.TlsFragmentInterval)
			if err != nil {
				return nil, nil, err
			}
			t.fragmentMinInterval = minInterval
			t.fragmentMaxInterval = maxInterval
		}
	}
	return t, &dialer.Property{
		Name:     u.Fragment,
		Address:  wsUrl.Host,
		Protocol: u.Scheme,
		Link:     link,
	}, nil
}

func (s *Ws) DialContext(ctx context.Context, network, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
		wsDialer := &websocket.Dialer{
			NetDial: func(_, addr string) (net.Conn, error) {
				c, err := s.dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}

				if s.tlsFragmentation {
					c = transportTls.NewFragmentConn(c, s.fragmentMinLength, s.fragmentMaxLength, s.fragmentMinInterval, s.fragmentMaxInterval)
				}

				return &netproxy.FakeNetConn{
					Conn:  c,
					LAddr: nil,
					RAddr: nil,
				}, nil
			},
			TLSClientConfig: s.tlsClientConfig,
		}
		rc, _, err := wsDialer.DialContext(ctx, s.wsAddr, s.header)
		if err != nil {
			return nil, fmt.Errorf("[Ws]: dial to %s: %w", s.wsAddr, err)
		}
		return newConn(rc), err
	case "udp":
		if s.passthroughUdp {
			return s.dialer.DialContext(ctx, network, addr)
		}
		return nil, fmt.Errorf("%w: ws+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}
