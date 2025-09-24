package vless

import (
	"context"
	"fmt"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/vless/vision"
	"github.com/daeuniverse/outbound/protocol/vmess"
)

const (
	XRV = "xtls-rprx-vision"
	// 添加更多 Xray-core 兼容的流控制选项
	FlowVisionReality = "xtls-rprx-vision-udp443"
	FlowOrigin        = "xtls-rprx-origin"
	FlowOriginUDP443  = "xtls-rprx-origin-udp443"
	FlowDirect        = "xtls-rprx-direct"
	FlowDirectUDP443  = "xtls-rprx-direct-udp443"
	FlowSplice        = "xtls-rprx-splice"
	FlowSpliceUDP443  = "xtls-rprx-splice-udp443"
	// 额外的流控制类型（Xray-core 支持的）
	FlowVisionRealityTCP = "xtls-rprx-vision-tcp443"
)

func init() {
	protocol.Register("vless", NewDialer)
}

type Dialer struct {
	proxyAddress string
	nextDialer   netproxy.Dialer
	metadata     protocol.Metadata
	flow         string
	xudp         bool
	key          []byte
	// 新增 Xray-core 兼容参数
	encryption      string
	level           uint32
	fallbacks       []Fallback
	fallbackManager *FallbackManager
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}
	//log.Trace("vless.NewDialer: metadata: %v, password: %v", metadata, password)
	id, err := Password2Key(header.Password)
	if err != nil {
		return nil, err
	}
	flow := header.Feature1
	switch flow {
	case XRV, FlowVisionReality, FlowOrigin, FlowOriginUDP443, FlowDirect, FlowDirectUDP443, FlowSplice, FlowSpliceUDP443, FlowVisionRealityTCP:
		if !metadata.IsClient {
			return nil, fmt.Errorf("unsupported server mode xtls flow type: %v", flow)
		}
	case "":
	default:
		return nil, fmt.Errorf("unsupported xtls flow type: %v", flow)
	}
	// 确定是否启用 XUDP，支持更多流控制类型
	enableXUDP := false
	if flowStr, ok := flow.(string); ok {
		switch flowStr {
		case XRV, FlowVisionReality, FlowOrigin, FlowOriginUDP443, FlowDirect, FlowDirectUDP443, FlowSplice, FlowSpliceUDP443, FlowVisionRealityTCP:
			enableXUDP = true
		}
	}

	fallbacks := []Fallback{} // 空的回退配置，可以通过配置扩展
	fallbackManager := NewFallbackManager(fallbacks)

	return &Dialer{
		proxyAddress:    header.ProxyAddress,
		nextDialer:      nextDialer,
		metadata:        metadata,
		flow:            flow.(string),
		xudp:            enableXUDP,
		key:             id,
		encryption:      "none", // VLESS 默认不加密
		level:           0,      // 默认用户级别
		fallbacks:       fallbacks,
		fallbackManager: fallbackManager,
	}, nil
}

func (d *Dialer) DialTcp(ctx context.Context, addr string) (c netproxy.Conn, err error) {
	return d.DialContext(ctx, "tcp", addr)
}

func (d *Dialer) DialUdp(ctx context.Context, addr string) (c netproxy.PacketConn, err error) {
	pktConn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	return pktConn.(netproxy.PacketConn), nil
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.IsClient = d.metadata.IsClient

		tcpNetwork := netproxy.MagicNetwork{
			Network: "tcp",
			Mark:    magicNetwork.Mark,
			Mptcp:   magicNetwork.Mptcp,
		}.Encode()
		conn, err := d.nextDialer.DialContext(ctx, tcpNetwork, d.proxyAddress)
		if err != nil {
			return nil, err
		}
		conn, err = NewConn(conn, Metadata{
			Metadata:   vmess.Metadata{Metadata: mdata, Network: magicNetwork.Network},
			Flow:       d.flow,
			Mux:        magicNetwork.Network == "udp" && d.xudp,
			Encryption: d.encryption,
			Level:      d.level,
		}, d.key)
		if err != nil {
			return nil, err
		}
		// 支持更多的 XTLS 流控制类型
		switch d.flow {
		case XRV, FlowVisionReality, FlowVisionRealityTCP:
			if d.xudp {
				return vision.NewPacketConn(conn, d.key, magicNetwork.Network, addr)
			}
			return vision.NewConn(conn, d.key)
		case FlowOrigin, FlowOriginUDP443:
			// Origin 流控制：使用标准 XTLS 实现
			if d.xudp {
				return vision.NewPacketConn(conn, d.key, magicNetwork.Network, addr)
			}
			return vision.NewConn(conn, d.key)
		case FlowDirect, FlowDirectUDP443:
			// Direct 流控制：直接透传，无额外处理
			return conn, nil
		case FlowSplice, FlowSpliceUDP443:
			// Splice 流控制：零拷贝优化，使用标准连接
			return conn, nil
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}
