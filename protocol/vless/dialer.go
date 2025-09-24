package vless

import (
	"context"
	"fmt"

	"github.com/tearsful/outbound/netproxy"
	"github.com/tearsful/outbound/protocol"
	"github.com/tearsful/outbound/protocol/vless/encryption"
	"github.com/tearsful/outbound/protocol/vless/vision"
	"github.com/tearsful/outbound/protocol/vmess"
	"github.com/tearsful/outbound/transport/xhttp"
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

	// 支持的加密模式
	EncryptionNone               = "none"
	EncryptionMLKEM768X25519Plus = "mlkem768x25519plus.native.0rtt"

	// 传输类型
	TransportXHTTP = "xhttp"
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
	// Post-Quantum Encryption 支持
	pqeEncryption *encryption.PostQuantumEncryption
	mldsa65Auth   *encryption.MLDSA65Auth
	// XHTTP 传输支持
	transportType string
	xhttpConfig   *xhttp.XHTTPConfig
	// Xray-core PQ/0-RTT 相关
	o0rttToken string
	pqv        string
	nfsKeys    [][]byte
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

	// 解析加密模式（支持从 Feature2 注入）
	encryptionMode := EncryptionNone
	if header.Feature2 != nil {
		if enc, ok := header.Feature2.(string); ok {
			encryptionMode = enc
		}
	}

	// 解析传输类型（支持从 Feature3 注入）
	transportType := "tcp"
	if header.Feature3 != nil {
		if tr, ok := header.Feature3.(string); ok {
			transportType = tr
		}
	}

	// 初始化 Post-Quantum Encryption（如果支持）
	var pqeEncryption *encryption.PostQuantumEncryption
	if encryptionMode == EncryptionMLKEM768X25519Plus {
		pqeEncryption, err = encryption.NewPostQuantumEncryption(encryptionMode)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize post-quantum encryption: %v", err)
		}
	}

	// 初始化 MLDSA65 认证（如果提供）
	var mldsa65Auth *encryption.MLDSA65Auth
	if header.Feature4 != nil && header.Feature5 != nil {
		if seed, ok1 := header.Feature4.(string); ok1 {
			if verifyKey, ok2 := header.Feature5.(string); ok2 {
				var err error
				mldsa65Auth, err = encryption.NewMLDSA65AuthFromBase64(seed, verifyKey)
				if err != nil {
					return nil, fmt.Errorf("failed to initialize MLDSA65 auth: %v", err)
				}
			}
		}
	}

	// 初始化 XHTTP 配置（如果使用 XHTTP 传输）
	var xhttpConfig *xhttp.XHTTPConfig
    if transportType == TransportXHTTP {
        xhttpConfig, err = xhttp.ParseXHTTPConfig(header.ProxyAddress)
        if err != nil {
            return nil, fmt.Errorf("failed to parse XHTTP config: %v", err)
        }
        // 从 Extra 携带的 xhttp 参数补充配置
        if header.Extra != nil {
            if v, ok := header.Extra["xhttp.path"]; ok && v != "" {
                xhttpConfig.Path = v
            }
            if v, ok := header.Extra["xhttp.mode"]; ok && v != "" {
                xhttpConfig.Mode = v
            }
            if v, ok := header.Extra["xhttp.headers"]; ok && v != "" {
                // 解析 CSV 头部列表: k:v,k2:v2
                if xhttpConfig.Headers == nil {
                    xhttpConfig.Headers = map[string]string{}
                }
                for _, part := range strings.Split(v, ",") {
                    kv := strings.SplitN(strings.TrimSpace(part), ":", 2)
                    if len(kv) == 2 {
                        xhttpConfig.Headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
                    }
                }
            }
        }
    }

	// 读取 pqv 与 0-RTT token
	var o0rttToken, pqv string
	var nfsPKeysCsv string
	if header.Extra != nil {
		if v, ok := header.Extra["o0rtt"]; ok {
			o0rttToken = v
		}
		if v, ok := header.Extra["pqv"]; ok {
			pqv = v
		}
		if v, ok := header.Extra["NfsPKeys"]; ok {
			nfsPKeysCsv = v
		}
	}

	// 解析 NfsPKeys (可选，从订阅/链接或后续首次握手发现)
	var parsedNfsKeys [][]byte
	if keys, err := ParseNfsPKeysCSVBase64(nfsPKeysCsv); err == nil {
		parsedNfsKeys = keys
	}

	return &Dialer{
		proxyAddress:    header.ProxyAddress,
		nextDialer:      nextDialer,
		metadata:        metadata,
		flow:            flow.(string),
		xudp:            enableXUDP,
		key:             id,
		encryption:      encryptionMode,
		level:           0, // 默认用户级别
		fallbacks:       fallbacks,
		fallbackManager: fallbackManager,
		pqeEncryption:   pqeEncryption,
		mldsa65Auth:     mldsa65Auth,
		transportType:   transportType,
		xhttpConfig:     xhttpConfig,
		o0rttToken:      o0rttToken,
		pqv:             pqv,
		nfsKeys:         parsedNfsKeys,
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

	// 如果使用 XHTTP 传输，直接使用 XHTTP 拨号器
	if d.transportType == TransportXHTTP {
		return d.dialXHTTP(ctx, magicNetwork, addr)
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

		// 如果使用 Post-Quantum Encryption，执行握手
		if d.pqeEncryption != nil {
			// 准备 NfsPKeys：优先本地缓存/传入，其次可在后续链路中通过 Reality+xhttp 获取
			serverPublicKeys := d.nfsKeys
			if len(serverPublicKeys) == 0 {
				if cached, ok := defaultNfsKeyCache.Get(d.proxyAddress); ok {
					serverPublicKeys = cached
				}
			}
			session, err := d.pqeEncryption.Handshake(conn, serverPublicKeys)
			if err != nil {
				return nil, fmt.Errorf("post-quantum encryption handshake failed: %v", err)
			}
			// TODO: 若首次握手服务端返回 NfsPKeys，应当提取并缓存
			if len(serverPublicKeys) != 0 {
				defaultNfsKeyCache.Set(d.proxyAddress, serverPublicKeys)
			}
			_ = session
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

// dialXHTTP 使用 XHTTP 传输建立连接
func (d *Dialer) dialXHTTP(ctx context.Context, magicNetwork netproxy.MagicNetwork, addr string) (netproxy.Conn, error) {
	// 创建 XHTTP 拨号器
	if d.xhttpConfig != nil {
		cfg := d.xhttpConfig
		// 注入 NfsPKeys 回调：写入缓存供后续 PQ/0-RTT 复用
		cfg.OnNfsPKeys = func(keys [][]byte) {
			if len(keys) == 0 {
				return
			}
			defaultNfsKeyCache.Set(d.proxyAddress, keys)
		}
	}
	xhttpDialer, err := xhttp.NewXHTTPDialer(d.xhttpConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create XHTTP dialer: %v", err)
	}

	// 使用 XHTTP 建立连接
	conn, err := xhttpDialer.DialContext(ctx, magicNetwork.Network, addr)
	if err != nil {
		return nil, fmt.Errorf("XHTTP dial failed: %v", err)
	}

	// 如果使用 Post-Quantum Encryption，在 XHTTP 连接上执行握手
	if d.pqeEncryption != nil {
		// 这里需要服务器公钥，实际实现中应该从配置获取
		serverPublicKeys := d.nfsKeys
		if len(serverPublicKeys) == 0 {
			if cached, ok := defaultNfsKeyCache.Get(d.proxyAddress); ok {
				serverPublicKeys = cached
			}
		}
		session, err := d.pqeEncryption.Handshake(conn, serverPublicKeys)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("post-quantum encryption handshake failed: %v", err)
		}
		// 使用会话密钥更新连接（留待后续集成）
		_ = session
	}

	return conn, nil
}
