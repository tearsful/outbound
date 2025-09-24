package protocol

import "crypto/tls"

type Header struct {
	ProxyAddress string
	SNI          string
	Feature1     interface{}
	// 扩展特性字段用于不同协议方言的临时透传
	Feature2 interface{}
	Feature3 interface{}
	Feature4 interface{}
	Feature5 interface{}
	// 额外键值对参数（如 pqv、0rtt token 等）
	Extra     map[string]string
	TlsConfig *tls.Config
	Cipher    string
	User      string
	Password  string
	IsClient  bool
	Flags     Flags
}

type Flags uint64

const (
	Flags_VMess_UsePacketAddr = 1 << iota
)

const (
	Flags_Tuic_UdpRelayModeQuic = 1 << iota
)
