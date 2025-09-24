package vless

// Fallback 定义 VLESS 协议的回退机制，兼容 Xray-core
type Fallback struct {
	Name string // 回退名称
	Alpn string // ALPN 协议标识
	Path string // 路径匹配
	Dest string // 回退目标地址
	Xver uint32 // PROXY protocol 版本
}

// VlessUser 定义 VLESS 用户配置，兼容 Xray-core
type VlessUser struct {
	ID         string // 用户 UUID
	Flow       string // 流控制类型
	Encryption string // 加密方式 (对于 VLESS 通常是 "none")
	Level      uint32 // 用户级别
}

// VlessServerConfig 定义 VLESS 服务器配置
type VlessServerConfig struct {
	Address string      // 服务器地址
	Port    uint32      // 服务器端口
	Users   []VlessUser // 用户列表
}

// VlessConfig 定义完整的 VLESS 配置结构
type VlessConfig struct {
	VNext []VlessServerConfig // 服务器列表
}

// VlessSettings 定义 VLESS 协议设置
type VlessSettings struct {
	Decryption string     // 解密方式
	Fallbacks  []Fallback // 回退配置列表
}

// 支持的加密方式常量
const (
	EncryptionNone = "none"
)

// 支持的用户级别常量
const (
	UserLevelDefault = 0
	UserLevelVIP     = 1
)
