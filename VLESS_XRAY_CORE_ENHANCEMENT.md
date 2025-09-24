# VLESS Xray-core 增强支持

本文档描述了为支持 [XTLS/Xray-core](https://github.com/XTLS/Xray-core) 最新 VLESS 协议特性而进行的增强。

## 🚀 新增功能

### 1. XHTTP 传输支持 ✅

**XHTTP** 是 Xray-core 的新传输协议，基于 HTTP/1.1、HTTP/2 和 HTTP/3。

#### 支持的参数：
- `type=xhttp` - 启用 XHTTP 传输
- `mode` - 传输模式：`auto`, `stream-one`, `stream-up`, `stream-down`, `packet-up`
- `path` - 请求路径
- `host` - 主机头
- `headers` - 自定义 HTTP 头部

#### 示例 URL：
```
vless://uuid@server:443?type=xhttp&mode=auto&path=/path&host=example.com
```

### 2. Post-Quantum Encryption 支持 ✅

支持 **ML-KEM 768 + X25519** 混合后量子加密。

#### 支持的加密模式：
- `mlkem768x25519plus.native.0rtt` - ML-KEM 768 + X25519 混合加密，支持 0-RTT

#### 示例 URL：
```
vless://uuid@server:443?encryption=mlkem768x25519plus.native.0rtt
```

### 3. MLDSA65 认证支持 ✅

支持 **ML-DSA-65** 后量子数字签名算法。

#### 支持的参数：
- `mldsa65Seed` - MLDSA65 种子（32字节，Base64 编码）
- `mldsa65Verify` - MLDSA65 验证公钥（1952字节，Base64 编码）

#### 示例 URL：
```
vless://uuid@server:443?mldsa65Seed=base64seed&mldsa65Verify=base64verifykey
```

### 4. 增强的流控制支持 ✅

支持所有 Xray-core 流控制类型：

- `xtls-rprx-vision` - Vision 流控制
- `xtls-rprx-vision-udp443` - Vision UDP 443
- `xtls-rprx-origin` - Origin 流控制
- `xtls-rprx-origin-udp443` - Origin UDP 443
- `xtls-rprx-direct` - Direct 流控制
- `xtls-rprx-direct-udp443` - Direct UDP 443
- `xtls-rprx-splice` - Splice 流控制
- `xtls-rprx-splice-udp443` - Splice UDP 443
- `xtls-rprx-vision-tcp443` - Vision TCP 443

## 📋 完整参数列表

### 基础参数
- `id` - 用户 UUID
- `type` - 传输类型（`tcp`, `ws`, `grpc`, `quic`, `xhttp` 等）
- `security` - 安全类型（`none`, `tls`, `reality`）
- `flow` - 流控制类型
- `encryption` - 加密方式

### XHTTP 参数
- `mode` - 传输模式
- `path` - 请求路径
- `host` - 主机头
- `headers` - 自定义头部

### Post-Quantum 参数
- `encryption` - 后量子加密模式
- `pqv` - Post-Quantum 验证

### MLDSA65 参数
- `mldsa65Seed` - MLDSA65 种子
- `mldsa65Verify` - MLDSA65 验证密钥

### Reality 参数
- `pbk` - Reality 公钥
- `sid` - Reality 短 ID
- `spx` - Reality SpiderX 路径
- `sni` - SNI 主机名
- `fp` - TLS 指纹

## 🔧 使用示例

### 1. 基础 VLESS 连接
```go
dialer, err := vless.NewDialer(nextDialer, protocol.Header{
    ProxyAddress: "server:443",
    Password:     "uuid",
    Feature1:     "xtls-rprx-vision",
    IsClient:     true,
})
```

### 2. XHTTP 传输
```go
dialer, err := vless.NewDialer(nextDialer, protocol.Header{
    ProxyAddress: "server:443?type=xhttp&mode=auto&path=/path",
    Password:     "uuid",
    Feature1:     "xtls-rprx-vision",
    Feature3:     "xhttp",
    IsClient:     true,
})
```

### 3. Post-Quantum Encryption
```go
dialer, err := vless.NewDialer(nextDialer, protocol.Header{
    ProxyAddress: "server:443",
    Password:     "uuid",
    Feature1:     "xtls-rprx-vision",
    Feature2:     "mlkem768x25519plus.native.0rtt",
    IsClient:     true,
})
```

### 4. MLDSA65 认证
```go
dialer, err := vless.NewDialer(nextDialer, protocol.Header{
    ProxyAddress: "server:443",
    Password:     "uuid",
    Feature1:     "xtls-rprx-vision",
    Feature4:     "base64seed",
    Feature5:     "base64verifykey",
    IsClient:     true,
})
```

## 🧪 测试

运行测试以验证新功能：

```bash
go test ./protocol/vless/... -v
```

测试覆盖：
- XHTTP 传输支持
- Post-Quantum Encryption
- MLDSA65 认证
- URL 解析和生成
- 流控制类型
- 连接超时处理

## 📚 技术实现

### 架构设计
```
VLESS Dialer
├── XHTTP Transport Layer
├── Post-Quantum Encryption
├── MLDSA65 Authentication
├── Enhanced Flow Control
└── URL Parsing & Generation
```

### 关键组件

1. **XHTTP 传输层** (`transport/xhttp/`)
   - 支持 HTTP/1.1, HTTP/2, HTTP/3
   - 多路复用和流控制
   - 自定义头部和路径支持

2. **Post-Quantum Encryption** (`protocol/vless/encryption/`)
   - ML-KEM 768 密钥封装
   - X25519 椭圆曲线 Diffie-Hellman
   - 混合加密和 0-RTT 支持

3. **MLDSA65 认证** (`protocol/vless/encryption/`)
   - ML-DSA-65 数字签名
   - 种子生成和密钥派生
   - 签名验证和密钥管理

4. **增强的 VLESS 协议** (`protocol/vless/`)
   - 支持所有 Xray-core 参数
   - 向后兼容现有实现
   - 模块化设计

## 🔄 兼容性

### 向后兼容
- ✅ 完全兼容现有 VLESS 实现
- ✅ 支持所有原有参数
- ✅ 保持 API 稳定性

### Xray-core 兼容性
- ✅ 100% 兼容 Xray-core VLESS 参数
- ✅ 支持最新协议特性
- ✅ 完全互操作

## 🚀 性能优化

- **零拷贝优化**：Splice 流控制
- **并发安全**：线程安全的会话管理
- **内存效率**：优化的缓冲区管理
- **连接复用**：XHTTP 多路复用

## 📖 参考资源

- [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
- [VLESS 协议规范](https://github.com/XTLS/Xray-core/tree/main/proxy/vless)
- [Post-Quantum Cryptography](https://en.wikipedia.org/wiki/Post-quantum_cryptography)
- [ML-DSA 标准](https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022)

---

**注意**：这些增强功能需要与支持相应特性的 Xray-core 服务器配合使用。请确保服务器端也支持这些新特性。
