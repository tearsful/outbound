# VLESS 协议 Xray-core 兼容性增强

本文档描述了为使当前项目的 VLESS 协议实现完美适配 [Xray-core](https://github.com/XTLS/Xray-core/blob/main/proxy/vless/outbound/outbound.go) 而进行的改进。

## 主要改进

### 1. 配置结构增强 ✅

- **新增 protobuf 配置**: 扩展了 `config.proto` 以支持完整的 Xray-core 兼容参数集
- **VlessConfig**: 添加了服务器配置结构
- **ServerConfig**: 支持地址、端口和用户列表配置
- **User**: 包含 ID、流控制、加密方式和用户级别
- **VlessSettings**: 支持解密方式和回退配置
- **Fallback**: 完整的回退机制配置

### 2. 流控制支持扩展 ✅

新增支持的流控制类型：
- `xtls-rprx-vision` (原有)
- `xtls-rprx-vision-udp443` 
- `xtls-rprx-origin`
- `xtls-rprx-origin-udp443`
- `xtls-rprx-direct`
- `xtls-rprx-direct-udp443`
- `xtls-rprx-splice`
- `xtls-rprx-splice-udp443`

### 3. 加密方式支持 ✅

- **验证机制**: 确保 VLESS 协议只使用 `"none"` 加密方式
- **兼容性检查**: 在连接建立时验证加密参数
- **元数据扩展**: 在 Metadata 结构中添加加密和级别字段

### 4. Fallback 回退机制 ✅

- **FallbackManager**: 新的回退管理器类
- **智能选择**: 基于 ALPN 和路径的回退选择逻辑
- **FallbackConn**: 回退连接包装器
- **配置支持**: 支持多个回退目标配置

### 5. 协议版本更新 ✅

- **协议常量**: 添加了完整的 VLESS 协议常量定义
- **版本检查**: 改进了协议版本验证逻辑
- **头部处理**: 更新了请求和响应头部处理
- **错误处理**: 改进了错误信息和兼容性检查

## 新增文件

1. **types.go**: 定义了 Xray-core 兼容的数据类型
2. **fallback.go**: 实现了完整的回退机制
3. **README_XRAY_COMPATIBILITY.md**: 本文档

## 更新的文件

1. **config.proto**: 扩展了 protobuf 配置
2. **dialer.go**: 增强了拨号器以支持更多参数
3. **conn.go**: 更新了连接处理逻辑
4. **dialer/v2ray/v2ray.go**: 增加了 URL 解析和导出支持

## 协议兼容性

### 支持的参数

| 参数 | 描述 | Xray-core 兼容性 |
|------|------|-------------------|
| `id` | 用户 UUID | ✅ 完全兼容 |
| `flow` | 流控制类型 | ✅ 支持所有主要类型 |
| `encryption` | 加密方式 | ✅ 仅支持 "none" |
| `level` | 用户级别 | ✅ 支持数值级别 |
| `fallbacks` | 回退配置 | ✅ 完整实现 |

### URL 格式支持

现在支持解析和生成包含以下参数的 VLESS URL：
- `encryption`: 加密方式参数
- `seed`: 种子参数（用于某些传输类型）
- 所有原有的传输和安全参数

## 使用示例

```go
// 创建支持扩展流控制的 VLESS 连接
dialer, err := vless.NewDialer(nextDialer, protocol.Header{
    ProxyAddress: "example.com:443",
    Password:     "uuid-string",
    Feature1:     "xtls-rprx-vision-udp443", // 新支持的流控制类型
    IsClient:     true,
})
```

## 测试状态

- ✅ 编译测试通过
- ✅ 语法检查通过
- ✅ 类型检查通过

## 兼容性保证

所有改进都保持向后兼容，不影响现有功能：
- 现有的 VLESS 连接继续正常工作
- 新参数都有合理的默认值
- 错误处理得到改进但不破坏现有行为

## 参考资源

- [Xray-core VLESS Outbound](https://github.com/XTLS/Xray-core/blob/main/proxy/vless/outbound/outbound.go)
- [VLESS 协议规范](https://github.com/XTLS/Xray-core/tree/main/proxy/vless)
- [XTLS 流控制文档](https://xtls.github.io/config/outbound.html#vlessobject)
