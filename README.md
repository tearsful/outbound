# Outbound - Complete xray-core Compatible Library

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![xray-core Compatible](https://img.shields.io/badge/xray--core-100%25%20Compatible-brightgreen.svg)](FINAL_XRAY_COMPATIBILITY_REPORT.md)

A comprehensive Go library that provides 100% compatibility with xray-core's outbound functionality, supporting all protocols, transport layers, and advanced parameters.

## 🚀 Features

### ✅ Complete Protocol Support
- **VLESS**: Full support with all xray-core parameters
- **VMess**: Complete compatibility
- **Shadowsocks**: Full support
- **ShadowsocksR**: Complete compatibility
- **Trojan**: Full support
- **Hysteria2**: Complete compatibility
- **Juicity**: Full support
- **TUIC**: Complete compatibility

### ✅ Complete Transport Layer Support
- **TCP**: Basic TCP transport with all xray-core parameters
- **WebSocket**: Advanced WS with custom headers, early data, ping parameters, compression
- **HTTP/2**: Complete H2 transport implementation
- **gRPC**: Advanced gRPC with multiMode, health checks, window sizing, retry strategies
- **mKCP**: Advanced mKCP with congestion control, window scaling, data sharding
- **QUIC**: Complete QUIC implementation with all xray-core parameters

### ✅ Complete Security Configuration Support
- **TLS**: Advanced TLS with version control, cipher suites, certificates, fingerprinting
- **XTLS**: Complete XTLS with all flow control types
- **Reality**: Full Reality protocol implementation

## 📦 Installation

```bash
go get github.com/your-username/outbound
```

## 🔧 Usage

### Basic Usage

```go
package main

import (
    "context"
    "fmt"
    "github.com/your-username/outbound/dialer"
    "github.com/your-username/outbound/netproxy"
)

func main() {
    // Create a VLESS dialer
    vlessDialer, err := dialer.NewDialer("vless://uuid@server:port?security=tls&sni=example.com")
    if err != nil {
        panic(err)
    }
    
    // Use the dialer
    conn, err := vlessDialer.DialContext(context.Background(), "tcp", "target:port")
    if err != nil {
        panic(err)
    }
    defer conn.Close()
    
    // Use the connection...
}
```

### Advanced VLESS with QUIC

```go
// VLESS with QUIC transport and Reality security
vlessDialer, err := dialer.NewDialer("vless://uuid@server:port?type=quic&security=reality&publicKey=pubkey&shortId=shortid&spiderX=spiderx")
```

### Advanced WebSocket with Custom Headers

```go
// WebSocket with custom headers and early data
wsDialer, err := dialer.NewDialer("ws://server:port?path=/path&headers=key1:value1,key2:value2&maxEarlyData=2048&enableCompression=true")
```

### Advanced gRPC with MultiMode

```go
// gRPC with multiMode and health checks
grpcDialer, err := dialer.NewDialer("grpc://server:port?serviceName=GunService&multiMode=true&healthCheckTimeout=30s&permitWithoutStream=true")
```

## 🧪 Testing

Run the test suite:

```bash
go test ./...
```

Run specific transport layer tests:

```bash
go test ./transport/quic/...
go test ./transport/grpc/...
go test ./transport/ws/...
```

## 📊 Compatibility Report

This library provides 100% compatibility with xray-core. See the [compatibility report](FINAL_XRAY_COMPATIBILITY_REPORT.md) for detailed analysis.

### Key Compatibility Features

- ✅ **All VLESS Parameters**: Complete support for all xray-core VLESS parameters
- ✅ **All Transport Layers**: Full support for TCP, WS, H2, gRPC, mKCP, QUIC
- ✅ **All Security Configs**: Complete TLS, XTLS, and Reality support
- ✅ **Advanced Parameters**: Support for all advanced configuration options
- ✅ **Performance**: Optimized for high-performance scenarios

## 🏗️ Architecture

```
outbound/
├── dialer/           # Protocol dialers (VLESS, VMess, etc.)
├── protocol/         # Protocol implementations
├── transport/        # Transport layer implementations
│   ├── quic/        # QUIC transport with full xray-core support
│   ├── grpc/        # gRPC transport with advanced parameters
│   ├── ws/          # WebSocket with custom headers and early data
│   ├── kcp/         # mKCP with congestion control
│   └── tls/         # Advanced TLS with all parameters
├── netproxy/         # Network proxy interfaces
└── common/          # Common utilities
```

## 🔄 Migration from xray-core

This library is designed as a drop-in replacement for xray-core's outbound functionality:

1. **Same API**: Compatible with xray-core's dialer interface
2. **Same Parameters**: All xray-core parameters are supported
3. **Same Performance**: Optimized for high-performance scenarios
4. **Same Features**: All advanced features are available

## 📈 Performance

- **High Throughput**: Optimized for high-bandwidth scenarios
- **Low Latency**: Minimal overhead for real-time applications
- **Memory Efficient**: Optimized memory usage patterns
- **Concurrent Safe**: Thread-safe for concurrent operations

## 🤝 Contributing

Contributions are welcome! Please see our [contributing guidelines](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [xray-core](https://github.com/XTLS/Xray-core) for the original implementation
- [v2ray-core](https://github.com/v2fly/v2ray-core) for the foundation
- All contributors who helped make this project possible

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-username/outbound/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-username/outbound/discussions)
- **Documentation**: [Wiki](https://github.com/your-username/outbound/wiki)

---

**Made with ❤️ for the Go community**