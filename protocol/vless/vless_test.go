package vless

import (
	"testing"

	"github.com/daeuniverse/outbound/protocol"
)

func TestNewDialer(t *testing.T) {
	tests := []struct {
		name     string
		header   protocol.Header
		wantErr  bool
		flowType string
	}{
		{
			name: "Valid XTLS Vision flow",
			header: protocol.Header{
				ProxyAddress: "example.com:443",
				Password:     "12345678-1234-1234-1234-123456789abc",
				Feature1:     XRV,
				IsClient:     true,
			},
			wantErr:  false,
			flowType: XRV,
		},
		{
			name: "Valid Vision Reality flow",
			header: protocol.Header{
				ProxyAddress: "example.com:443",
				Password:     "12345678-1234-1234-1234-123456789abc",
				Feature1:     FlowVisionReality,
				IsClient:     true,
			},
			wantErr:  false,
			flowType: FlowVisionReality,
		},
		{
			name: "Valid Origin flow",
			header: protocol.Header{
				ProxyAddress: "example.com:443",
				Password:     "12345678-1234-1234-1234-123456789abc",
				Feature1:     FlowOrigin,
				IsClient:     true,
			},
			wantErr:  false,
			flowType: FlowOrigin,
		},
		{
			name: "Empty flow (should work)",
			header: protocol.Header{
				ProxyAddress: "example.com:443",
				Password:     "12345678-1234-1234-1234-123456789abc",
				Feature1:     "",
				IsClient:     true,
			},
			wantErr:  false,
			flowType: "",
		},
		{
			name: "Invalid flow type",
			header: protocol.Header{
				ProxyAddress: "example.com:443",
				Password:     "12345678-1234-1234-1234-123456789abc",
				Feature1:     "invalid-flow",
				IsClient:     true,
			},
			wantErr: true,
		},
		{
			name: "Short password (gets converted to UUID5)",
			header: protocol.Header{
				ProxyAddress: "example.com:443",
				Password:     "invalid-uuid",
				Feature1:     XRV,
				IsClient:     true,
			},
			wantErr:  false,
			flowType: XRV,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialer, err := NewDialer(nil, tt.header)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDialer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				vlessDialer := dialer.(*Dialer)
				if vlessDialer.flow != tt.flowType {
					t.Errorf("NewDialer() flow = %v, want %v", vlessDialer.flow, tt.flowType)
				}
				if vlessDialer.encryption != "none" {
					t.Errorf("NewDialer() encryption = %v, want 'none'", vlessDialer.encryption)
				}
				if vlessDialer.level != 0 {
					t.Errorf("NewDialer() level = %v, want 0", vlessDialer.level)
				}
			}
		})
	}
}

func TestPassword2Key(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "Valid UUID with hyphens",
			password: "12345678-1234-1234-1234-123456789abc",
			wantErr:  false,
		},
		{
			name:     "Valid UUID without hyphens",
			password: "123456781234123412341234567890ab",
			wantErr:  false,
		},
		{
			name:     "Short string (will be converted to UUID5)",
			password: "test",
			wantErr:  false,
		},
		{
			name:     "Invalid hex characters",
			password: "12345678-1234-1234-1234-123456789xyz",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := Password2Key(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Password2Key() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(key) != 16 {
				t.Errorf("Password2Key() key length = %v, want 16", len(key))
			}
		})
	}
}

func TestFallbackManager(t *testing.T) {
	fallbacks := []Fallback{
		{
			Name: "http",
			Alpn: "http/1.1",
			Path: "/api",
			Dest: "127.0.0.1:8080",
		},
		{
			Name: "default",
			Dest: "127.0.0.1:80",
		},
	}

	manager := NewFallbackManager(fallbacks)

	tests := []struct {
		name     string
		alpn     string
		path     string
		wantName string
		wantErr  bool
	}{
		{
			name:     "Match ALPN and path",
			alpn:     "http/1.1",
			path:     "/api/test",
			wantName: "http",
			wantErr:  false,
		},
		{
			name:     "Match default",
			alpn:     "h2",
			path:     "/other",
			wantName: "default",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fallback, err := manager.SelectFallback(tt.alpn, tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("SelectFallback() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && fallback.Name != tt.wantName {
				t.Errorf("SelectFallback() name = %v, want %v", fallback.Name, tt.wantName)
			}
		})
	}
}

func TestVlessConstants(t *testing.T) {
	// 测试协议常量的正确性
	if Version != 0 {
		t.Errorf("Version = %v, want 0", Version)
	}
	if UUIDBytes != 16 {
		t.Errorf("UUIDBytes = %v, want 16", UUIDBytes)
	}
	if CmdTCP != 1 {
		t.Errorf("CmdTCP = %v, want 1", CmdTCP)
	}
	if CmdUDP != 2 {
		t.Errorf("CmdUDP = %v, want 2", CmdUDP)
	}
}
