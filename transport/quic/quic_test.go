package quic

import (
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/tearsful/outbound/dialer"
)

func TestParseQuicConfig(t *testing.T) {
	tests := []struct {
		name     string
		link     string
		expected *QuicConfig
	}{
		{
			name: "Basic QUIC config",
			link: "quic://example.com:443?security=tls&key=testkey",
			expected: &QuicConfig{
				Host:               "example.com",
				Port:               443,
				Security:           "tls",
				Key:                "testkey",
				HeaderType:         "none",
				IdleTimeout:        30 * time.Second,
				KeepAlivePeriod:    10 * time.Second,
				MaxIncomingStreams: 1000,
			},
		},
		{
			name: "QUIC with advanced parameters",
			link: "quic://server.com:8443?security=reality&publicKey=pubkey&shortId=shortid&spiderX=spiderx&idleTimeout=60s&keepAlivePeriod=20s&maxIncomingStreams=2000&disablePathMTUDiscovery=true",
			expected: &QuicConfig{
				Host:                    "server.com",
				Port:                    8443,
				Security:                "reality",
				IdleTimeout:             60 * time.Second,
				KeepAlivePeriod:         20 * time.Second,
				MaxIncomingStreams:      2000,
				DisablePathMTUDiscovery: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.link)
			if err != nil {
				t.Fatalf("Failed to parse URL: %v", err)
			}

			config := parseQuicConfig(u)

			if config.Host != tt.expected.Host {
				t.Errorf("Host = %v, want %v", config.Host, tt.expected.Host)
			}
			if config.Port != tt.expected.Port {
				t.Errorf("Port = %v, want %v", config.Port, tt.expected.Port)
			}
			if config.Security != tt.expected.Security {
				t.Errorf("Security = %v, want %v", config.Security, tt.expected.Security)
			}
		})
	}
}

func TestNewQuic(t *testing.T) {
	tests := []struct {
		name    string
		link    string
		wantErr bool
	}{
		{
			name:    "Valid QUIC link",
			link:    "quic://example.com:443?security=tls",
			wantErr: false,
		},
		{
			name:    "Invalid QUIC link",
			link:    "invalid-link",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := NewQuic(&dialer.ExtraOption{}, nil, tt.link)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewQuic() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// parseQuicConfig 解析QUIC配置的辅助函数
func parseQuicConfig(u *url.URL) *QuicConfig {
	config := &QuicConfig{
		Host:               u.Hostname(),
		Port:               443,
		Security:           "none",
		HeaderType:         "none",
		IdleTimeout:        30 * time.Second,
		KeepAlivePeriod:    10 * time.Second,
		MaxIncomingStreams: 1000,
	}

	// 解析端口
	if portStr := u.Port(); portStr != "" {
		if port, err := strconv.Atoi(portStr); err == nil {
			config.Port = port
		}
	}

	// 解析查询参数
	query := u.Query()
	if security := query.Get("security"); security != "" {
		config.Security = security
	}
	if key := query.Get("key"); key != "" {
		config.Key = key
	}
	if headerType := query.Get("headerType"); headerType != "" {
		config.HeaderType = headerType
	}
	if idleTimeout := query.Get("idleTimeout"); idleTimeout != "" {
		if duration, err := time.ParseDuration(idleTimeout); err == nil {
			config.IdleTimeout = duration
		}
	}
	if keepAlive := query.Get("keepAlivePeriod"); keepAlive != "" {
		if duration, err := time.ParseDuration(keepAlive); err == nil {
			config.KeepAlivePeriod = duration
		}
	}
	if maxStreams := query.Get("maxIncomingStreams"); maxStreams != "" {
		if streams, err := strconv.ParseInt(maxStreams, 10, 64); err == nil {
			config.MaxIncomingStreams = streams
		}
	}
	if disablePathMTU := query.Get("disablePathMTUDiscovery"); disablePathMTU == "true" {
		config.DisablePathMTUDiscovery = true
	}

	return config
}
