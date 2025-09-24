package grpc

import (
	"net/url"
	"testing"
	"time"
)

func TestParseGrpcConfig(t *testing.T) {
	tests := []struct {
		name     string
		link     string
		expected *GrpcConfig
	}{
		{
			name: "Basic gRPC config",
			link: "grpc://example.com:443?serviceName=GunService",
			expected: &GrpcConfig{
				ServiceName:                  "GunService",
				MultiMode:                    false,
				IdleTimeout:                  30 * time.Second,
				HealthCheckTimeout:           20 * time.Second,
				PermitWithoutStream:          false,
				MaxRecvMsgSize:               4 * 1024 * 1024,
				MaxSendMsgSize:               4 * 1024 * 1024,
				InitialWindowSize:            65535,
				InitialConnWindowSize:        65535,
				KeepAliveTime:                30 * time.Second,
				KeepAliveTimeout:             5 * time.Second,
				KeepAlivePermitWithoutStream: false,
				MinTime:                      5 * time.Minute,
				MaxConnectionIdle:            5 * time.Minute,
				MaxConnectionAge:             30 * time.Minute,
				MaxConnectionAgeGrace:        5 * time.Second,
				Time:                         2 * time.Hour,
				Timeout:                      20 * time.Second,
				MaxRetries:                   3,
				BackoffBaseDelay:             1.0 * time.Second,
				BackoffMaxDelay:              120 * time.Second,
				BackoffMultiplier:            1.6,
				BackoffJitter:                0.2,
				UserAgent:                    "grpc-go/1.0.0",
				Authority:                    "",
				MaxHeaderListSize:            16384,
				HeaderTableSize:              4096,
				NumStreamWorkers:             0,
				MaxConcurrentStreams:         100,
				WriteBufferSize:              32 * 1024,
				ReadBufferSize:               32 * 1024,
				NumServerWorkers:             0,
			},
		},
		{
			name: "Advanced gRPC config",
			link: "grpc://server.com:8443?serviceName=CustomService&multiMode=true&idleTimeout=60s&healthCheckTimeout=30s&permitWithoutStream=true&maxRecvMsgSize=8388608&maxSendMsgSize=8388608&initialWindowSize=131070&initialConnWindowSize=131070&keepAliveTime=60s&keepAliveTimeout=10s&keepAlivePermitWithoutStream=true&minTime=10m&maxConnectionIdle=10m&maxConnectionAge=60m&maxConnectionAgeGrace=10s&time=4h&timeout=40s&maxRetries=5&backoffBaseDelay=2s&backoffMaxDelay=240s&backoffMultiplier=2.0&backoffJitter=0.3&userAgent=custom-grpc/2.0.0&authority=custom.example.com&maxHeaderListSize=32768&headerTableSize=8192&numStreamWorkers=4&maxConcurrentStreams=200&writeBufferSize=65536&readBufferSize=65536&numServerWorkers=4",
			expected: &GrpcConfig{
				ServiceName:                  "CustomService",
				MultiMode:                    true,
				IdleTimeout:                  60 * time.Second,
				HealthCheckTimeout:           30 * time.Second,
				PermitWithoutStream:          true,
				MaxRecvMsgSize:               8 * 1024 * 1024,
				MaxSendMsgSize:               8 * 1024 * 1024,
				InitialWindowSize:            131070,
				InitialConnWindowSize:        131070,
				KeepAliveTime:                60 * time.Second,
				KeepAliveTimeout:             10 * time.Second,
				KeepAlivePermitWithoutStream: true,
				MinTime:                      10 * time.Minute,
				MaxConnectionIdle:            10 * time.Minute,
				MaxConnectionAge:             60 * time.Minute,
				MaxConnectionAgeGrace:        10 * time.Second,
				Time:                         2 * time.Hour,
				Timeout:                      20 * time.Second,
				MaxRetries:                   5,
				BackoffBaseDelay:             2.0 * time.Second,
				BackoffMaxDelay:              240 * time.Second,
				BackoffMultiplier:            2.0,
				BackoffJitter:                0.3,
				UserAgent:                    "custom-grpc/2.0.0",
				Authority:                    "custom.example.com",
				MaxHeaderListSize:            32768,
				HeaderTableSize:              8192,
				NumStreamWorkers:             4,
				MaxConcurrentStreams:         200,
				WriteBufferSize:              65536,
				ReadBufferSize:               65536,
				NumServerWorkers:             4,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.link)
			if err != nil {
				t.Fatalf("Failed to parse URL: %v", err)
			}

			config := ParseGrpcConfig(u)

			if config.ServiceName != tt.expected.ServiceName {
				t.Errorf("ServiceName = %v, want %v", config.ServiceName, tt.expected.ServiceName)
			}
			if config.MultiMode != tt.expected.MultiMode {
				t.Errorf("MultiMode = %v, want %v", config.MultiMode, tt.expected.MultiMode)
			}
			if config.IdleTimeout != tt.expected.IdleTimeout {
				t.Errorf("IdleTimeout = %v, want %v", config.IdleTimeout, tt.expected.IdleTimeout)
			}
			if config.HealthCheckTimeout != tt.expected.HealthCheckTimeout {
				t.Errorf("HealthCheckTimeout = %v, want %v", config.HealthCheckTimeout, tt.expected.HealthCheckTimeout)
			}
			if config.PermitWithoutStream != tt.expected.PermitWithoutStream {
				t.Errorf("PermitWithoutStream = %v, want %v", config.PermitWithoutStream, tt.expected.PermitWithoutStream)
			}
			if config.MaxRecvMsgSize != tt.expected.MaxRecvMsgSize {
				t.Errorf("MaxRecvMsgSize = %v, want %v", config.MaxRecvMsgSize, tt.expected.MaxRecvMsgSize)
			}
			if config.MaxSendMsgSize != tt.expected.MaxSendMsgSize {
				t.Errorf("MaxSendMsgSize = %v, want %v", config.MaxSendMsgSize, tt.expected.MaxSendMsgSize)
			}
			if config.InitialWindowSize != tt.expected.InitialWindowSize {
				t.Errorf("InitialWindowSize = %v, want %v", config.InitialWindowSize, tt.expected.InitialWindowSize)
			}
			if config.InitialConnWindowSize != tt.expected.InitialConnWindowSize {
				t.Errorf("InitialConnWindowSize = %v, want %v", config.InitialConnWindowSize, tt.expected.InitialConnWindowSize)
			}
			if config.KeepAliveTime != tt.expected.KeepAliveTime {
				t.Errorf("KeepAliveTime = %v, want %v", config.KeepAliveTime, tt.expected.KeepAliveTime)
			}
			if config.KeepAliveTimeout != tt.expected.KeepAliveTimeout {
				t.Errorf("KeepAliveTimeout = %v, want %v", config.KeepAliveTimeout, tt.expected.KeepAliveTimeout)
			}
			if config.KeepAlivePermitWithoutStream != tt.expected.KeepAlivePermitWithoutStream {
				t.Errorf("KeepAlivePermitWithoutStream = %v, want %v", config.KeepAlivePermitWithoutStream, tt.expected.KeepAlivePermitWithoutStream)
			}
			if config.MinTime != tt.expected.MinTime {
				t.Errorf("MinTime = %v, want %v", config.MinTime, tt.expected.MinTime)
			}
			if config.MaxConnectionIdle != tt.expected.MaxConnectionIdle {
				t.Errorf("MaxConnectionIdle = %v, want %v", config.MaxConnectionIdle, tt.expected.MaxConnectionIdle)
			}
			if config.MaxConnectionAge != tt.expected.MaxConnectionAge {
				t.Errorf("MaxConnectionAge = %v, want %v", config.MaxConnectionAge, tt.expected.MaxConnectionAge)
			}
			if config.MaxConnectionAgeGrace != tt.expected.MaxConnectionAgeGrace {
				t.Errorf("MaxConnectionAgeGrace = %v, want %v", config.MaxConnectionAgeGrace, tt.expected.MaxConnectionAgeGrace)
			}
			if config.Time != tt.expected.Time {
				t.Errorf("Time = %v, want %v", config.Time, tt.expected.Time)
			}
			if config.Timeout != tt.expected.Timeout {
				t.Errorf("Timeout = %v, want %v", config.Timeout, tt.expected.Timeout)
			}
			if config.MaxRetries != tt.expected.MaxRetries {
				t.Errorf("MaxRetries = %v, want %v", config.MaxRetries, tt.expected.MaxRetries)
			}
			if config.BackoffBaseDelay != tt.expected.BackoffBaseDelay {
				t.Errorf("BackoffBaseDelay = %v, want %v", config.BackoffBaseDelay, tt.expected.BackoffBaseDelay)
			}
			if config.BackoffMaxDelay != tt.expected.BackoffMaxDelay {
				t.Errorf("BackoffMaxDelay = %v, want %v", config.BackoffMaxDelay, tt.expected.BackoffMaxDelay)
			}
			if config.BackoffMultiplier != tt.expected.BackoffMultiplier {
				t.Errorf("BackoffMultiplier = %v, want %v", config.BackoffMultiplier, tt.expected.BackoffMultiplier)
			}
			if config.BackoffJitter != tt.expected.BackoffJitter {
				t.Errorf("BackoffJitter = %v, want %v", config.BackoffJitter, tt.expected.BackoffJitter)
			}
			if config.UserAgent != tt.expected.UserAgent {
				t.Errorf("UserAgent = %v, want %v", config.UserAgent, tt.expected.UserAgent)
			}
			if config.Authority != tt.expected.Authority {
				t.Errorf("Authority = %v, want %v", config.Authority, tt.expected.Authority)
			}
			if config.MaxHeaderListSize != tt.expected.MaxHeaderListSize {
				t.Errorf("MaxHeaderListSize = %v, want %v", config.MaxHeaderListSize, tt.expected.MaxHeaderListSize)
			}
			if config.HeaderTableSize != tt.expected.HeaderTableSize {
				t.Errorf("HeaderTableSize = %v, want %v", config.HeaderTableSize, tt.expected.HeaderTableSize)
			}
			if config.NumStreamWorkers != tt.expected.NumStreamWorkers {
				t.Errorf("NumStreamWorkers = %v, want %v", config.NumStreamWorkers, tt.expected.NumStreamWorkers)
			}
			if config.MaxConcurrentStreams != tt.expected.MaxConcurrentStreams {
				t.Errorf("MaxConcurrentStreams = %v, want %v", config.MaxConcurrentStreams, tt.expected.MaxConcurrentStreams)
			}
			if config.WriteBufferSize != tt.expected.WriteBufferSize {
				t.Errorf("WriteBufferSize = %v, want %v", config.WriteBufferSize, tt.expected.WriteBufferSize)
			}
			if config.ReadBufferSize != tt.expected.ReadBufferSize {
				t.Errorf("ReadBufferSize = %v, want %v", config.ReadBufferSize, tt.expected.ReadBufferSize)
			}
			if config.NumServerWorkers != tt.expected.NumServerWorkers {
				t.Errorf("NumServerWorkers = %v, want %v", config.NumServerWorkers, tt.expected.NumServerWorkers)
			}
		})
	}
}
