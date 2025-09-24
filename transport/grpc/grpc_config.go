package grpc

import (
	"net/url"
	"strconv"
	"time"
)

// GrpcConfig 定义 gRPC 传输配置
type GrpcConfig struct {
	ServiceName                  string
	MultiMode                    bool
	IdleTimeout                  time.Duration
	HealthCheckTimeout           time.Duration
	PermitWithoutStream          bool
	MaxRecvMsgSize               int
	MaxSendMsgSize               int
	InitialWindowSize            int32
	InitialConnWindowSize        int32
	KeepAliveTime                time.Duration
	KeepAliveTimeout             time.Duration
	KeepAlivePermitWithoutStream bool
	MinTime                      time.Duration
	MaxConnectionIdle            time.Duration
	MaxConnectionAge             time.Duration
	MaxConnectionAgeGrace        time.Duration
	Time                         time.Duration
	Timeout                      time.Duration
	MaxRetries                   uint32
	BackoffBaseDelay             time.Duration
	BackoffMaxDelay              time.Duration
	BackoffMultiplier            float64
	BackoffJitter                float64
	UserAgent                    string
	Authority                    string
	MaxHeaderListSize            uint32
	HeaderTableSize              uint32
	NumStreamWorkers             uint32
	MaxConcurrentStreams         uint32
	WriteBufferSize              int
	ReadBufferSize               int
	NumServerWorkers             uint32
	// 简化的配置结构，避免重复声明
}

// ParseGrpcConfig 从URL解析gRPC配置
func ParseGrpcConfig(u *url.URL) *GrpcConfig {
	config := &GrpcConfig{
		ServiceName:                  "GunService",
		MultiMode:                    false,
		IdleTimeout:                  30 * time.Second,
		HealthCheckTimeout:           20 * time.Second,
		PermitWithoutStream:          false,
		MaxRecvMsgSize:               4 * 1024 * 1024, // 4MB
		MaxSendMsgSize:               4 * 1024 * 1024, // 4MB
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
	}

	query := u.Query()

	// 解析基础参数
	if serviceName := query.Get("serviceName"); serviceName != "" {
		config.ServiceName = serviceName
	}
	if multiMode := query.Get("multiMode"); multiMode == "true" {
		config.MultiMode = true
	}
	if permitWithoutStream := query.Get("permitWithoutStream"); permitWithoutStream == "true" {
		config.PermitWithoutStream = true
	}

	// 解析超时参数
	if idleTimeout := query.Get("idleTimeout"); idleTimeout != "" {
		if val, err := time.ParseDuration(idleTimeout); err == nil {
			config.IdleTimeout = val
		}
	}
	if healthCheckTimeout := query.Get("healthCheckTimeout"); healthCheckTimeout != "" {
		if val, err := time.ParseDuration(healthCheckTimeout); err == nil {
			config.HealthCheckTimeout = val
		}
	}

	// 解析消息大小参数
	if maxRecvMsgSize := query.Get("maxRecvMsgSize"); maxRecvMsgSize != "" {
		if val, err := strconv.Atoi(maxRecvMsgSize); err == nil {
			config.MaxRecvMsgSize = val
		}
	}
	if maxSendMsgSize := query.Get("maxSendMsgSize"); maxSendMsgSize != "" {
		if val, err := strconv.Atoi(maxSendMsgSize); err == nil {
			config.MaxSendMsgSize = val
		}
	}

	// 解析窗口大小参数
	if initialWindowSize := query.Get("initialWindowSize"); initialWindowSize != "" {
		if val, err := strconv.ParseInt(initialWindowSize, 10, 32); err == nil {
			config.InitialWindowSize = int32(val)
		}
	}
	if initialConnWindowSize := query.Get("initialConnWindowSize"); initialConnWindowSize != "" {
		if val, err := strconv.ParseInt(initialConnWindowSize, 10, 32); err == nil {
			config.InitialConnWindowSize = int32(val)
		}
	}

	// 解析KeepAlive参数
	if keepAliveTime := query.Get("keepAliveTime"); keepAliveTime != "" {
		if val, err := time.ParseDuration(keepAliveTime); err == nil {
			config.KeepAliveTime = val
		}
	}
	if keepAliveTimeout := query.Get("keepAliveTimeout"); keepAliveTimeout != "" {
		if val, err := time.ParseDuration(keepAliveTimeout); err == nil {
			config.KeepAliveTimeout = val
		}
	}
	if keepAlivePermitWithoutStream := query.Get("keepAlivePermitWithoutStream"); keepAlivePermitWithoutStream == "true" {
		config.KeepAlivePermitWithoutStream = true
	}

	// 解析连接参数
	if minTime := query.Get("minTime"); minTime != "" {
		if val, err := time.ParseDuration(minTime); err == nil {
			config.MinTime = val
		}
	}
	if maxConnectionIdle := query.Get("maxConnectionIdle"); maxConnectionIdle != "" {
		if val, err := time.ParseDuration(maxConnectionIdle); err == nil {
			config.MaxConnectionIdle = val
		}
	}
	if maxConnectionAge := query.Get("maxConnectionAge"); maxConnectionAge != "" {
		if val, err := time.ParseDuration(maxConnectionAge); err == nil {
			config.MaxConnectionAge = val
		}
	}
	if maxConnectionAgeGrace := query.Get("maxConnectionAgeGrace"); maxConnectionAgeGrace != "" {
		if val, err := time.ParseDuration(maxConnectionAgeGrace); err == nil {
			config.MaxConnectionAgeGrace = val
		}
	}

	// 解析重试参数
	if maxRetries := query.Get("maxRetries"); maxRetries != "" {
		if val, err := strconv.ParseUint(maxRetries, 10, 32); err == nil {
			config.MaxRetries = uint32(val)
		}
	}
	if backoffBaseDelay := query.Get("backoffBaseDelay"); backoffBaseDelay != "" {
		if val, err := time.ParseDuration(backoffBaseDelay); err == nil {
			config.BackoffBaseDelay = val
		}
	}
	if backoffMaxDelay := query.Get("backoffMaxDelay"); backoffMaxDelay != "" {
		if val, err := time.ParseDuration(backoffMaxDelay); err == nil {
			config.BackoffMaxDelay = val
		}
	}
	if backoffMultiplier := query.Get("backoffMultiplier"); backoffMultiplier != "" {
		if val, err := strconv.ParseFloat(backoffMultiplier, 64); err == nil {
			config.BackoffMultiplier = val
		}
	}
	if backoffJitter := query.Get("backoffJitter"); backoffJitter != "" {
		if val, err := strconv.ParseFloat(backoffJitter, 64); err == nil {
			config.BackoffJitter = val
		}
	}

	// 解析其他参数
	if userAgent := query.Get("userAgent"); userAgent != "" {
		config.UserAgent = userAgent
	}
	if authority := query.Get("authority"); authority != "" {
		config.Authority = authority
	}
	if maxHeaderListSize := query.Get("maxHeaderListSize"); maxHeaderListSize != "" {
		if val, err := strconv.ParseUint(maxHeaderListSize, 10, 32); err == nil {
			config.MaxHeaderListSize = uint32(val)
		}
	}
	if headerTableSize := query.Get("headerTableSize"); headerTableSize != "" {
		if val, err := strconv.ParseUint(headerTableSize, 10, 32); err == nil {
			config.HeaderTableSize = uint32(val)
		}
	}
	if numStreamWorkers := query.Get("numStreamWorkers"); numStreamWorkers != "" {
		if val, err := strconv.ParseUint(numStreamWorkers, 10, 32); err == nil {
			config.NumStreamWorkers = uint32(val)
		}
	}
	if maxConcurrentStreams := query.Get("maxConcurrentStreams"); maxConcurrentStreams != "" {
		if val, err := strconv.ParseUint(maxConcurrentStreams, 10, 32); err == nil {
			config.MaxConcurrentStreams = uint32(val)
		}
	}
	if writeBufferSize := query.Get("writeBufferSize"); writeBufferSize != "" {
		if val, err := strconv.Atoi(writeBufferSize); err == nil {
			config.WriteBufferSize = val
		}
	}
	if readBufferSize := query.Get("readBufferSize"); readBufferSize != "" {
		if val, err := strconv.Atoi(readBufferSize); err == nil {
			config.ReadBufferSize = val
		}
	}
	if numServerWorkers := query.Get("numServerWorkers"); numServerWorkers != "" {
		if val, err := strconv.ParseUint(numServerWorkers, 10, 32); err == nil {
			config.NumServerWorkers = uint32(val)
		}
	}

	return config
}
