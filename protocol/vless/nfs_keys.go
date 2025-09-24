package vless

import (
	"encoding/base64"
	"strings"
	"sync"
)

// NfsKeyCache 提供基于目标地址的服务端 NFS 公钥链缓存
type NfsKeyCache struct {
	mu    sync.RWMutex
	cache map[string][][]byte // key: host:port
}

var defaultNfsKeyCache = &NfsKeyCache{cache: make(map[string][][]byte)}

func (c *NfsKeyCache) Get(server string) ([][]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.cache[server]
	return v, ok
}

func (c *NfsKeyCache) Set(server string, keys [][]byte) {
	c.mu.Lock()
	c.cache[server] = keys
	c.mu.Unlock()
}

// ParseNfsPKeysCSVBase64 解析以逗号分隔的 base64url 键列表
// 每个元素应为单个公钥（X25519 32 字节或 ML-KEM768 1088 字节）的 base64url 表示
func ParseNfsPKeysCSVBase64(csv string) ([][]byte, error) {
	if strings.TrimSpace(csv) == "" {
		return nil, nil
	}
	parts := strings.Split(csv, ",")
	keys := make([][]byte, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		b, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil {
			// 兼容标准 base64
			if b2, err2 := base64.StdEncoding.DecodeString(p); err2 == nil {
				b = b2
			} else {
				return nil, err
			}
		}
		keys = append(keys, b)
	}
	return keys, nil
}
