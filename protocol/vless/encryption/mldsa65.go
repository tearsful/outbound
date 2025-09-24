package vless

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// MLDSA65Auth 实现 MLDSA65 认证
type MLDSA65Auth struct {
	// 种子（32字节）
	seed []byte
	// 验证公钥（1952字节）
	verifyKey []byte
	// 私钥
	privateKey sign.PrivateKey
	// 公钥
	publicKey sign.PublicKey
}

// NewMLDSA65Auth 创建新的 MLDSA65 认证实例
func NewMLDSA65Auth(seed, verifyKey []byte) (*MLDSA65Auth, error) {
	auth := &MLDSA65Auth{
		seed:      seed,
		verifyKey: verifyKey,
	}

	// 如果提供了种子，生成密钥对
	if len(seed) > 0 {
		if len(seed) != 32 {
			return nil, fmt.Errorf("invalid seed length: expected 32 bytes, got %d", len(seed))
		}

		// 从种子生成密钥
		var seedArray [32]byte
		copy(seedArray[:], seed)
		// CIRCL 返回顺序为 (publicKey, privateKey)
		pub, priv := mldsa65.NewKeyFromSeed(&seedArray)
		auth.privateKey = priv
		auth.publicKey = pub
	}

	// 如果提供了验证公钥，解析它
	if len(verifyKey) > 0 {
		if len(verifyKey) != 1952 {
			return nil, fmt.Errorf("invalid verify key length: expected 1952 bytes, got %d", len(verifyKey))
		}

		// 解析验证公钥
		verifyPublicKey, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(verifyKey)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal verify key: %v", err)
		}
		// 赋值为接口类型
		auth.publicKey = verifyPublicKey
	}

	return auth, nil
}

// NewMLDSA65AuthFromBase64 从 Base64 编码的种子和验证密钥创建认证实例
func NewMLDSA65AuthFromBase64(seedBase64, verifyKeyBase64 string) (*MLDSA65Auth, error) {
	var seed []byte
	var verifyKey []byte
	var err error

	if seedBase64 != "" {
		seed, err = base64.RawURLEncoding.DecodeString(seedBase64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode seed: %v", err)
		}
	}

	if verifyKeyBase64 != "" {
		verifyKey, err = base64.RawURLEncoding.DecodeString(verifyKeyBase64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode verify key: %v", err)
		}
	}

	return NewMLDSA65Auth(seed, verifyKey)
}

// Sign 使用 MLDSA65 私钥签名数据
func (auth *MLDSA65Auth) Sign(data []byte) ([]byte, error) {
	if auth.privateKey == nil {
		return nil, fmt.Errorf("private key not available")
	}

	// 计算数据的哈希
	hash := sha256.Sum256(data)

	// 使用 MLDSA65 签名（CIRCL API）
	sig := mldsa65.Scheme().Sign(auth.privateKey, hash[:], nil)
	return sig, nil
}

// Verify 使用 MLDSA65 公钥验证签名
func (auth *MLDSA65Auth) Verify(data, signature []byte) error {
	if auth.publicKey == nil {
		return fmt.Errorf("public key not available")
	}

	// 计算数据的哈希
	hash := sha256.Sum256(data)

	// 使用 MLDSA65 验证
	valid := mldsa65.Scheme().Verify(auth.publicKey, hash[:], signature, nil)

	if !valid {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

// VerifyWithExternalKey 使用外部公钥验证签名
func (auth *MLDSA65Auth) VerifyWithExternalKey(data, signature, publicKeyBytes []byte) error {
	if len(publicKeyBytes) != 1952 {
		return fmt.Errorf("invalid public key length: expected 1952 bytes, got %d", len(publicKeyBytes))
	}

	// 解析公钥
	publicKey, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(publicKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal public key: %v", err)
	}

	// 计算数据的哈希
	hash := sha256.Sum256(data)

	// 使用 MLDSA65 验证（CIRCL API 返回 bool）
	valid := mldsa65.Scheme().Verify(publicKey, hash[:], signature, nil)

	if !valid {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

// GetPublicKeyBytes 获取公钥的字节表示
func (auth *MLDSA65Auth) GetPublicKeyBytes() ([]byte, error) {
	if auth.publicKey == nil {
		return nil, fmt.Errorf("public key not available")
	}
    if pk, ok := auth.publicKey.(*mldsa65.PublicKey); ok {
        return pk.Bytes(), nil
    }
    return nil, fmt.Errorf("unexpected public key type")
}

// GetPublicKeyBase64 获取公钥的 Base64 编码
func (auth *MLDSA65Auth) GetPublicKeyBase64() (string, error) {
	keyBytes, err := auth.GetPublicKeyBytes()
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(keyBytes), nil
}

// GetSeed 获取种子
func (auth *MLDSA65Auth) GetSeed() []byte {
	return auth.seed
}

// GetSeedBase64 获取种子的 Base64 编码
func (auth *MLDSA65Auth) GetSeedBase64() string {
	return base64.RawURLEncoding.EncodeToString(auth.seed)
}

// GetVerifyKey 获取验证密钥
func (auth *MLDSA65Auth) GetVerifyKey() []byte {
	return auth.verifyKey
}

// GetVerifyKeyBase64 获取验证密钥的 Base64 编码
func (auth *MLDSA65Auth) GetVerifyKeyBase64() string {
	return base64.RawURLEncoding.EncodeToString(auth.verifyKey)
}

// IsValid 检查认证实例是否有效
func (auth *MLDSA65Auth) IsValid() bool {
	return auth.privateKey != nil || len(auth.verifyKey) > 0
}

// GenerateKeyPair 生成新的密钥对
func GenerateMLDSA65KeyPair() (sign.PrivateKey, sign.PublicKey, error) {
    pub, priv, err := mldsa65.Scheme().GenerateKey()
    if err != nil {
        return nil, nil, err
    }
    return priv, pub, nil
}

// GenerateKeyPairFromSeed 从种子生成密钥对
func GenerateMLDSA65KeyPairFromSeed(seed [32]byte) (sign.PrivateKey, sign.PublicKey) {
	pub, priv := mldsa65.NewKeyFromSeed(&seed)
	return priv, pub
}
