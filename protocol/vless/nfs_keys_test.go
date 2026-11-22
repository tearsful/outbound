package vless

import (
	"encoding/base64"
	"testing"

	"github.com/tearsful/outbound/protocol"
)

func TestParseNfsPKeysCSVBase64(t *testing.T) {
	// 准备两个 key（32 与 1088 字节的占位）
	k1 := make([]byte, 32)
	k1[0] = 1
	k2 := make([]byte, 1088)
	k2[0] = 2
	csv := base64.RawURLEncoding.EncodeToString(k1) + "," + base64.RawURLEncoding.EncodeToString(k2)

	keys, err := ParseNfsPKeysCSVBase64(csv)
	if err != nil {
		t.Fatalf("parse nfs keys failed: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expect 2 keys, got %d", len(keys))
	}
	if len(keys[0]) != 32 || keys[0][0] != 1 {
		t.Fatalf("unexpected key[0]")
	}
	if len(keys[1]) != 1088 || keys[1][0] != 2 {
		t.Fatalf("unexpected key[1]")
	}
}

func TestDialerReadsNfsPKeysFromHeaderExtra(t *testing.T) {
	k1 := make([]byte, 32)
	k1[0] = 7
	csv := base64.RawURLEncoding.EncodeToString(k1)

	h := protocol.Header{
		ProxyAddress: "example.com:443",
		Password:     "12203a60-7e88-4930-b778-a9fa80c911e5",
		Feature1:     "",
		Feature2:     "mlkem768x25519plus.native.0rtt",
		Feature3:     "xhttp",
		IsClient:     true,
		Extra: map[string]string{
			"NfsPKeys": csv,
			"pqv":      "dummy-pqv",
			"o0rtt":    "dummy-token",
		},
	}

	d, err := NewDialer(nil, h)
	if err != nil {
		t.Fatalf("new dialer failed: %v", err)
	}

	vd := d.(*Dialer)
	if len(vd.nfsKeys) != 1 || len(vd.nfsKeys[0]) != 32 || vd.nfsKeys[0][0] != 7 {
		t.Fatalf("dialer nfsKeys not parsed correctly")
	}
	if vd.pqv != "dummy-pqv" || vd.o0rttToken != "dummy-token" {
		t.Fatalf("pqv/o0rtt not wired correctly")
	}
}
