package v2ray

import (
	"strings"
	"testing"
)

func TestParseVlessURLAllowInsecureAndFlowNone(t *testing.T) {
	s, err := ParseVlessURL("vless://12203a60-7e88-4930-b778-a9fa80c911e5@example.com:443?type=tcp&security=tls&flow=none&allowInsecure=1&encryption=none#n")
	if err != nil {
		t.Fatal(err)
	}
	if !s.AllowInsecure {
		t.Fatalf("AllowInsecure = false, want true")
	}
	if s.Flow != "" {
		t.Fatalf("Flow = %q, want empty after normalizing none", s.Flow)
	}

	exported := s.ExportToURL()
	if strings.Contains(strings.ToLower(exported), "flow=") {
		t.Fatalf("ExportToURL should omit empty flow, got %q", exported)
	}
	if !strings.Contains(exported, "allowInsecure=1") && !strings.Contains(exported, "allowInsecure=true") {
		t.Fatalf("ExportToURL should keep allowInsecure, got %q", exported)
	}
}

func TestParseVlessURLAllowInsecureAliases(t *testing.T) {
	for _, raw := range []string{
		"allowInsecure=1",
		"allow_insecure=true",
		"allowinsecure=yes",
		"skipVerify=y",
	} {
		u := "vless://12203a60-7e88-4930-b778-a9fa80c911e5@example.com:443?type=tcp&security=tls&encryption=none&" + raw + "#n"
		s, err := ParseVlessURL(u)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if !s.AllowInsecure {
			t.Fatalf("%s: AllowInsecure=false", raw)
		}
	}
}

func TestParseVlessURLGrpcMode(t *testing.T) {
	s, err := ParseVlessURL("vless://12203a60-7e88-4930-b778-a9fa80c911e5@example.com:443?type=grpc&security=tls&serviceName=GunService&mode=multi#g")
	if err != nil {
		t.Fatal(err)
	}
	if s.Mode != "multi" {
		t.Fatalf("Mode = %q, want multi", s.Mode)
	}
	if s.Path != "GunService" {
		t.Fatalf("Path = %q, want GunService", s.Path)
	}
}

func TestSecurityUsesTLSIncludesXTLS(t *testing.T) {
	if !securityUsesTLS("tls") || !securityUsesTLS("XTLS") {
		t.Fatal("tls/xtls should enable TLS wrap")
	}
	if securityUsesTLS("none") || securityUsesTLS("reality") {
		t.Fatal("none/reality should not use generic TLS wrap helper")
	}
}
