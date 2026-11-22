package v2ray

import "testing"

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
