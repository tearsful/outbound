package shadowsocks

import "testing"

func TestParseSip003PluginOnlyDoesNotPanic(t *testing.T) {
	got := ParseSip003("v2ray-plugin")
	if got.Name != "v2ray-plugin" {
		t.Fatalf("Name=%q, want v2ray-plugin", got.Name)
	}
}

func TestParseSip003SimpleObfs(t *testing.T) {
	got := ParseSip003("obfs-local;obfs=tls;obfs-host=example.com")
	if got.Name != "simple-obfs" || got.Opts.Obfs != "tls" || got.Opts.Host != "example.com" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseSip003ShadowTLS(t *testing.T) {
	got := ParseSip003("shadow-tls;host=a.example")
	if got.Name != "shadow-tls" || got.Opts.Host != "a.example" {
		t.Fatalf("got %+v", got)
	}
}
