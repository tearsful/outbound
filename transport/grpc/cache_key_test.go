package grpc

import "testing"

func TestGrpcClientCacheKeySeparatesTLSPolicy(t *testing.T) {
	secure := grpcClientCacheKey("example.com:443", "example.com", false, false)
	insecure := grpcClientCacheKey("example.com:443", "example.com", true, false)
	otherSNI := grpcClientCacheKey("example.com:443", "other.example.com", false, false)
	multi := grpcClientCacheKey("example.com:443", "example.com", false, true)

	if secure == insecure {
		t.Fatalf("secure and insecure dials must not share cache key: %q", secure)
	}
	if secure == otherSNI {
		t.Fatalf("different SNI must not share cache key: %q", secure)
	}
	if secure == multi {
		t.Fatalf("multi mode must not share cache key with default: %q", secure)
	}
	if want := "example.com:443|sni=example.com|insecure=false|multi"; multi != want {
		t.Fatalf("multi key = %q, want %q", multi, want)
	}
}
