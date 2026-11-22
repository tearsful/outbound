package grpc

import (
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

func TestGrpcClientCacheKeySeparatesTLSPolicy(t *testing.T) {
	secure := grpcClientCacheKey("", "d1", "example.com:443", "example.com", false, false, 0, false)
	insecureKey := grpcClientCacheKey("", "d1", "example.com:443", "example.com", true, false, 0, false)
	h2c := grpcClientCacheKey("", "d1", "example.com:443", "example.com", false, true, 0, false)
	otherSNI := grpcClientCacheKey("", "d1", "example.com:443", "other.example.com", false, false, 0, false)
	otherDialer := grpcClientCacheKey("", "d2", "example.com:443", "example.com", false, false, 0, false)
	otherMark := grpcClientCacheKey("", "d1", "example.com:443", "example.com", false, false, 100, false)
	otherScope := grpcClientCacheKey("reload-1", "d1", "example.com:443", "example.com", false, false, 0, false)
	if secure == otherScope {
		t.Fatalf("different reload scope must not share cache key: %q", secure)
	}

	if secure == insecureKey {
		t.Fatalf("secure and insecure dials must not share cache key: %q", secure)
	}
	if secure == h2c {
		t.Fatalf("tls and h2c dials must not share cache key: %q", secure)
	}
	if secure == otherSNI {
		t.Fatalf("different SNI must not share cache key: %q", secure)
	}
	if secure == otherDialer {
		t.Fatalf("different dialer identity must not share cache key: %q", secure)
	}
	if secure == otherMark {
		t.Fatalf("different mark must not share cache key: %q", secure)
	}
}

func newTestClientConn(t *testing.T) *grpc.ClientConn {
	t.Helper()
	cc, err := grpc.Dial("passthrough:///unused", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

func TestAcquireGrpcClientConnGunIsDedicated(t *testing.T) {
	CleanGlobalClientConnectionCache()
	t.Cleanup(CleanGlobalClientConnectionCache)

	calls := 0
	create := func() (*grpc.ClientConn, error) {
		calls++
		return newTestClientConn(t), nil
	}

	meta1, release1, err := acquireGrpcClientConn("k", false, create)
	if err != nil {
		t.Fatal(err)
	}
	meta2, release2, err := acquireGrpcClientConn("k", false, create)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("gun mode factory calls = %d, want 2", calls)
	}
	if meta1.cc == meta2.cc {
		t.Fatal("gun mode should return dedicated ClientConn instances")
	}

	release1()
	release2()
	if meta1.cc.GetState() != connectivity.Shutdown || meta2.cc.GetState() != connectivity.Shutdown {
		t.Fatal("gun mode release should close dedicated ClientConn")
	}
}

func TestAcquireGrpcClientConnMultiIsShared(t *testing.T) {
	CleanGlobalClientConnectionCache()
	t.Cleanup(CleanGlobalClientConnectionCache)

	calls := 0
	create := func() (*grpc.ClientConn, error) {
		calls++
		return newTestClientConn(t), nil
	}

	meta1, release1, err := acquireGrpcClientConn("shared-key", true, create)
	if err != nil {
		t.Fatal(err)
	}
	meta2, release2, err := acquireGrpcClientConn("shared-key", true, create)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("multi mode factory calls = %d, want 1", calls)
	}
	if meta1.cc != meta2.cc {
		t.Fatal("multi mode should reuse ClientConn")
	}

	release1()
	release2()
	if meta1.cc.GetState() == connectivity.Shutdown {
		t.Fatal("multi mode stream close must not shut down shared ClientConn")
	}

	CleanGlobalClientConnectionCache()
	if meta1.cc.GetState() != connectivity.Shutdown {
		t.Fatal("CleanGlobalClientConnectionCache should close shared ClientConn")
	}
}

func TestClientConnCloseIsIdempotent(t *testing.T) {
	calls := 0
	c := NewClientConn(nil, func() { calls++ })
	_ = c.Close()
	_ = c.Close()
	if calls != 1 {
		t.Fatalf("closer calls = %d, want 1", calls)
	}
}
