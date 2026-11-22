package xhttp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestResolveXHTTPHostPortPrefersConfigHost(t *testing.T) {
	host, err := resolveXHTTPHostPort(&XHTTPConfig{Host: "proxy.example.com"}, "1.2.3.4:443")
	if err != nil {
		t.Fatal(err)
	}
	if host != "proxy.example.com:443" {
		t.Fatalf("host = %q", host)
	}
}

func TestStreamOneBidirectional(t *testing.T) {
	var gotUpload []byte
	var mu sync.Mutex

	// stream-one needs true request/response duplex; use HTTP/2 over TLS.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if r.ProtoMajor < 2 {
			t.Errorf("expected HTTP/2, got %s", r.Proto)
		}
		// Flush headers first so the client can obtain the response while still uploading.
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		mu.Lock()
		gotUpload = append([]byte(nil), body...)
		mu.Unlock()
		_, _ = w.Write([]byte("down-data"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	d, err := NewXHTTPDialer(&XHTTPConfig{
		Host: strings.TrimPrefix(srv.URL, "https://"),
		Path: "/",
		Mode: "stream-one",
	})
	if err != nil {
		t.Fatal(err)
	}
	d.client = srv.Client()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := d.dialBidirectionalStream(ctx, srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("up-data"))
		if err == nil {
			if closer, ok := conn.(interface{ CloseWrite() error }); ok {
				err = closer.CloseWrite()
			}
		}
		writeErr <- err
	}()

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "down-data" {
		t.Fatalf("download = %q", got)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("upload write: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := bytes.Equal(gotUpload, []byte("up-data"))
		mu.Unlock()
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("upload = %q, want up-data", gotUpload)
}

func TestPacketUpUploadsChunks(t *testing.T) {
	var uploads [][]byte
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("from-server"))
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			uploads = append(uploads, append([]byte(nil), body...))
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	d, err := NewXHTTPDialer(&XHTTPConfig{
		Host:             strings.TrimPrefix(srv.URL, "http://"),
		Path:             "/",
		Mode:             "packet-up",
		MaxEachPostBytes: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	d.client = srv.Client()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := d.dialPacketMode(ctx, srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("abcdefgh")); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "from-server" {
		t.Fatalf("download = %q", got)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		nPosts := len(uploads)
		mu.Unlock()
		if nPosts >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(uploads) < 2 {
		t.Fatalf("expected chunked uploads, got %#v", uploads)
	}
	joined := bytes.Join(uploads, nil)
	if !bytes.Equal(joined, []byte("abcdefgh")) {
		t.Fatalf("uploads joined = %q", joined)
	}
}
