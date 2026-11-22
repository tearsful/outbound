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

	"github.com/tearsful/outbound/netproxy"
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

func TestParseXHTTPConfigHostPortForms(t *testing.T) {
	cases := []struct {
		in   string
		host string
		path string
		mode string
	}{
		{"1.2.3.4:443", "1.2.3.4:443", "", ""},
		{"example.com:443?type=xhttp&path=/path&mode=auto", "example.com:443", "/path", "auto"},
		{"https://cdn.example.com:8443/xhttp?mode=stream-one&host=virtual.example", "cdn.example.com:8443", "/xhttp", "stream-one"},
	}
	for _, tc := range cases {
		cfg, err := ParseXHTTPConfig(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if cfg.Host != tc.host || cfg.Path != tc.path || cfg.Mode != tc.mode {
			t.Fatalf("%s: got host=%q path=%q mode=%q", tc.in, cfg.Host, cfg.Path, cfg.Mode)
		}
	}
	cfg, err := ParseXHTTPConfig("example.com:443?host=cdn.example.com&path=/")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Headers["Host"] != "cdn.example.com" {
		t.Fatalf("Host header = %q", cfg.Headers["Host"])
	}
}

func TestDialContextDoesNotLeakHeadersIntoQuery(t *testing.T) {
	var sawURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawURL = r.URL.String()
		if r.Host != "cdn.example.com" {
			t.Errorf("Host = %q", r.Host)
		}
		if strings.Contains(r.URL.RawQuery, "Host=") {
			t.Errorf("headers leaked into query: %s", r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	d, err := NewXHTTPDialer(&XHTTPConfig{
		Host:    strings.TrimPrefix(srv.URL, "https://"),
		Path:    "/xhttp",
		Mode:    "packet-up",
		Headers: map[string]string{"Host": "cdn.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	d.client = srv.Client()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 8)
	_, _ = conn.Read(buf)
	if sawURL == "" {
		t.Fatal("request not observed")
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

type stubConn struct{}

func (stubConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (stubConn) Write(b []byte) (int, error)      { return len(b), nil }
func (stubConn) Close() error                     { return nil }
func (stubConn) SetDeadline(time.Time) error      { return nil }
func (stubConn) SetReadDeadline(time.Time) error  { return nil }
func (stubConn) SetWriteDeadline(time.Time) error { return nil }

type stubUnderlay struct {
	dialed chan string
}

func (s *stubUnderlay) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	select {
	case s.dialed <- addr:
	default:
	}
	return stubConn{}, nil
}

func TestXHTTPUsesUnderlayDialer(t *testing.T) {
	under := &stubUnderlay{dialed: make(chan string, 1)}
	d, err := NewXHTTPDialerWithOptions(&XHTTPConfig{
		Host: "proxy.example.com:443",
		Path: "/",
		Mode: "packet-up",
	}, &DialerOptions{Underlay: under, AlreadyTLS: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, _ = d.DialContext(ctx, "tcp", "proxy.example.com:443")
	select {
	case addr := <-under.dialed:
		if addr != "proxy.example.com:443" {
			t.Fatalf("underlay addr = %q", addr)
		}
	case <-ctx.Done():
		t.Fatal("underlay was not used")
	}
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
