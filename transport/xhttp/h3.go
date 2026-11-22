package xhttp

import (
	"crypto/tls"
	"net/http"

	"github.com/daeuniverse/quic-go/http3"
)

func newH3RoundTripper(tlsConf *tls.Config) http.RoundTripper {
	conf := tlsConf.Clone()
	// HTTP/3 requires ALPN "h3".
	conf.NextProtos = []string{http3.NextProtoH3}
	return &http3.RoundTripper{
		TLSClientConfig: conf,
	}
}
