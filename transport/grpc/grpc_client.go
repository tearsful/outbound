package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tearsful/outbound/netproxy"
	"github.com/tearsful/outbound/pkg/cert"
	proto "github.com/tearsful/outbound/pkg/gun_proto"
	"github.com/tearsful/outbound/pool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// https://github.com/v2fly/v2ray-core/blob/v5.0.6/transport/internet/grpc/dial.go
type clientConnMeta struct {
	cc *grpc.ClientConn
}

var (
	globalCCMap    map[string]*clientConnMeta
	globalCCAccess sync.Mutex
)

func scopedCachePrefix(scope string) string {
	return scope + "\x00"
}

func CleanGlobalClientConnectionCache() {
	globalCCAccess.Lock()
	cached := make([]*grpc.ClientConn, 0, len(globalCCMap))
	for _, meta := range globalCCMap {
		if meta != nil && meta.cc != nil {
			cached = append(cached, meta.cc)
		}
	}
	globalCCMap = make(map[string]*clientConnMeta)
	globalCCAccess.Unlock()

	for _, cc := range cached {
		_ = cc.Close()
	}
}

func CleanScopedClientConnectionCache(scope string) {
	if scope == "" {
		return
	}
	prefix := scopedCachePrefix(scope)
	globalCCAccess.Lock()
	var cached []*grpc.ClientConn
	for key, meta := range globalCCMap {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if meta != nil && meta.cc != nil {
			cached = append(cached, meta.cc)
		}
		delete(globalCCMap, key)
	}
	globalCCAccess.Unlock()

	for _, cc := range cached {
		_ = cc.Close()
	}
}

type ccCanceller func()

type ClientConn struct {
	tun       proto.GunService_TunClient
	closer    context.CancelFunc
	closeOnce sync.Once
	muReading sync.Mutex // muReading protects reading
	muWriting sync.Mutex // muWriting protects writing
	muRecv    sync.Mutex // muReading protects recv
	muSend    sync.Mutex // muWriting protects send
	buf       []byte
	offset    int

	deadlineMu    sync.Mutex
	readDeadline  *time.Timer
	writeDeadline *time.Timer

	ctxRead     context.Context
	cancelRead  func()
	ctxWrite    context.Context
	cancelWrite func()
	ctx         context.Context
	cancel      func()
}

func NewClientConn(tun proto.GunService_TunClient, closer context.CancelFunc) *ClientConn {
	ctx, cancel := context.WithCancel(context.Background())
	ctxRead, cancelRead := context.WithCancel(context.Background())
	ctxWrite, cancelWrite := context.WithCancel(context.Background())
	if closer == nil {
		closer = func() {}
	}
	return &ClientConn{
		tun:         tun,
		closer:      closer,
		ctx:         ctx,
		cancel:      cancel,
		ctxRead:     ctxRead,
		cancelRead:  cancelRead,
		ctxWrite:    ctxWrite,
		cancelWrite: cancelWrite,
	}
}

type RecvResp struct {
	hunk *proto.Hunk
	err  error
}

func (c *ClientConn) Read(p []byte) (n int, err error) {
	select {
	case <-c.ctxRead.Done():
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	default:
	}

	c.muReading.Lock()
	defer c.muReading.Unlock()
	if c.buf != nil {
		n = copy(p, c.buf[c.offset:])
		c.offset += n
		if c.offset == len(c.buf) {
			pool.Put(c.buf)
			c.buf = nil
		}
		return n, nil
	}
	// set 1 to avoid channel leak
	readDone := make(chan RecvResp, 1)
	// pass channel to the function to avoid closure leak
	go func(readDone chan RecvResp) {
		// FIXME: not really abort the send so there is some problems when recover
		c.muRecv.Lock()
		defer c.muRecv.Unlock()
		recv, e := c.tun.Recv()
		readDone <- RecvResp{
			hunk: recv,
			err:  e,
		}
	}(readDone)
	select {
	case <-c.ctxRead.Done():
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	case recvResp := <-readDone:
		err = recvResp.err
		if err != nil {
			if code := status.Code(err); code == codes.Unavailable || status.Code(err) == codes.OutOfRange {
				err = io.EOF
			}
			return 0, err
		}
		n = copy(p, recvResp.hunk.Data)
		c.buf = pool.Get(len(recvResp.hunk.Data) - n)
		copy(c.buf, recvResp.hunk.Data[n:])
		c.offset = 0
		return n, nil
	}
}

func (c *ClientConn) Write(p []byte) (n int, err error) {
	select {
	case <-c.ctxWrite.Done():
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	default:
	}

	c.muWriting.Lock()
	defer c.muWriting.Unlock()
	// set 1 to avoid channel leak
	sendDone := make(chan error, 1)
	// pass channel to the function to avoid closure leak
	go func(sendDone chan error) {
		// FIXME: not really abort the send so there is some problems when recover
		c.muSend.Lock()
		defer c.muSend.Unlock()
		e := c.tun.Send(&proto.Hunk{Data: p})
		sendDone <- e
	}(sendDone)
	select {
	case <-c.ctxWrite.Done():
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	case err = <-sendDone:
		if code := status.Code(err); code == codes.Unavailable || status.Code(err) == codes.OutOfRange {
			err = io.EOF
		}
		return len(p), err
	}
}

func (c *ClientConn) Close() error {
	c.closeOnce.Do(func() {
		select {
		case <-c.ctx.Done():
		default:
			c.cancel()
		}
		c.closer()
	})
	return nil
}
func (c *ClientConn) CloseWrite() error {
	return c.tun.CloseSend()
}

func (c *ClientConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		// refresh the deadline if the deadline has been exceeded
		select {
		case <-c.ctxRead.Done():
			c.ctxRead, c.cancelRead = context.WithCancel(context.Background())

		default:
		}
		select {
		case <-c.ctxWrite.Done():
			c.ctxWrite, c.cancelWrite = context.WithCancel(context.Background())
		default:
		}
		// reset the deadline timer
		if c.readDeadline != nil {
			c.readDeadline.Stop()
		}
		c.readDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.ctxRead.Done():
			default:
				c.cancelRead()
			}
		})
		if c.writeDeadline != nil {
			c.writeDeadline.Stop()
		}
		c.writeDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.ctxWrite.Done():
			default:
				c.cancelWrite()
			}
		})
	} else {
		select {
		case <-c.ctxRead.Done():
		default:
			c.cancelRead()
		}
		select {
		case <-c.ctxWrite.Done():
		default:
			c.cancelWrite()
		}
	}
	return nil
}

func (c *ClientConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		// refresh the deadline if the deadline has been exceeded
		select {
		case <-c.ctxRead.Done():
			c.ctxRead, c.cancelRead = context.WithCancel(context.Background())
		default:
		}
		// reset the deadline timer
		if c.readDeadline != nil {
			c.readDeadline.Stop()
		}
		c.readDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.ctxRead.Done():
			default:
				c.cancelRead()
			}
		})
	} else {
		select {
		case <-c.ctxRead.Done():
		default:
			c.cancelRead()
		}
	}
	return nil
}

func (c *ClientConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		// refresh the deadline if the deadline has been exceeded
		select {
		case <-c.ctxWrite.Done():
			c.ctxWrite, c.cancelWrite = context.WithCancel(context.Background())
		default:
		}
		if c.writeDeadline != nil {
			c.writeDeadline.Stop()
		}
		c.writeDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.ctxWrite.Done():
			default:
				c.cancelWrite()
			}
		})
	} else {
		select {
		case <-c.ctxWrite.Done():
		default:
			c.cancelWrite()
		}
	}
	return nil
}

type Dialer struct {
	NextDialer    netproxy.Dialer
	ServiceName   string
	ServerName    string
	AllowInsecure bool
	// PlainText uses h2c (no TLS). When false, gRPC dials with TLS.
	PlainText bool
	// MultiMode mirrors xray-core gRPC mode=multi/guna: reuse one HTTP/2
	// connection with concurrent Tun streams instead of gun-style singles.
	MultiMode bool
}

func (d *Dialer) DialContext(ctx context.Context, network string, address string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	if d.NextDialer == nil {
		return nil, fmt.Errorf("grpc: next dialer is nil")
	}

	meta, releaseCC, err := getGrpcClientConn(ctx, d.NextDialer, d.ServerName, address, d.AllowInsecure, d.PlainText, d.MultiMode, magicNetwork.Mark, magicNetwork.Mptcp)
	if err != nil {
		releaseCC()
		return nil, err
	}
	client := proto.NewGunServiceClient(meta.cc)

	clientX := client.(proto.GunServiceClientX)
	serviceName := d.ServiceName
	if serviceName == "" {
		serviceName = "GunService"
	}
	// ctx is the lifetime of the tun stream
	ctxStream, cancelStream := context.WithCancel(context.Background())
	tun, err := clientX.TunCustomName(ctxStream, serviceName)
	if err != nil {
		cancelStream()
		releaseCC()
		return nil, err
	}
	return NewClientConn(tun, func() {
		cancelStream()
		releaseCC()
	}), nil
}

type grpcConnFactory func() (*grpc.ClientConn, error)

// acquireGrpcClientConn implements the documented gun/multi split:
//   - gun (multiMode=false): dedicated ClientConn per logical dial; release closes it
//   - multi: shared ClientConn keyed by TLS identity; release is a no-op
func acquireGrpcClientConn(cacheKey string, multiMode bool, create grpcConnFactory) (*clientConnMeta, ccCanceller, error) {
	if !multiMode {
		cc, err := create()
		if err != nil {
			return nil, func() {}, err
		}
		return &clientConnMeta{cc: cc}, func() { _ = cc.Close() }, nil
	}

	globalCCAccess.Lock()
	defer globalCCAccess.Unlock()

	if globalCCMap == nil {
		globalCCMap = make(map[string]*clientConnMeta)
	}
	if meta, found := globalCCMap[cacheKey]; found && meta != nil && meta.cc != nil && meta.cc.GetState() != connectivity.Shutdown {
		return meta, func() {}, nil
	}

	cc, err := create()
	if err != nil {
		return nil, func() {}, err
	}
	meta := &clientConnMeta{cc: cc}
	globalCCMap[cacheKey] = meta
	return meta, func() {}, nil
}

func getGrpcClientConn(ctx context.Context, tcpDialer netproxy.Dialer, serverName string, address string, allowInsecure bool, plainText bool, multiMode bool, somark uint32, mptcp bool) (*clientConnMeta, ccCanceller, error) {
	var transportCreds grpc.DialOption
	if plainText {
		transportCreds = grpc.WithTransportCredentials(insecure.NewCredentials())
	} else {
		roots, err := cert.GetSystemCertPool()
		if err != nil {
			return nil, func() {}, fmt.Errorf("failed to get system certificate pool")
		}
		transportCreds = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			ServerName:         serverName,
			RootCAs:            roots,
			InsecureSkipVerify: allowInsecure,
		}))
	}

	scope := netproxy.TransportCacheNamespace(tcpDialer)
	cacheKey := grpcClientCacheKey(scope, fmt.Sprintf("%p", tcpDialer), address, serverName, allowInsecure, plainText, somark, mptcp)

	keepAlive := keepalive.ClientParameters{
		Time:                30 * time.Second,
		Timeout:             10 * time.Second,
		PermitWithoutStream: true,
	}
	windowSize := int32(65535)
	if multiMode {
		// Keep HTTP/2 warm for concurrent Tun streams.
		keepAlive.Time = 10 * time.Second
		keepAlive.Timeout = 20 * time.Second
		keepAlive.PermitWithoutStream = true
		windowSize = 1 << 20 // 1 MiB
	}

	create := func() (*grpc.ClientConn, error) {
		return grpc.DialContext(ctx, address,
			transportCreds,
			grpc.WithContextDialer(func(ctxGrpc context.Context, s string) (net.Conn, error) {
				tcpNetwork := netproxy.MagicNetwork{
					Network: "tcp",
					Mark:    somark,
					Mptcp:   mptcp,
				}.Encode()
				c, err := tcpDialer.DialContext(ctxGrpc, tcpNetwork, s)
				if err != nil {
					return nil, err
				}
				return &netproxy.FakeNetConn{
					Conn:  c,
					LAddr: nil,
					RAddr: nil,
				}, nil
			}), grpc.WithConnectParams(grpc.ConnectParams{
				Backoff: backoff.Config{
					BaseDelay:  500 * time.Millisecond,
					Multiplier: 1.5,
					Jitter:     0.2,
					MaxDelay:   19 * time.Second,
				},
				MinConnectTimeout: 5 * time.Second,
			}),
			grpc.WithKeepaliveParams(keepAlive),
			grpc.WithDefaultCallOptions(
				grpc.MaxCallRecvMsgSize(4*1024*1024),
				grpc.MaxCallSendMsgSize(4*1024*1024),
			),
			grpc.WithInitialWindowSize(windowSize),
			grpc.WithInitialConnWindowSize(windowSize),
		)
	}

	return acquireGrpcClientConn(cacheKey, multiMode, create)
}

// grpcClientCacheKey keeps reload-scope + dialer identity + TLS/socket policy
// in the key so insecure/secure, SNI, mark, or chained dialers never share a
// ClientConn, and CleanScopedClientConnectionCache can drop one generation.
func grpcClientCacheKey(scope, dialerID, address, serverName string, allowInsecure bool, plainText bool, somark uint32, mptcp bool) string {
	return fmt.Sprintf("%s\x00%s|%s|sni=%s|insecure=%t|h2c=%t|mark=%d|mptcp=%t", scope, dialerID, address, serverName, allowInsecure, plainText, somark, mptcp)
}
