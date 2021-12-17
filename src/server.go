// server.go -- TCP Listener
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"context"
	"crypto/tls"
	//"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	L "github.com/opencoff/go-logger"
	"github.com/opencoff/go-ratelimit"
)

// Common server state
type Server struct {
	// listen address
	*ListenConf

	conf *Conf

	// optional - will be set only if listening via TLS
	tls *tls.Config

	// optional - will be set only if connecting to a TLS peer
	clientTls *tls.Config

	dial    Dialer
	dialnet string

	// for seamless shutdown
	ctx    context.Context
	cancel context.CancelFunc

	pool *sync.Pool

	activeConn map[string]*relay
	mu         sync.Mutex

	wg sync.WaitGroup

	rl *ratelimit.Limiter

	log *L.Logger
}

// Encapsulates info needed to be a plain listener or a TLS listener.
// And has a dialer to connect to a plain or TLS endpoint
type TCPServer struct {
	*net.TCPListener

	*Server
}

type QuicServer struct {
	quic.Listener

	*Server
}

type Dialer interface {
	// Conn is our abstraction over TCP/TLS and quic.ic
	Dial(net, addr string, lhs Conn, c context.Context) (Conn, error)
}

// I/O writer, reader, closer and deadlines
// We will implement this for quic.ic as streams
type Conn interface {
	net.Conn
}

// relay context
type relay struct {
	ctx context.Context

	lconn Conn
	rconn Conn

	lhs string
	rhs string
}

// Make a new instance of a Server and return it
// This function exits on any configuration parsing error.
func NewServer(lc *ListenConf, c *Conf, log *L.Logger) Proxy {
	addr := lc.Addr

	// create a sub-logger with the listener's prefix.
	log = log.New(addr, 0)

	// Conf file specifies ratelimit as N conns/sec
	rl, err := ratelimit.New(lc.Ratelimit.Global, lc.Ratelimit.PerHost, lc.Ratelimit.CacheSize)
	if err != nil {
		die("%s: Can't create ratelimiter: %s", addr, err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		ListenConf: lc,
		conf:       c,
		tls:        lc.serverCfg,
		clientTls:  lc.clientCfg,
		log:        log,
		ctx:        ctx,
		cancel:     cancel,
		activeConn: make(map[string]*relay),

		// IOSize is a global in main; it can be changed via command line flag
		pool: &sync.Pool{
			New: func() interface{} { return make([]byte, IOSize) },
		},
		rl: rl,
	}

	if t := lc.Tls; t != nil && len(t.Sni) > 0 {
		s.tls.GetCertificate = s.getSNIHandler(t.Sni, log)
	}

	if lc.Connect.IsQuic() {
		q, err := newQuicDialer(s, log)
		if err != nil {
			die("can't create quic dialer: %s", err)
		}
		s.dial = q
		s.dialnet = "udp"
	} else {
		t, err := newTCPDialer(s, log)
		if err != nil {
			die("can't create TCP dialer: %s", err)
		}
		s.dial = t
		s.dialnet = "tcp"
	}

	if lc.Quic {
		return s.newQuicServer()
	}

	return s.newTCPServer()
}

func (s *Server) newTCPServer() Proxy {
	addr := s.Addr

	la, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		die("Can't resolve %s: %s", addr, err)
	}

	ln, err := net.ListenTCP("tcp", la)
	if err != nil {
		die("Can't listen on %s: %s", addr, err)
	}

	p := &TCPServer{
		TCPListener: ln,
		Server:      s,
	}
	return p
}

func (s *Server) newQuicServer() Proxy {
	addr := s.Addr

	if len(s.tls.ServerName) == 0 {
		die("Quic Server %s: No TLS server name specified", addr)
	}

	la, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		die("Can't resolve %s: %s", addr, err)
	}

	ln, err := net.ListenUDP("udp", la)
	if err != nil {
		die("Can't listen on %s: %s", addr, err)
	}

	// we need to set the next-proto to be relay or socks
	var nextproto = "relay"
	s.tls.NextProtos = []string{nextproto}

	// XXX do we verify ServerName?

	qcfg := &quic.Config{
		KeepAlive: true,
	}

	q, err := quic.Listen(ln, s.tls, qcfg)
	if err != nil {
		die("can't start quic listener on %s: %s", addr, err)
	}

	p := &QuicServer{
		Listener: q,
		Server:   s,
	}

	return p
}

// Start listener
func (p *TCPServer) Start() {

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		if p.tls != nil {
			p.log.Info("Starting TLS server ..")
		} else {
			p.log.Info("Starting TCP server ..")
		}

		p.log.Info("Ratelimit: Global %d req/s, Per-host: %d req/s",
			p.Ratelimit.Global, p.Ratelimit.PerHost)

		p.serveTCP()
	}()
}

// Stop server
func (p *TCPServer) Stop() {
	p.cancel()
	p.TCPListener.Close() // causes Accept() to abort
	p.wg.Wait()
	p.log.Info("TCP server shutdown")
}

// Start Quic listener
func (p *QuicServer) Start() {

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		p.log.Info("Starting Quic server ..")
		p.log.Info("Ratelimit: Global %d req/s, Per-host: %d req/s",
			p.Ratelimit.Global, p.Ratelimit.PerHost)

		p.serveQuic()
	}()
}

// Stop server
func (p *QuicServer) Stop() {
	p.cancel()
	p.Listener.Close() // causes Accept() to abort
	p.wg.Wait()
	p.log.Info("Quic server shutdown")
}

func (p *TCPServer) serveTCP() {
	n := 0
	done := p.ctx.Done()
	defer p.Close()
	for {
		conn, err := p.Accept()
		select {
		case <-done:
			return
		default:
		}

		if err != nil {
			n += 1
			if n >= 10 {
				p.log.Warn("Accept failure: %s", err)
				p.log.Warn("10 consecutive server accept() failure; bailing ..")
				return
			}

			time.Sleep(2 * time.Second)
			continue
		}

		n = 0
		src := conn.RemoteAddr().String()
		ctx := context.WithValue(p.ctx, "client", src)

		p.wg.Add(1)
		go p.handleTCP(conn, ctx)
	}
}

func (p *QuicServer) serveQuic() {
	n := 0
	done := p.ctx.Done()
	defer p.Close()
	for {
		err := p.rl.Wait(p.ctx)
		if errors.Is(err, context.Canceled) {
			return
		}

		sess, err := p.Accept(p.ctx)
		select {
		case <-done:
			return
		default:
		}

		if err != nil {
			n += 1
			if n >= 10 {
				p.log.Warn("Accept failure: %s", err)
				p.log.Warn("10 consecutive server accept() failure; bailing ..")
				return
			}

			time.Sleep(2 * time.Second)
			continue
		}

		there := sess.RemoteAddr()

		// wait for per-host ratelimiter
		p.rl.WaitHost(p.ctx, there)

		// Check ACLs only after we have ratelimited inbound conns
		if !AclOK(p.ListenConf, there) {
			p.log.Debug("ACL failure: %s", there)
			sess.CloseWithError(401, "Not authorized")
			continue
		}

		n = 0
		p.wg.Add(1)
		go p.serviceSession(sess)
	}
}

func (p *QuicServer) serviceSession(sess quic.Session) {
	defer p.wg.Done()
	done := p.ctx.Done()

	n := 0
	for {
		// we also accept the corresponding stream
		conn, err := sess.AcceptStream(p.ctx)
		select {
		case <-done:
			return
		default:
		}

		if err != nil {
			n += 1
			if n >= 10 {
				p.log.Warn("AcceptStream failure: %s", err)
				p.log.Warn("10 consecutive server AcceptStream() failure; bailing ..")
				return
			}

			time.Sleep(2 * time.Second)
			continue
		}

		n = 0
		qc := &qConn{
			Stream: conn,
			s:      sess,
		}
		peer := qc.LocalAddr()
		ctx := context.WithValue(p.ctx, "client", peer.String())

		qc.log = p.log.New(peer.String(), 0)

		p.wg.Add(1)
		go p.handleConn(qc, ctx, qc.log)
	}
}

func (p *TCPServer) handleTCP(conn Conn, ctx context.Context) {
	if p.tls != nil {
		lhs := conn.RemoteAddr().String()
		econn := tls.Server(conn, p.tls)
		err := econn.Handshake()
		if err != nil {
			p.log.Warn("can't establish TLS with %s: %s", lhs, err)
			conn.Close()
			p.wg.Done()
			return
		}

		st := econn.ConnectionState()
		p.log.Debug("tls server handshake with %s complete; Version %#x, Cipher %#x", lhs,
			st.Version, st.CipherSuite)
		conn = econn
	}

	log := p.log.New(conn.RemoteAddr().String(), 0)
	p.handleConn(conn, ctx, log)
}

// handle the relay from 'conn' to the peer and back.
// this sets up the peer connection before the relay
func (p *Server) handleConn(conn Conn, ctx context.Context, log *L.Logger) {
	defer func() {
		p.wg.Done()
		conn.Close()
	}()

	var err error
	var network, addr string
	var nr int

	b0 := p.getBuf()
	addr = p.Connect.Addr
	network = p.dialnet
	socks := p.Connect.IsSocks()

	if socks {
		network, addr, nr, err = p.socks(conn, b0, log)
		if err != nil {
			return
		}
	}

	peer, err := p.dial.Dial(network, addr, conn, ctx)
	if err != nil {
		log.Warn("can't connect to %s: %s", addr, err)

		// send error message or success to client
		// buffer b0 is still intact
		if socks {
			b0[1] = 0x4 // XXX generic error
			WriteAll(conn, b0[:nr])
		}
		return
	}

	if socks {
		b0[1] = 0x0
		_, err = WriteAll(conn, b0[:nr])
		select {
		case <-p.ctx.Done():
			return
		default:
		}
		if err != nil {
			log.Warn("can't write socks response: %s", err)
			return
		}
	}

	defer peer.Close()

	// we grab the printable info before the socket is closed
	lhs_there := conn.LocalAddr().String()
	lhs_here := conn.RemoteAddr().String()
	rhs_here := peer.LocalAddr().String()
	rhs_there := peer.RemoteAddr().String()
	inbound := fmt.Sprintf("%s-%s", lhs_here, lhs_there)
	outbound := fmt.Sprintf("%s-%s", rhs_here, rhs_there)

	// we really need to log this in the parent logger
	p.log.Debug("LHS %s, RHS %s", inbound, outbound)

	// create a child logger anchored to the remote-addr
	log = log.New(outbound, 0)

	var wg sync.WaitGroup

	b1 := p.getBuf()

	wg.Add(2)
	ch := make(chan bool)
	go func() {
		wg.Wait()
		close(ch)
	}()

	var r0, r1, w0, w1 int
	go func() {
		defer wg.Done()
		r0, w0 = p.cancellableCopy(conn, peer, b0, ctx, log)
	}()

	go func() {
		defer wg.Done()
		r1, w1 = p.cancellableCopy(peer, conn, b1, ctx, log)
	}()

	select {
	case <-ctx.Done():
		<-ch

	case <-ch:
	}

	p.putBuf(b0)
	p.putBuf(b1)

	log.Info("%s: rd %d, wr %d; %s: rd %d, wr %d", inbound, r1, w0, outbound, r0, w1)
}

// Negotiate socksv5 with peer 'fd' and return endpoints to dial
func (p *Server) socks(fd Conn, buf []byte, log *L.Logger) (network, addr string, nr int, err error) {

	done := p.ctx.Done()
	// Socksv5 state machine:
	// 1. Read Methods
	// 2. Write Method Response
	// 3. Read ConnInfo
	// 4. Write Conn Response

	n, err := fd.Read(buf)
	select {
	case <-done:
		err = errShutdown
		return
	default:
	}
	if err != nil {
		log.Warn("unable to read Socks version info: %s", err)
		return
	}

	if n < 2 {
		log.Warn("insufficient socks method info (exp at least 2, saw %d)", n)
		err = errMsgTooSmall
		return
	}

	if buf[0] != 0x5 {
		log.Warn("unsupported socks version %d", buf[0])
		err = errUnsupportedSocksVer
		return
	}

	// so, we write a hard-coded response saying "no auth needed"
	buf[1] = 0
	_, err = WriteAll(fd, buf[:2])
	select {
	case <-done:
		err = errShutdown
		return
	default:
	}
	if err != nil {
		log.Warn("unable to write socks greeting: %s", err)
		return
	}

	// next read conn setup info
	n, err = fd.Read(buf)
	select {
	case <-done:
		err = errShutdown
		return
	default:
	}
	if err != nil {
		log.Warn("unable to read socks connect info: %s", err)
		return
	}

	// minimum size is 10 bytes:
	//  0: ver
	//  1: cmd
	//  2: resv
	//  3: atype
	//  4-7: IPv4 addr
	//  8-9: port
	if n < 10 {
		log.Warn("insufficient socks method info (exp at least 10, saw %d)", n)
		err = errMsgTooSmall
		return
	}

	//log.Debug("socks-connect: %d bytes\n%s", n, hex.Dump(buf[:n]))

	nr = n
	switch buf[1] {
	case 0x1:
		network = "tcp"
	case 0x2:
		log.Warn("unsupported 'bind' type for socks")
		err = errUnsupportedMethod
		return
	case 0x3:
		network = "udp"
	}

	// buf[2] is Reserved

	// we've consumed 4 bytes so far
	n -= 4

	want := 0
	daddr := buf[4:]

	// Now connecting dest addr & port
	switch buf[3] {
	case 0x1: // ipv4 address
		want = 4
	case 0x3: // fqdn; first octet is length
		want = int(buf[4])
		daddr = buf[5:]
		if want == 0 {
			log.Warn("socksv5 domain name length is zero")
			err = errMsgTooSmall
			return
		}

	case 0x4: // ipv6 addr
		want = 16

	default:
		log.Warn("unknown socks addr type %#x", buf[3])
		err = errUnsupportedAddr
		return
	}

	// we must have enough bytes for addr:port
	if n < (want + 2) {
		log.Warn("insufficient socks method info (exp at least %d, saw %d)", want+2, n)
		err = errMsgTooSmall
		return
	}

	port := daddr[want:]
	switch buf[3] {
	case 0x1:
		addr = fmt.Sprintf("%d.%d.%d.%d", daddr[0], daddr[1], daddr[2], daddr[3])
	case 0x3:
		var s strings.Builder
		for i := 0; i < want; i++ {
			s.WriteByte(daddr[i])
		}
		addr = s.String()
	case 0x4:
		var s strings.Builder
		s.WriteString(fmt.Sprintf("[%02x", daddr[0]))
		for i := 1; i < want; i++ {
			s.WriteString(fmt.Sprintf(":%02x", daddr[i]))
		}
		s.WriteRune(']')
		addr = s.String()
	}

	iport := (uint16(port[0]) << 8) + uint16(port[1])
	addr = fmt.Sprintf("%s:%d", addr, iport)
	err = nil

	log.Debug("socks: connecting to %s/%s", network, addr)
	return
}

func (p *Server) getBuf() []byte {
	b := p.pool.Get()
	return b.([]byte)
}

func (p *Server) putBuf(b []byte) {
	// resize before putting it back
	b = b[:cap(b)]
	p.pool.Put(b)
}

func (p *Server) cancellableCopy(d, s Conn, buf []byte, ctx context.Context, log *L.Logger) (x, y int) {
	rto := time.Duration(p.Timeout.Read) * time.Second
	wto := time.Duration(p.Timeout.Write) * time.Second
	done := ctx.Done()
	for {
		s.SetReadDeadline(time.Now().Add(rto))
		nr, err := s.Read(buf)
		select {
		case <-done:
			return
		default:
		}

		if err != nil {
			if err != io.EOF && err != context.Canceled && !isReset(err) {
				log.Debug("%s: nr %d, read err %s", s.LocalAddr().String(), nr, err)
				return
			}
		}

		switch {
		case nr == 0:
			log.Debug("EOF")
			return

		case nr > 0:
			d.SetWriteDeadline(time.Now().Add(wto))
			x += nr
			nw, err := WriteAll(d, buf[:nr])
			select {
			case <-done:
				return
			default:
			}

			if err != nil {
				log.Debug("%s: Write Err %s", d.RemoteAddr().String(), err)
				return
			}
			if nw != nr {
				return
			}
			y += nw
		}
	}
}

// Accept() new socket connections from the listener
func (p *TCPServer) Accept() (net.Conn, error) {
	ln := p.TCPListener
	for {
		ln.SetDeadline(time.Now().Add(2 * time.Second))

		nc, err := ln.Accept()

		select {
		case <-p.ctx.Done():
			if err == nil {
				nc.Close()
			}
			return nil, errShutdown

		default:
		}

		if err != nil {
			if ne, ok := err.(net.Error); ok {
				if ne.Timeout() || ne.Temporary() {
					continue
				}
			}
			return nil, err
		}

		there := nc.RemoteAddr()

		// First enforce a global ratelimit
		if !p.rl.Allow() {
			p.log.Debug("global ratelimit reached: %s", there)
			nc.Close()
			continue
		}

		// Then a per-host ratelimit
		if !p.rl.AllowHost(there) {
			p.log.Debug("per-host ratelimit reached: %s", there)
			nc.Close()
			continue
		}

		if !AclOK(p.ListenConf, there) {
			p.log.Debug("ACL failure: %s", there)
			nc.Close()
			continue
		}

		p.log.Debug("Accepted new connection from %s", there)
		return nc, nil
	}
}

func (s *Server) getSNIHandler(dir string, log *L.Logger) func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	conf := s.conf
	dir = conf.Path(dir)
	if !isdir(dir) {
		die("%s: SNI %s is not a directory?", s.Addr, dir)
	}

	fp := func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		crt := path.Join(dir, h.ServerName, ".crt")
		key := path.Join(dir, h.ServerName, ".key")

		cert, err := conf.loadCertKey(crt, key)
		if err != nil {
			log.Warn("%s", err)
			return nil, fmt.Errorf("%s: %w", h.ServerName, err)
		}

		log.Debug("SNI: %s -> {%s, %s}", h.ServerName, crt, key)
		return cert, nil
	}

	return fp
}

// resolve 'addr' into a net.Addr
func resolveAddr(addr string) net.Addr {
	if ip := net.ParseIP(addr); ip != nil {
		return &net.IPAddr{IP: ip}
	}

	a, err := net.LookupIP(addr)
	if err == nil {
		return &net.IPAddr{IP: a[0]}
	}
	// XXX Gah
	return nil
}

var (
	errNoCert    = errors.New("SNI: no cert/key for name")
	errNoCACerts = errors.New("TLS: no CA certs found")
	errShutdown  = errors.New("server shutdown")

	// socks errors
	errMsgTooSmall         = errors.New("socks: message too small")
	errUnsupportedMethod   = errors.New("socks: unsupported method")
	errUnsupportedAddr     = errors.New("socks: unsupported address")
	errUnsupportedSocksVer = errors.New("socks: unsupported version")
)

// vim: noexpandtab:ts=8:sw=8:tw=88:
