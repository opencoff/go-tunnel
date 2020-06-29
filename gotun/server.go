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
	"errors"
	"fmt"
	"io"
	"net"
	"path"
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

	rl *ratelimit.RateLimiter

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
	rl, err := ratelimit.New(lc.Ratelimit.Global, lc.Ratelimit.PerHost, 10000)
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
		pool: &sync.Pool{
			New: func() interface{} { return make([]byte, BufSize) },
		},
		rl: rl,
	}

	if t := lc.Tls; t != nil && len(t.Sni) > 0 {
		s.tls.GetCertificate = s.getSNIHandler(t.Sni, log)
	}

	if lc.Connect.Quic {
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

	la, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		die("Can't resolve %s: %s", addr, err)
	}

	ln, err := net.ListenUDP("udp", la)
	if err != nil {
		die("Can't listen on %s: %s", addr, err)
	}

	q, err := quic.Listen(ln, s.tls, &quic.Config{})
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

		p.log.Info("Starting TCP server ..")
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
	for {
		conn, err := p.Accept()
		select {
		case <-p.ctx.Done():
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
	for {
		p.rl.Wait(p.ctx)
		sess, err := p.Accept(p.ctx)
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

		// wait for per-host ratelimiter
		p.rl.WaitHost(p.ctx, sess.RemoteAddr())

		// we also accept the corresponding stream
		conn, err := sess.AcceptStream(p.ctx)
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
		peer := qc.RemoteAddr()
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

	peer, err := p.dial.Dial(p.dialnet, p.Connect.Addr, conn, ctx)
	if err != nil {
		log.Warn("can't connect to %s: %s", p.Connect.Addr, err)
		return
	}

	defer peer.Close()

	// we grab the printable info before the socket is closed
	lhs_theirs := conn.RemoteAddr().String()
	inbound := fmt.Sprintf("%s-%s", lhs_theirs, conn.LocalAddr().String())
	rhs_theirs := peer.RemoteAddr().String()
	outbound := fmt.Sprintf("%s-%s", peer.LocalAddr().String(), rhs_theirs)

	// we really need to log this in the parent logger
	p.log.Debug("LHS %s, RHS %s", inbound, outbound)

	// create a child logger anchored to the remote-addr
	log = log.New(rhs_theirs, 0)

	var wg sync.WaitGroup

	b0 := p.getBuf()
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

	log.Info("%s: rd %d, wr %d; %s: rd %d, wr %d", lhs_theirs, r1, w0, rhs_theirs, r0, w1)
}

func (p *Server) getBuf() []byte {
	b := p.pool.Get()
	return b.([]byte)
}

func (p *Server) putBuf(b []byte) {
	p.pool.Put(b)
}

// interruptible copy
func (p *Server) cancellableCopy(d, s Conn, buf []byte, ctx context.Context, log *L.Logger) (r, w int) {

	ch := make(chan bool)
	go func() {
		r, w = p.copyBuf(d, s, buf, log)
		close(ch)
	}()

	select {
	case <-ch:

	case <-ctx.Done():
		// This forces both copy go-routines to end the for{} loops.
		log.Debug("SHUTDOWN: Force closing %s and %s",
			d.RemoteAddr().String(), s.LocalAddr().String())
		d.Close()
		s.Close()
	}

	return
}

// copy from 's' to 'd' using 'buf'
func (p *Server) copyBuf(d, s Conn, buf []byte, log *L.Logger) (x, y int) {
	rto := time.Duration(p.Timeout.Read) * time.Second
	wto := time.Duration(p.Timeout.Write) * time.Second
	for {
		s.SetReadDeadline(time.Now().Add(rto))
		nr, err := s.Read(buf)
		if err != nil {
			if err != io.EOF && err != context.Canceled && !isReset(err) {
				log.Debug("%s: nr %d, read err %s", s.LocalAddr().String(), nr, err)
				return
			}
		}

		if nr > 0 {
			d.SetWriteDeadline(time.Now().Add(wto))
			x += nr
			nw, err := d.Write(buf[:nr])
			if err != nil {
				log.Debug("%s: Write Err %s", d.RemoteAddr().String(), err)
				return
			}
			if nw != nr {
				return
			}
			y += nw
		}
		if err != nil {
			log.Debug("%s: read error: %s", s.RemoteAddr().String(), err)
			return
		}
		if nr == 0 {
			log.Debug("%s: EOF", s.RemoteAddr().String())
			return
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

		// First enforce a global ratelimit
		if !p.rl.Allow() {
			p.log.Debug("global ratelimit reached: %s", nc.RemoteAddr().String())
			nc.Close()
			continue
		}

		// Then a per-host ratelimit
		if !p.rl.AllowHost(nc.RemoteAddr()) {
			p.log.Debug("per-host ratelimit reached: %s", nc.RemoteAddr().String())
			nc.Close()
			continue
		}

		if !AclOK(p.ListenConf, nc) {
			p.log.Debug("ACL failure: %s", nc.RemoteAddr().String())
			nc.Close()
			continue
		}

		p.log.Debug("Accepted new connection from %s", nc.RemoteAddr().String())
		return nc, nil
	}
}

func (s *Server) getSNIHandler(dir string, log *L.Logger) func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	conf := s.conf
	dir = conf.Path(dir)
	if !isdir(dir) {
		die("%s: certdir %s is not a directory?", s.Addr, dir)
	}

	fp := func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		crt := path.Join(dir, h.ServerName, ".crt")
		key := path.Join(dir, h.ServerName, ".key")

		if err := conf.IsFileSafe(crt); err != nil {
			log.Warn("insecure perms on %s, skipping ..", crt)
			return nil, fmt.Errorf("%s: %w", crt, errNoCert)
		}

		if err := conf.IsFileSafe(key); err != nil {
			log.Warn("insecure perms on %s, skipping ..", key)
			return nil, fmt.Errorf("%s: %w", key, errNoCert)
		}

		// XXX Toctou -- ideally we want to send opened file handles
		cert, err := tls.LoadX509KeyPair(crt, key)
		if err != nil {
			return nil, err
		}

		log.Debug("SNI: %s -> {%s, %s}", h.ServerName, crt, key)
		return &cert, nil
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
)

// vim: noexpandtab:ts=8:sw=8:tw=88:
