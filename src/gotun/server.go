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
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"path"
	"sync"
	"time"

	L "github.com/opencoff/go-logger"
	"github.com/opencoff/go-ratelimit"
)

// Encapsulates info needed to be a plain listener or a TLS listener.
// And has a dialer to connect to a plain or TLS endpoint
type TCPServer struct {
	*net.TCPListener

	// listen address
	*ListenConf

	// optional - will be set only if listening via TLS
	tls *tls.Config

	// optional - will be set only if connecting to a TLS peer
	clientTls *tls.Config

	dial *net.Dialer

	// for seamless shutdown
	ctx    context.Context
	cancel context.CancelFunc

	pool *sync.Pool

	activeConn map[string]*relay
	mu         sync.Mutex

	wg sync.WaitGroup

	grl *ratelimit.Ratelimiter
	prl *ratelimit.PerIPRatelimiter

	log *L.Logger
}

// relay context
type relay struct {
	ctx context.Context

	lconn net.Conn
	rconn net.Conn

	lhs string
	rhs string
}

// Make a new instance of a TCPServer and return it
// This function exits on any configuration parsing error.
func NewTCPServer(lc *ListenConf, log *L.Logger) Proxy {
	addr := lc.Addr
	la, err := net.ResolveTCPAddr("tcp4", addr)
	if err != nil {
		die("Can't resolve %s: %s", addr, err)
	}

	ln, err := net.ListenTCP("tcp4", la)
	if err != nil {
		die("Can't listen on %s: %s", addr, err)
	}

	// create a sub-logger with the listener's prefix.
	log = log.New(ln.Addr().String(), 0)

	// Conf file specifies ratelimit as N conns/sec
	rl, err := ratelimit.New(lc.Ratelimit.Global, 1)
	if err != nil {
		die("%s: Can't create global ratelimiter: %s", addr, err)
	}

	pl, err := ratelimit.NewPerIPRatelimiter(lc.Ratelimit.PerHost, 1)
	if err != nil {
		die("%s: Can't create per-host ratelimiter: %s", addr, err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &TCPServer{
		TCPListener: ln,
		ListenConf:  lc,
		tls:         parseTLSServerConf(lc, log),
		clientTls:   parseTLSClientConf(lc, log),
		log:         log,
		ctx:         ctx,
		cancel:      cancel,
		pool: &sync.Pool{
			New: func() interface{} { return make([]byte, 65536) },
		},
		dial: &net.Dialer{
			Timeout:   time.Duration(lc.Timeout.Connect) * time.Second,
			LocalAddr: resolveAddr(lc.Connect.Bind),
			KeepAlive: 25 * time.Second,
		},
		grl: rl,
		prl: pl,
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

		p.serve()
	}()
}

// Stop server
func (p *TCPServer) Stop() {
	p.cancel()
	p.TCPListener.Close() // forcibly
	p.wg.Wait()
	p.log.Info("TCP server shutdown")
}

func (p *TCPServer) serve() {
	// XXX n consecutive errors and kill the server?
	for {
		var quit bool

		conn, err := p.Accept()
		select {
		case <-p.ctx.Done():
			quit = true
		default:
			quit = false
		}

		if quit {
			break
		}

		if err != nil {
			// Try again?
			time.Sleep(2 * time.Second)
			continue
		}

		src := conn.RemoteAddr().String()
		ctx := context.WithValue(p.ctx, "client", src)

		p.wg.Add(1)
		go p.handleConn(conn, ctx)
	}
}

// handle the relay from 'conn' to the peer and back.
// this sets up the peer connection before the relay
func (p *TCPServer) handleConn(conn net.Conn, ctx context.Context) {
	src := conn.RemoteAddr().String()
	r := &relay{
		ctx:   ctx,
		lconn: conn,
		lhs:   fmt.Sprintf("%s-%s", src, conn.LocalAddr().String()),
	}
	p.mu.Lock()
	p.activeConn[src] = r
	p.mu.Unlock()

	defer func() {
		p.wg.Done()

		p.mu.Lock()
		delete(p.activeConn, src)
		p.mu.Unlock()
	}()

	peer, err := p.dial.DialContext(ctx, "tcp4", p.Connect.Addr)
	if err != nil {
		p.log.Info("can't connect to %s: %s", p.Connect.Addr, err)
		conn.Close()
		return
	}

	r.rhs = fmt.Sprintf("%s-%s", peer.LocalAddr().String(), peer.RemoteAddr().String())
	r.rconn = peer

	lhs := conn.RemoteAddr().String()
	rhs_theirs := peer.RemoteAddr().String()

	p.log.Debug("LHS %s, RHS %s", r.lhs, r.rhs)
	if p.tls != nil {
		econn := tls.Server(conn, p.tls)
		err := econn.Handshake()
		if err != nil {
			p.log.Warn("can't establish TLS with %s: %s", conn.RemoteAddr().String(), err)
			conn.Close()
			peer.Close()
			return
		}

		st := econn.ConnectionState()
		p.log.Debug("tls server handshake complete; Version %x, Cipher %x", st.Version, st.CipherSuite)
		conn = econn
	}

	if p.clientTls != nil {
		econn := tls.Client(peer, p.clientTls)
		err := econn.Handshake()
		if err != nil {
			p.log.Warn("can't establish TLS with %s: %s", peer.RemoteAddr().String(), err)
			conn.Close()
			peer.Close()
			return
		}
		st := econn.ConnectionState()
		p.log.Debug("tls client handshake complete; Version %x, Cipher %x", st.Version, st.CipherSuite)
		peer = econn
	}

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
		r0, w0 = p.cancellableCopy(conn, peer, ctx, b0)
		conn.Close()
		peer.Close()
	}()

	go func() {
		defer wg.Done()
		r1, w1 = p.cancellableCopy(peer, conn, ctx, b1)
		conn.Close()
		peer.Close()
	}()

	select {
	case <-ctx.Done():
		<-ch

	case <-ch:
	}

	p.putBuf(b0)
	p.putBuf(b1)

	p.log.Info("%s: rd %d, wr %d; %s: rd %d, wr %d", lhs, r1, w0, rhs_theirs, r0, w1)
}

func (p *TCPServer) getBuf() []byte {
	b := p.pool.Get()
	return b.([]byte)
}

func (p *TCPServer) putBuf(b []byte) {
	p.pool.Put(b)
}

// interruptible copy
func (p *TCPServer) cancellableCopy(d, s net.Conn, ctx context.Context, buf []byte) (r, w int) {

	ch := make(chan bool)
	go func() {
		r, w = p.copyBuf(d, s, buf)
		close(ch)
	}()

	for {
		select {
		case <-ch:
			return

		case <-ctx.Done():
			p.log.Debug("cancellable copy: FORCE CANCEL")
			// This forces both copy go-routines to end the for{} loops.
			d.Close()
			s.Close()
		}
	}
}

// copy from 's' to 'd' using 'buf'
func (p *TCPServer) copyBuf(d, s net.Conn, buf []byte) (x, y int) {
	rto := time.Duration(p.Timeout.Read) * time.Second
	wto := time.Duration(p.Timeout.Write) * time.Second
	for {
		s.SetReadDeadline(time.Now().Add(rto))
		nr, err := s.Read(buf)
		if err != nil && err != io.EOF && err != context.Canceled && !isReset(err) {
			return
		}
		if nr > 0 {
			s.SetWriteDeadline(time.Now().Add(wto))
			x += nr
			nw, err := d.Write(buf[:nr])
			if err != nil {
				return
			}
			if nw != nr {
				return
			}
			y += nw
		}
		if err != nil || nr == 0 {
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
		if p.grl.Limit() {
			p.log.Debug("global ratelimit reached: %s", nc.RemoteAddr().String())
			nc.Close()
			continue
		}

		// Then a per-host ratelimit
		if p.prl.Limit(nc.RemoteAddr()) {
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

func parseTLSServerConf(lc *ListenConf, log *L.Logger) *tls.Config {
	t := lc.Tls
	if t == nil {
		return nil
	}

	cfg := &tls.Config{
		SessionTicketsDisabled: true,
	}

	if t.Sni {
		if !isdir(t.Certdir) {
			die("%s: certdir %s is not a directory?", lc.Addr, t.Certdir)
		}

		cfg.GetCertificate = func(c *tls.ClientHelloInfo) (*tls.Certificate, error) {
			crt := path.Join(t.Certdir, c.ServerName, ".crt")
			key := path.Join(t.Certdir, c.ServerName, ".key")

			if !isfile(crt) && !isfile(key) {
				log.Warn("can't find cert/key for %s", c.ServerName)
				return nil, errNoCert
			}

			cert, err := tls.LoadX509KeyPair(crt, key)
			if err != nil {
				return nil, err
			}

			log.Debug("SNI: %s -> {%s, %s}", c.ServerName, crt, key)
			return &cert, nil
		}

	} else {
		cert, err := tls.LoadX509KeyPair(t.Cert, t.Key)
		if err != nil {
			die("%s: can't load server cert {%s, %s}: %s", lc.Addr, t.Cert, t.Key, err)
		}

		log.Debug("Loading {%s, %s}", t.Cert, t.Key)
		cfg.Certificates = []tls.Certificate{cert}
	}

	needCA := true
	switch t.ClientCert {
	case "required":
		cfg.ClientAuth = tls.RequireAndVerifyClientCert

	case "optional":
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
		// XXX We may have to write a VerifyPeerCertificate() callback to verify

	default:
		needCA = false
		cfg.ClientAuth = tls.NoClientCert
	}

	if needCA {
		var err error

		cfg.ClientCAs, err = ReadCA(t.ClientCA, log)
		if err != nil {
			die("%s: can't read client CA in %s: %s", lc.Addr, t.ClientCA, err)
		}
		log.Debug("using %s for verifying client certs", t.ClientCA)
	}

	return cfg
}

func parseTLSClientConf(lc *ListenConf, log *L.Logger) *tls.Config {
	c := &lc.Connect
	t := c.Tls
	if t == nil {
		return nil
	}

	cfg := &tls.Config{
		ServerName:             t.Server,
		SessionTicketsDisabled: true,
	}

	var err error

	cfg.RootCAs, err = ReadCA(t.Ca, log)
	if err != nil {
		die("%s: can't load TLS client CA from %s: %s", lc.Addr, t.Ca, err)
	}

	if len(t.Cert) > 0 && len(t.Key) > 0 {
		cert, err := tls.LoadX509KeyPair(t.Cert, t.Key)
		if err != nil {
			die("%s: can't load TLS client cert/key {%s, %s}: %s", lc.Addr, t.Cert, t.Key, err)
		}
		log.Debug("loaded client cert %s/%s", t.Cert, t.Key)
		cfg.Certificates = []tls.Certificate{cert}
	}

	if len(cfg.ServerName) == 0 {
		log.Warn("TLS Client towards %s has no server-name; UNABLE TO VERIFY server presented cert", c.Addr)
		cfg.InsecureSkipVerify = true
	}

	return cfg
}

func ReadCA(nm string, log *L.Logger) (*x509.CertPool, error) {
	var files []string

	if isdir(nm) {
		filei, _, _, err := readdir(nm)
		if err != nil {
			return nil, err
		}
		if len(filei) > 0 {
			files = make([]string, len(filei))
			for i, fi := range filei {
				files[i] = fi.Name()
			}
		}
		log.Debug("Found %d files in CA dir %s", len(files), nm)
	} else {
		files = []string{nm}
	}

	p := x509.NewCertPool()
	for _, nm := range files {
		var pem []byte
		var err error
		pem, err = ioutil.ReadFile(nm)
		if err != nil {
			return nil, err
		}
		log.Debug("Added CA bundle from %s ..", nm)
		p.AppendCertsFromPEM(pem)
	}

	if s := p.Subjects(); len(s) == 0 {
		return nil, errNoCACerts
	}

	log.Debug("Total %d individual CA certificates loaded", len(p.Subjects()))

	return p, nil
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
