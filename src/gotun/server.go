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
	"io"
	"io/ioutil"
	"net"
	"path"
	"sync"
	"time"

	L "github.com/opencoff/go-logger"
	"github.com/opencoff/go-ratelimit"
)

// XXX These should be in a config file
const dialerTimeout = 3        // seconds
const connectionKeepAlive = 20 // seconds
const readTimeout = 20         // seconds
const writeTimeout = 60        // seconds; 3x read timeout. Enough time?

type TCPServer struct {
	*net.TCPListener

	// listen address
	*ListenConf

	// optional - will be set only if listening via TLS
	tls *tls.Config

	clientTls *tls.Config

	// Dialer - will be either a plain dialer or TLS dialer
	dial *net.Dialer

	ctx    context.Context
	cancel context.CancelFunc

	pool *sync.Pool

	wg   sync.WaitGroup

	grl *ratelimit.Ratelimiter
	prl *ratelimit.PerIPRatelimiter

	// logger
	log *L.Logger
}

func NewTCPServer(lc *ListenConf, log *L.Logger) Proxy {
	addr := lc.Addr
	la, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		die("Can't resolve %s: %s", addr, err)
	}

	ln, err := net.ListenTCP("tcp", la)
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
			Timeout:   dialerTimeout,
			LocalAddr: resolveAddr(lc.Connect.Bind),
			KeepAlive: connectionKeepAlive,
		},
		grl:  rl,
		prl:  pl,
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
	p.TCPListener.Close()	// forcibly
	p.wg.Wait()
	p.log.Info("TCP server shutdown")
}

func (p *TCPServer) serve() {
	// XXX n consecutive errors and kill the server?
	for {
		var quit bool

		conn, err := p.Accept()
		select {
		case <- p.ctx.Done():
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

		ctx := context.WithValue(p.ctx, "client", conn.RemoteAddr().String())

		p.wg.Add(1)
		go p.handleConn(conn, ctx)
	}
}

func (p *TCPServer) handleConn(conn net.Conn, ctx context.Context) {
	defer p.wg.Done()

	peer, err := p.dial.DialContext(ctx, "tcp", p.Connect.Addr)
	if err != nil {
		p.log.Info("can't connect to %s: %s", p.Connect.Addr, err)
		return
	}

	if p.tls != nil {
		conn = tls.Server(conn, p.tls)
	}

	if p.clientTls != nil {
		peer = tls.Client(conn, p.clientTls)
	}

	var wg sync.WaitGroup

	b0 := p.getBuf()
	b1 := p.getBuf()

	wg.Add(2)
	go func() {
		defer wg.Done()
		cancellableCopy(conn, peer, ctx, b0)
	}()

	go func() {
		defer wg.Done()
		cancellableCopy(peer, conn, ctx, b1)
	}()

	ch := make(chan bool)
	go func() {
		wg.Wait()
		close(ch)
	}()

	select {
	case <-ctx.Done():
		<-ch

	case <-ch:
	}

	p.putBuf(b0)
	p.putBuf(b1)

	conn.Close()
	peer.Close()
}

func (p *TCPServer) getBuf() []byte {
	b := p.pool.Get()
	return b.([]byte)
}

func (p *TCPServer) putBuf(b []byte) {
	p.pool.Put(b)
}

// interruptible copy
func cancellableCopy(d, s net.Conn, ctx context.Context, buf []byte) {
	ch := make(chan bool)
	go func() {
		copyBuf(d, s, buf)
		close(ch)
	}()

	for {
		select {
		case <-ch:
			return
		case <-ctx.Done():
			// This forces both copy go-routines to end the for{} loops.
			d.Close()
			s.Close()
		}
	}
}

// copy from 's' to 'd' using 'buf'
func copyBuf(d, s net.Conn, buf []byte) {
	for {
		nr, err := s.Read(buf)
		if err != nil && err != io.EOF && err != context.Canceled && !isReset(err) {
			return
		}
		if nr > 0 {
			nw, err := d.Write(buf[:nr])
			if err != nil {
				return
			}
			if nw != nr {
				return
			}
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
			return &cert, nil
		}

	} else {
		cert, err := tls.LoadX509KeyPair(t.Cert, t.Key)
		if err != nil {
			die("%s: can't load server cert %s/%s: %s", lc.Addr, t.Cert, t.Key, err)
		}

		cfg.Certificates = []tls.Certificate{cert}
	}

	needCA := true
	switch t.ClientAuth {
	case "required":
		cfg.ClientAuth = tls.RequireAndVerifyClientCert

	case "optional":
		cfg.ClientAuth = tls.VerifyClientCertIfGiven

	default:
		needCA = false
		cfg.ClientAuth = tls.NoClientCert
	}

	if needCA {
		var err error

		cfg.ClientCAs, err = ReadCA(t.ClientCA)
		if err != nil {
			die("%s: can't read client CA in %s: %s", lc.Addr, t.ClientCA, err)
		}
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

	cfg.RootCAs, err = ReadCA(t.Ca)
	if err != nil {
		die("%s: can't load TLS client CA from %s: %s", lc.Addr, t.Ca, err)
	}

	if len(t.Cert) > 0 && len(t.Key) > 0 {
		cert, err := tls.LoadX509KeyPair(t.Cert, t.Key)
		if err != nil {
			die("%s: can't load TLS client cert/key %s/%s: %s", lc.Addr, t.Cert, t.Key, err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	if len(cfg.ServerName) == 0 {
		log.Warn("TLS Client towards %s has no server-name; UNABLE TO VERIFY server presented cert", c.Addr)
		cfg.InsecureSkipVerify = true
	}

	return cfg
}

func ReadCA(nm string) (*x509.CertPool, error) {
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
		p.AppendCertsFromPEM(pem)
	}

	if s := p.Subjects(); len(s) == 0 {
		return nil, errNoCACerts
	}

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
	return &net.IPAddr{IP: net.IPv4zero}
}

var (
	errNoCert    = errors.New("SNI: no cert/key for name")
	errNoCACerts = errors.New("TLS: no CA certs found")
	errShutdown  = errors.New("server shutdown")
)

// vim: noexpandtab:ts=8:sw=8:tw=88:
