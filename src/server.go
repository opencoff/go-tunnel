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

	"github.com/quic-go/quic-go"
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

// Handle the relay from 'conn' to the peer and back.
// This sets up the peer connection before the relay.
// This is called by tcpsrv.go and quicsrv.go in their
// respective handler-loops.
func (p *Server) handleConn(conn, peer Conn, ctx context.Context, log *L.Logger) {

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
	peer.Close()

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
