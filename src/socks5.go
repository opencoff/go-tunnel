// socks5.go - simple socks5 server side parsing functions
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"net/netip"
)



func (s *Server) doGreeting(fd Conn, buf []byte, log *L.Logger) (error) {
	// XXX we assume a max of (256 + 2 = ) 258 bytes for the initial greeting

	n, err := fd.Read(buf[:258])
	if err != nil {
		count("rerr-socks-ver", 1)
		log.Debug("can't read socks version: %s", err)
		return err
	}

	if n < 2 {
		count("too-small", 1)
		log.Debug("insufficient greeting bytes (saw %d, want at least 2)", n)
		return errMsgTooSmall
	}

	if buf[0] != 0x05 {
		count("bad-socks-ver", 1)
		log.Debug("bad socks ver %#x in greeting", buf[0])
		return errUnsupportedSocksVer
	}

	// In our case, we don't support any auth methods; all plaintext auth is broken anyway.
	// So, we implicitly say "yay"
	buf[1] = 0x0
	_, err = writeAll(fd, buf[:2])
	if err != nil {
		count("werr-greeting",1)
		log.Debug("can't complete greeting: %s", err)
	}
	return err
}

type AddrType uint8
const (
	A_INVALID AddrType = 0x0
	A_IPV4    AddrType = 0x01
	A_HOST    AddrType = 0x03
	A_IPV6    AddrType = 0x04
)

type Proto uint8
const (
	P_TCP  Proto = 0x01
	P_UDP  Proto = 0x03
)

type AddrSpec struct {
	Typ  AddrType
	Proto Proto
	AddrPort netip.AddrPort
	HostPort string
}

func (s *Server) doClientConn(fd Conn, log *L.Logger) (a AddrSpec, err error) {
	buf := s.getBuf()
	defer s.putBuf(buf)

	// XXX We read all available bytes
	n, err := fd.Read(buf)
	if err != nil {
		count("rerr-client-conn", 1)
		log.Debug("can't read client conn: %s", err)
		return
	}

	if n < 10 {
		count("too-small", 1)
		log.Debug("insufficient client-conn bytes (want 10, saw %d)", n)
		return
	}

	if buf[0] != 0x05 {
		count("bad-socks-ver", 1)
		log.Debug("bad socks ver %#x in client conn", buf[0])
		err = errUnsupportedSocksVer
		return
	}

	switch buf[1] {
	case P_TCP:
		a.Proto = P_TCP
	case P_UDP:
		a.Proto = P_UDP
	default:
		count("bad-cmd", 1)
		log.Debug("Unsupported client command %#x", buf[1])
		err = errUnsupportedMethod
		return
	}

	aparse := func(b []byte) (netip.Addr, error) {
		x, err := netip.ParseAddr(string(b))
		if err != nil {
			count("bad-addr", 1)
			log.Debug("can't parse IP addr: %s", err)
		}
		return x, err
	}

	toPort := func(b []byte) uint16 {
		return uint16(b[0] << 8) + uint16(b[1])
	}

	// Now we decode the address
	abuf := buf[3:]
	want := 0

	switch abuf[0] {
	case A_IPV4:
		want = 4
		daddr := buf[4:]

	case A_HOST:
		want = int(abuf[1])
		daddr := abuf[2:]

	case A_IPV6:
		want = 16
		daddr := buf[4:]

	default:
		count("bad-addrtype", 1)
		log.Debug("unknown client addrtype %#x", abuf[0])
		err = errUnsupportedAddr
		return
	}

	if len(abuf) < (want + 2 + 1) {
		count("too-small", 1)
		log.Debug("insufficient client-conn-addr bytes; want %d, have %d", (want+2+1), len(abuf))
		err = errMsgTooSmall
		return
	}

	port := toPort(daddr[want:])
	switch abuf[0] {
	case A_IPV4:
		addr := fmt.Sprintf("%d.%d.%d.%d:%d", daddr[0], daddr[1], daddr[2], daddr[3], port)
		a.Typ = A_IPV4
		a.AddrPort, err = netip.ParseAddrPort(addr)
		if err != nil {
			count("bad-addr", 1)
			log.Debug("bad IPv4 client conn addr: %s", err)
			return
		}

	case A_HOST:
		var s strings.Builder
		for i := 0; i < want; i++ {
			s.WriteByte(daddr[i])
		}
		addr := s.String()
		a.Typ = A_HOST
		a.HostPort = fmt.Sprintf("%s:%d", addr, port)

	case A_IPV6:
		var s strings.Builder
		s.WriteString(fmt.Sprintf("[%02x", daddr[0]))
		for i := 1; i < want; i++ {
			s.WriteString(fmt.Sprintf(":%02x", daddr[i]))
		}
		s.WriteRune(']')
		addr := s.String()
		a.AddrPort, err = netip.ParseAddrPort(fmt.Sprintf("%s:%d", addr, port))
		if err != nil {
			count("bad-addr", 1)
			log.Debug("bad IPv6 client conn addr: %s", err)
			return
		}
	}

	return
}

func (s *Server) doClientResp(fd Conn, log *L.Logger, a netip.AddrPort, err error) error {
	buf := s.getBuf()
	defer s.putBuf(buf)

	buf[0] = 0x05
	buf[2] = 0x0

	// failure response
	if err != nil {
		buf[1] = 0x04	// generic host unreach error
		_, err = WriteAll(fd, buf[:3])
		if err != nil {
			count("werr-client-resp", 1)
			log.Debug("can't write client err response: %s", err)
			return err
		}

		return nil
	}

	// success response
	laddr := a.Addr()
	lport := a.Port()

	var bytes []byte
	if laddr.Is6() {
		buf[3] = A_IPV6
		bytes = laddr.As16()[:]
	} else {
		buf[3] = A_IPV4
		bytes = laddr.As4()[:]
	}

	for i, x := range bytes {
		buf[4+i] = x
	}

	pbuf := buf[4+len(bytes):]
	pbuf[0] = uint8(0xff & (lport >> 8))
	pbuf[1] = uint8(lport & 0xff)

	_, err = WriteAll(fd, buf[:4+len(abytes)+2])
	if err != nil {
		count("werr-client-resp", 1)
		log.Debug("can't write client response: %s", err)
		return err
	}

	return nil
}


// UDP listener for socks5
// one instance per udp-associate request
type UDPListener struct {

	// listening socket
	fd  *net.UDPConn

	// rate limiter
	rl  *ratelimit.Limiter

	// my peer - already connected
	// either a quic stream or a TCP/TLS socket
	peer Conn

	log *L.Logger

	ctx context.Context
	cancel context.CancelFunc
	s *Server
}


func (s *Server) NewUDPListener(ctx context.Context, peer Conn, a netip.AddrPort) (*UDPListener, error) {
	var net string = "udp"
	if a.Addr().Is6() {
		net = "udp6"
	}

	fd, err := net.ListenUDP(net, a.String())
	if err != nil {
		count("udp-listen-fail", 1)
		log.Warn("can't listen on %s: %s", a.String(), err)
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	u := &UDPListener{
		fd:   fd,
		peer: peer,
		log:  s.log.New("UDP %s-%s", a.String(), peer.String()),
		ctx:  ctx,
		cancel: cancel,
	}

	s.wg.Add(1)
	go u.serveUDP()
	return u, nil
}

func (u *UDPListener) Stop() {
	u.cancel()
	u.fd.Close()

}


func (u *UDPListener) serveUDP() {
	s := u.s
	defer func() {
		s.wg.Done()
		u.fd.Close()
	}()

	done := u.ctx.Done()
	buf := u.s.getBuf()
	ctx := u.ctx
	log := u.log
	for {
		err := u.rl.Wait(ctx)
		if errors.Is(err, context.Canceled) {
			return
		}

		n, a, err := u.fd.ReadFrom(buf)
		select {
		case <- done:
			return
		default:
		}

		if err != nil {
			count("rerr-udp", 1)
			log.Debug("read error: %s", err)
			errs += 1
			if errs >= 10 {
				log.Warn("too many consec read errors; bailing..")
				return
			}
			continue
		}
		errs = 0

		// per host ratelimiting
		u.rl.WaitHost(ctx, a)

		if !AclOK(s.ListenConf, a) {
			count("acl-deny", 1)
			log.Debug("%s: ACL denied", a.String())
			continue
		}

		// parse UDP socks framing

		// handle fragments
		// handle timeouts for fragment handling

		// finally forward the data
	}
}


