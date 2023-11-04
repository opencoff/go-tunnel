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
	L "github.com/opencoff/go-logger"
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

	// Now we decode the address
	_, err = a.parseAddrSpec(buf[3:], log)
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

	// the IP addr of client that sent the original udp-associate
	from netip.Addr

	log *L.Logger

	ctx context.Context
	cancel context.CancelFunc

	// the parent server which handled the initial udp-associate
	s *Server

	// A single client could send from multiple source ports. We will setup
	// a new peer conn for every such unique tuple.
	clients map[netip.AddrPort]*udprelay
}

type udprelay struct {
	// established conn with peer
	peer Conn

	// fragment handler
	f   fragmap
}


// Create a new UDP listener for a client with IP Addr 'from':
// - listen on 'a'
// - forward to 'peer'
func (s *Server) NewUDPListener(ctx context.Context, from netip.Addr, a netip.AddrPort) (*UDPListener, error) {
	var net string = "udp"
	if a.Addr().Is6() {
		net = "udp6"
	}

	/*
	udpaddr := net.UDPAddr{
		IP: a.Addr.AsSlice(),
		Port: int(a.Port()),
	}
	*/

	fd, err := net.ListenUDP(net, &a)
	if err != nil {
		count("udp-listen-fail", 1)
		log.Warn("can't listen on %s: %s", a.String(), err)
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	u := &UDPListener{
		fd:   fd,
		log:  s.log.New("UDP %s", a.String()),
		ctx:  ctx,
		from: from,
		cancel: cancel,
		server: s,
		clients: make(map[netip.AddrPort]*udprelay),
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
	buf := s.getBuf()
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

		// Ignore zero sized datagrams
		if n == 0 {
			count("zero-sized-udp", 1)
			continue
		}

		// Make sure this is the same host that initiated the udp-associate
		// (primitive DoS mitigation)
		ax := a.AddrPort().Addr()
		if  ax != u.from {
			count("unknown-client", 1)
			log.Debug("%s: unknown client - dropped", a.String())
			continue
		}

		// per host ratelimiting
		u.rl.WaitHost(ctx, a)

		// acl checks - we want to use the same acl as the underlying socks5 server that
		// handled the udp-associate
		if !AclOK(s.ListenConf, a) {
			count("acl-deny", 1)
			log.Debug("%s: ACL denied", a.String())
			continue
		}

		if u.handleUDP(buf[:n], a.AddrPort()) {
			buf = s.getBuf()
		}
	}
}

// create a new udpclient instance and dial the peer as needed
func (u *UDPListener) newUDPRelay() (*udprelay, error) {
	peer, err := u.s.dial(u.ctx)
	if err != nil {
		// XXX We assume appropriate logs are written by dial()
		return nil, err
	}

	cl := &udpclient{
		peer: peer,
	}

	cl.f.init()
	return cl, nil
}

// handle one packet from a client and return true if the buffer was consumed (to be
// freed later).
func (u *UDPListener) handleUDP(buf []byte, from netip.AddrPort) bool {
	log := u.log

	var a AddrSpec

	// First decode the udp socks5 framing
	frag := buf[2]
	log := u.log

	n, err := a.parseAddrSpec(buf[4:], log)
	if err != nil {
		return false
	}

	// data offset is 'n'
	// Only this goroutine accesses this map; so we don't need locks around it.
	// (NB: Every UDPListener instance is in its own goroutine - and is tied to
	//  the corresponding udp-listen port allocated by udp-associate)
	cl, ok := u.clients[from]
	if !ok {
		cl, err = u.newUDPClient()
		if err != nil {
			return false
		}
		u.clients[from] = cl
	}

	bufs, ok := cl.f.Add(frag, buf, n)
	if !ok {
		// We tell the caller that we consumed this buffer and they
		// need to replenish.
		return true
	}

	// We have a list of buffers, we transmit and relay:
	// - send our internal relay header
	// - followed by the actual data packets
	var hdr [268]byte
	hdrsiz := a.Marshal(hdr[:])
	if hdrsiz == 0 {
		panic("udp relay hdr size too small")
	}

	s := p.s

	// from this point on - we have to return consumed buffers.
	// In particular, the incoming buffer is _also_ consumed:
	// it went into the fragmap!
	defer func() {
		for _, b := range bufs {
			s.putBuf(b)
		}
	}()

	done := u.ctx.Done()

	// first the relay header
	_, err := WriteAll(cl.peer, hdr[:hdrsiz])
	if err != nil {
		count("werr-udp-relay", 1)
		log.Debug("udp-relay write error: %s", err)
		return true
	}

	select {
	case <- done:
		return true
	default:
	}

	// then the client data bufs
	for _, b := range bufs {
		data := b.b[b.off:]
		_, err = WriteAll(cl.peer, data)
		if err != nil {
			count("werr-udp-relay", 1)
			log.Debug("udp-relay write error: %s", err)
			return true
		}
		select {
		case <- done:
			return true
		default:
		}
	}


	// Now wait for data from peer and relay it.
	// We can reuse the incoming buffer - we consumed and sent to
	// our peer above.

	buf := buf[:cap(buf)]

	// We only send back exactly one fragment (regardless of size)
	// Build the UDP Header
	h := buf[:]
	h[0] = 0    // resv
	h[1] = 0    // resv
	h[2] = 0    // no fragment handling
	h[3] = a.Typ
	hdrsiz = 4
	switch a.Typ {
	case  A_IPV4, A_IPV6:
		z := copy(h[4:], a.Addr.AsSlice())
		hdrsiz += z

	case A_HOST:
		// No one modified 'a'; thus, we know that len(a.Host) < 256!
		h[4] = uint8(len(a.Host))
		z := copy(h[5:], []byte(a.Host))
		hdrsiz += (z + 1)
	default:
		panic(fmt.Sprintf("udp-relay: unknown addr type: %#x", a.Typ))
	}

	h[hdrsiz] = uint8(0xff & (a.Port >> 8))
	h[hdrsiz+1] = uint8(0xff & a.Port)
	hdrsiz += 2


	// Now read the response from peer
	// XXX What if our buffer size is not enough to read what the peer sends?
	n, err := cl.peer.Read(buf[hdrsiz:])
	select {
	case <- done:
		return true
	default:
	}

	if err != nil {
		count("rerr-udp-relay", 1)
		log.Debug("udp-relay read error: %s", err)
		return true
	}
	if n == 0 {
		count("zero-sized-peer-msg", 1)
		return true
	}

	// Send socks formatted message back to the peer
	_, err = writeAllTo(u.fd, buf[:hdrsiz+n], from)
	if err != nil {
		count("werr-udp-relay", 1)
		log.Debug("udp-relay write error: %s", err)
	}

	return true
}


func writeAllTo(fd *net.UDPConn, b []byte, to netip.AddrPort) (int, error) {
	n := len(b)
	nw := 0
	for n > 0 {
		z, err := fd.WriteTo(b, to)
		if err != nil {
			return nw, err
		}

		n -= z
		nw += z
		b = b[z:]
	}
	return nw, nil
}
