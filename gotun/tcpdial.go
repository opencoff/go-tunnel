// tcpdial.go -- dialer abstraction for TCP/TLS
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
	"fmt"
	L "github.com/opencoff/go-logger"
	"net"
	"time"
)

type tcpDialer struct {
	r    *Server
	log  *L.Logger
	dial *net.Dialer
}

func newTCPDialer(r *Server, log *L.Logger) (Dialer, error) {
	return &tcpDialer{
		r:   r,
		log: log,
		dial: &net.Dialer{
			Timeout:   time.Duration(r.Timeout.Connect) * time.Second,
			LocalAddr: resolveAddr(r.Connect.Bind),

			// XXX Do we need this?
			KeepAlive: 25 * time.Second,
		},
	}, nil
}

func (t *tcpDialer) Dial(network string, addr string, lhs Conn, ctx context.Context) (Conn, error) {

	peer, err := t.dial.DialContext(ctx, network, addr)
	if err != nil {
		t.log.Warn("can't connect to %s: %s", addr, err)
		return nil, fmt.Errorf("can't dial %s: %w", addr, err)
	}

	t.log.Debug("%s connected to  %s", peer.LocalAddr().String(), addr)
	if t.r.clientTls != nil {
		econn := tls.Client(peer, t.r.clientTls)
		err := econn.Handshake()
		if err != nil {
			t.log.Warn("can't establish TLS with %s: %s", addr, err)
			return nil, fmt.Errorf("tls-client %s: %w", addr, err)
		}

		st := econn.ConnectionState()
		t.log.Debug("tls client handshake with %s complete; Version %#x, Cipher %#x", addr,
			st.Version, st.CipherSuite)
		peer = econn
	}

	// Proxy protocol handling
	switch t.r.Connect.ProxyProtocol {
	case "v1":
		a1 := lhs.RemoteAddr().(*net.TCPAddr)
		a2 := lhs.LocalAddr().(*net.TCPAddr)
		s := fmt.Sprintf("PROXY %s %s %s %d %d\r\n",
			a2.Network(), a1.IP.String(), a2.IP.String(), a1.Port, a2.Port)
		peer.Write([]byte(s))
	default:
		t.r.log.Debug("%s: no support for PROXY Protocol %s", addr, t.r.Connect.ProxyProtocol)
	}

	return peer, nil
}
