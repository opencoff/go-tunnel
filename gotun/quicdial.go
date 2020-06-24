// quicdial.go -- dialer abstraction for Quic
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"context"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	L "github.com/opencoff/go-logger"
	"net"
	"sync"
)

type quicDialer struct {
	sync.Mutex

	r *Server

	log *L.Logger

	// map of destinations to qSession
	dest map[string]quic.Session
}

// Wraps a quic Stream as a Conn
type qConn struct {
	quic.Stream

	// Link back to quic session for this stream
	s quic.Session

	log *L.Logger
}

func newQuicDialer(r *Server, log *L.Logger) (Dialer, error) {
	q := &quicDialer{
		r:    r,
		log:  log,
		dest: make(map[string]quic.Session),
	}

	return q, nil
}

// implement the dialer interface. We don't have any use for the LHS. It's only meaningful
// for the TCP/TLS dialer
func (q *quicDialer) Dial(network, addr string, _ Conn, ctx context.Context) (Conn, error) {
	var err error

	key := fmt.Sprintf("%s:%s", network, addr)
	q.Lock()
	d, ok := q.dest[key]
	if !ok {
		/*
			conn, err := net.ListenPacket(net, addr)
			if err != nil {
				q.Unlock()
				q.log.Warn("quic: can't listen %s: %s", addr, err)
				return nil, fmt.Sprintf("quic: %s: %w", addr, err)
			}
		*/

		// XXX Do we need to setup a quic Config?
		d, err = quic.DialAddrContext(ctx, addr, q.r.clientTls, &quic.Config{})
		if err != nil {
			q.Unlock()

			q.log.Warn("quic: can't dial %s: %s", addr, err)
			return nil, fmt.Errorf("quic: %s: %w", addr, err)
		}

		state := d.ConnectionState()
		q.log.Debug("quic: Established new session with %s [%s]", addr, state.ServerName)
		q.dest[key] = d
	}
	q.Unlock()

	t, err := d.OpenStream()
	if err != nil {
		q.log.Warn("quic: %s: can't open new stream: %s", addr, err)
		return nil, fmt.Errorf("quic: %s: %w", addr, err)
	}

	log := q.log.New(fmt.Sprintf("%s.%#x", addr, t.StreamID()), 0)
	log.Debug("quic: %s: opened new stream %#x", addr, t.StreamID())
	c := &qConn{
		Stream: t,
		s:      d,
		log:    log,
	}

	return c, nil
}

// Address abstraction that tacks on the stream-id
type qAddr struct {
	a  net.Addr
	id quic.StreamID
}

func (a *qAddr) Network() string {
	return a.a.Network()
}

func (a *qAddr) String() string {
	return fmt.Sprintf("%s.%#x", a.a.String(), a.id)
}

// implement new.Conn interfaces too
func (c *qConn) LocalAddr() net.Addr {
	return &qAddr{
		a:  c.s.LocalAddr(),
		id: c.StreamID(),
	}
}

func (c *qConn) RemoteAddr() net.Addr {
	return &qAddr{
		a:  c.s.RemoteAddr(),
		id: c.StreamID(),
	}
}
