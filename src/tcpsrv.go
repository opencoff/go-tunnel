// tcpsrv.go -- TCP Server
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
	"net"
	"time"
	"math/rand"

	"github.com/opencoff/go-utils"
)

// Encapsulates info needed to be a plain listener or a TLS listener.
// And has a dialer to connect to a plain or TLS endpoint
type TCPServer struct {
	*net.TCPListener

	*Server

	ports *utils.Q[int]
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

	if s.IsSocks() {
		n := s.Conf.UdpEnd - s.Conf.UdpStart + 1
		v := make([]uint16, n)
		z := s.Conf.UdpStart
		for i := 0; i < n; i++, z++ {
			v[i] = z
		}

		rand.Shuffle(n, func(i, j int) {
			v[i], v[j] = v[j], v[i]
		})

		p.ports = utils.NewQFrom[uint16](v)
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


func (p *TCPServer) handleTCP(conn Conn, ctx context.Context) {
	defer func() {
		p.wg.Done()
		conn.Close()
	}()

	if p.tls != nil {
		lhs := conn.RemoteAddr().String()
		econn := tls.Server(conn, p.tls)
		err := econn.Handshake()
		if err != nil {
			p.log.Warn("can't establish TLS with %s: %s", lhs, err)
			return
		}

		st := econn.ConnectionState()
		p.log.Debug("tls server handshake with %s complete; Version %#x, Cipher %#x", lhs,
			st.Version, st.CipherSuite)
		conn = econn
	}

	log := p.log.New(conn.RemoteAddr().String(), 0)

	b0 := p.getBuf()
	defer p.putBuf(b0)

	var err error
	var network, addr string

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

	p.handleConn(conn, peer, ctx, log)
}


func (p *TCPServer) findUdpPort() (netip.AddrPort, error) {
}

