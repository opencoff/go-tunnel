// tcp_test.go - test tcp/tls endpoints

package main

import (
	"fmt"
	"testing"
)

// return a configured Conf
func testSetup() *Conf {

	// TCP connect
	// We'll spin up a simple server on the connect endpoint

	lc := &ListenConf{
		Addr:    "127.0.0.1:9000",
		Allow:   "0.0.0.0/32",
		Connect: ConnectConf{
				Addr: "127.0.0.1:9001",
			},
	}

	c := &Conf{
		Logging: "NONE",
		Listen:  []*ListenConf{lc},
	}

	return c
}

type mockServer struct {
	net.Listener

	done chan bool
}

func newMockServer(network, addr string) (*mockServer, error) {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}

	return &mockServer{
			Listener: ln,
			done:	  make(chan bool),
		}
}

func (m *mockServer) buildup(h func(net.Listener, *mockServer)) {
	go func() {
		h(m.Listener, m)
		close(m.done)
	}()
}

func (m *mockServer) stop() {
	m.Close()
	<- m.done
}

func startEndpointTCPServer(addr string, t *testing.T, ctx context.Context)  {
	assert := newAsserter(t)
	ln, err := net.Listen("tcp", addr)
	assert(err == nil, "can't listen on %s: %s", addr, err)

	go func() {

		for {
			conn, err := ln.Accept()
			assert(err == nil, "can't accept on %s: %s", addr, err)

			go relay(conn, t)
		}

	}
}

func TestTCPtoTCP(t *testing.T) {
	assert := newAsserter(t)


	cfg := testSetup()

	m := newMockServer("tcp", cfg.Listen[0].Connect.Addr)
	m.buildup(relay)
}
