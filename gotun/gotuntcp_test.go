// tcp_test.go - test tcp/tls endpoints

package main

import (
	"net"
	"testing"
)

// return a configured Conf
func testSetup() *Conf {

	// TCP connect
	// We'll spin up a simple server on the connect endpoint

	lc := &ListenConf{
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

func TestTCPtoTCP(t *testing.T) {
	assert := newAsserter(t)

	pk, err := newPKI()
	assert(err == nil, "can't create PKI: %s", err)

	a := net.ParseIP("127.0.0.1")
	assert(a != nil, "can't parse ip: %s", err)

	cert, key, err := pk.ServerCert("myserver.com", a)
	assert(err == nil, "can't create server cert: %s", err)
	assert(cert != nil, "server cert nil")
	assert(key != nil, "server key nil")

	cert, key, err = pk.ClientCert("client@foo.com")
	assert(err == nil, "can't create client cert: %s", err)
	assert(cert != nil, "client cert nil")
	assert(key != nil, "client key nil")

}
