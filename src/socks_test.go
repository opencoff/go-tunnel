// socks_test.go - test socks+quic to endpoints

package main

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

// tcp -> socks
func TestSocksToTcpIP4(t *testing.T) {
	assert := newAsserter(t)

	log := newLogger(t)
	// first tunnel instance: TCP->Quic
	cfga := testSetup(8030, 8031)
	lca := cfga.Listen[0]
	lca.Connect.Addr = "SOCKS"

	cfga.Dump(&logWriter{t})

	// start simple server on the other end of socks
	s := newTcpServer("tcp4", "127.0.0.1:9010", nil, t)
	assert(s != nil, "tcp server-a creation failed")

	// now, create a gotunnel instance
	gt := NewServer(lca, cfga, log)

	gt.Start()

	// Create socks client
	c := newSocksClient(lca.Addr, "tcp4", "127.0.0.1:9010", t)
	assert(c != nil, "socks client failed")

	err := c.start(10)
	assert(err == nil, "can't dial socks: %s", err)

	assert(c.nw == s.nr, "i/o mismatch: client TX %d, server RX %d", c.nw, s.nr)
	assert(c.nr == s.nw, "i/o mismatch: server TX %d, client RX %d", s.nw, c.nr)

	c.stop()
	s.stop()
	gt.Stop()
	log.Close()
}

// socks hostname
func TestSocksToTcpHost(t *testing.T) {
	assert := newAsserter(t)

	log := newLogger(t)

	// first tunnel instance: TCP->Quic
	cfga := testSetup(8030, 8031)
	lca := cfga.Listen[0]
	lca.Connect.Addr = "SOCKS"

	cfga.Dump(&logWriter{t})

	// start simple server on the other end of socks
	s := newTcpServer("tcp4", "localhost:9010", nil, t)
	assert(s != nil, "tcp server-a creation failed")

	// now, create a gotunnel instance
	gt := NewServer(lca, cfga, log)

	gt.Start()

	// Create socks client
	c := newSocksClient(lca.Addr, "tcp4", "localhost:9010", t)
	assert(c != nil, "socks client failed")

	err := c.start(10)
	assert(err == nil, "can't dial socks: %s", err)

	assert(c.nw == s.nr, "i/o mismatch: client TX %d, server RX %d", c.nw, s.nr)
	assert(c.nr == s.nw, "i/o mismatch: server TX %d, client RX %d", s.nw, c.nr)

	c.stop()
	s.stop()
	gt.Stop()
	log.Close()
}

func TestSocksToQuicIP4(t *testing.T) {
	assert := newAsserter(t)

	log := newLogger(t)

	pki, err := newPKI()
	assert(err == nil, "can't create PKI: %s", err)

	pkic, err := newPKI()
	assert(err == nil, "can't create client PKI: %s", err)

	clientCert, err := pkic.ClientCert("client.name")
	assert(err == nil, "can't create client cert: %s", err)

	spool := x509.NewCertPool()
	spool.AddCert(pki.ca)

	cpool := x509.NewCertPool()
	cpool.AddCert(pkic.ca)

	// first tunnel instance: TCP->Quic
	cfga := testSetup(8030, 8031)
	lca := cfga.Listen[0]

	// we want outgoing connect to be quic + auth
	lca.Connect.Quic = true

	// This is second tunnel instance
	cfgb := quicSetup(8031, 8032)
	lcb := cfgb.Listen[0]
	lcb.Connect.Addr = "SOCKS"

	cfga.Dump(&logWriter{t})
	cfgb.Dump(&logWriter{t})

	cert, err := pki.ServerCert("server.name", lcb.Addr)
	assert(err == nil, "can't create server cert: %s", err)

	// Quic TLS cnfig for second instance
	tlsbCfg := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		ServerName:             "server.name",
		SessionTicketsDisabled: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

			// Best disabled, as they don't provide Forward Secrecy,
			// but might be necessary for some clients
			// tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
		NextProtos:   []string{"relay"},
		RootCAs:      spool,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    cpool,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
	}

	// client TLS config; we need the proper root
	tlsaCfg := *tlsbCfg
	tlsaCfg.Certificates = []tls.Certificate{clientCert}

	// outbound connection is a Quic client
	lca.clientCfg = &tlsaCfg
	lcb.serverCfg = tlsbCfg

	// to simulate a real server on the other side, we will
	// run TCP on port 9010, 9011

	// create a TCP server on the other end of second tunnel
	s0 := newTcpServer("tcp", "127.0.0.1:9010", nil, t)
	assert(s0 != nil, "tcp server-a creation failed")

	//s1 := newTcpServer("tcp", "127.0.0.1:9011", nil, t)
	//assert(s1 != nil, "tcp server-b creation failed")

	// tunnel #1: TCP -> Quic
	gta := NewServer(lca, cfga, log)
	gtb := NewServer(lcb, cfgb, log)

	gta.Start()
	gtb.Start()

	// Now create a mock client to send data to mock server
	c0 := newSocksClient(lca.Addr, "tcp", "127.0.0.1:9010", t)
	assert(c0 != nil, "client creation failed")

	c1 := newSocksClient(lca.Addr, "tcp", "127.0.0.1:9010", t)
	assert(c1 != nil, "client-2 creation failed")

	err = c0.start(10)
	assert(err == nil, "tcp client error: %s", err)

	err = c1.start(10)
	assert(err == nil, "tcp client-2 error: %s", err)

	assert(c0.nw+c1.nw == s0.nr, "i/o mismatch: client TX %d; %d, server RX %d", c0.nw, c1.nw, s0.nr)
	assert(c0.nr+c1.nr == s0.nw, "i/o mismatch: server TX %d; %d, client RX %d; %d", s0.nw, c0.nr, c1.nr)

	c0.stop()
	c1.stop()
	s0.stop()
	gta.Stop()
	gtb.Stop()
	log.Close()
}

/*
func TestSocksToQuicHost(t *testing.T) {
}

func TestSocksToQuicIP6(t *testing.T) {
}
*/
