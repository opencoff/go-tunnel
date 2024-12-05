// quic_test.go - test quic to {TCP, TLS} endpoints

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"testing"
)

// return a configured Conf
func quicSetup(lport, cport int) *Conf {

	// TCP connect
	// We'll spin up a simple server on the connect endpoint

	laddr := fmt.Sprintf("127.0.0.1:%d", lport)
	caddr := fmt.Sprintf("127.0.0.1:%d", cport)

	lc := &ListenConf{
		Addr: laddr,
		Quic: true,
		Connect: ConnectConf{
			Addr: caddr,
		},
	}

	c := &Conf{
		Logging: "NONE",
		Listen:  []*ListenConf{lc},
	}

	return ConfDefaults(c)
}

// Client -> gotun Quic
// gotun -> backend TCP
func TestQuicToTcp(t *testing.T) {
	assert := newAsserter(t)

	pki, err := newPKI()
	assert(err == nil, "can't create PKI: %s", err)

	cfg := quicSetup(8005, 8006)
	lc := cfg.Listen[0]

	cert, err := pki.ServerCert("server.name", lc.Addr)
	assert(err == nil, "can't create server cert: %s", err)

	pool := x509.NewCertPool()
	pool.AddCert(pki.ca)
	tlsCfg := &tls.Config{
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
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
	}

	lc.serverCfg = tlsCfg

	// client TLS config; we need the proper root. But no client Certs.
	ctlsCfg := *tlsCfg
	ctlsCfg.Certificates = []tls.Certificate{}

	// create a server on the other end of a connector
	s := newTcpServer("tcp", lc.Connect.Addr, nil, t)
	assert(s != nil, "server creation failed")

	log := newLogger(t)
	gt := NewServer(lc, cfg, log)
	gt.Start()

	// Now create a mock client to send data to mock server
	c := newQuicClient("udp", lc.Addr, &ctlsCfg, t)
	assert(c != nil, "client creation failed")

	c.start(10)

	assert(c.nw == s.nr, "i/o mismatch: client TX %d, server RX %d", c.nw, s.nr)
	assert(c.nr == s.nw, "i/o mismatch: server TX %d, client RX %d", s.nw, c.nr)

	c.stop()
	s.stop()
	gt.Stop()
	log.Close()
}

// Client -> gotun Quic with client auth
// gotun -> backend TCP
func TestQuicAuthToTcp(t *testing.T) {
	assert := newAsserter(t)

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

	cfg := quicSetup(8008, 8009)
	lc := cfg.Listen[0]

	cert, err := pki.ServerCert("server.name", lc.Addr)
	assert(err == nil, "can't create server cert: %s", err)

	tlsCfg := &tls.Config{
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

	lc.serverCfg = tlsCfg

	// client TLS config; we need the proper root
	ctlsCfg := *tlsCfg
	ctlsCfg.Certificates = []tls.Certificate{clientCert}

	// create a server on the other end of a connector
	s := newTcpServer("tcp", lc.Connect.Addr, nil, t)
	assert(s != nil, "server creation failed")

	log := newLogger(t)
	gt := NewServer(lc, cfg, log)
	gt.Start()

	// Now create a mock client to send data to mock server
	c := newQuicClient("udp", lc.Addr, &ctlsCfg, t)
	assert(c != nil, "client creation failed")

	c.start(10)

	assert(c.nw == s.nr, "i/o mismatch: client TX %d, server RX %d", c.nw, s.nr)
	assert(c.nr == s.nw, "i/o mismatch: server TX %d, client RX %d", s.nw, c.nr)

	c.stop()
	s.stop()
	gt.Stop()
	log.Close()
}

// Client -> gotun Quic with client auth
// gotun -> backend TLS
func TestQuicAuthToTls(t *testing.T) {
	assert := newAsserter(t)

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

	cfg := quicSetup(8020, 8021)
	lc := cfg.Listen[0]

	cert, err := pki.ServerCert("server.name", lc.Addr)
	assert(err == nil, "can't create server cert: %s", err)

	// config for quic server
	qtlsCfg := &tls.Config{
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

	// mock TLS server config
	stlsCfg := *qtlsCfg
	stlsCfg.ClientAuth = tls.NoClientCert
	stlsCfg.ClientCAs = nil

	// gotun TLS client config
	gtlsCfg := *qtlsCfg
	gtlsCfg.Certificates = nil
	gtlsCfg.ClientAuth = tls.NoClientCert
	gtlsCfg.ClientCAs = nil

	lc.serverCfg = qtlsCfg
	lc.clientCfg = &gtlsCfg

	// client quic config; we need the proper root and client certs
	ctlsCfg := *qtlsCfg
	ctlsCfg.Certificates = []tls.Certificate{clientCert}

	// create a TLS server on the other end of a connector
	s := newTcpServer("tcp", lc.Connect.Addr, &stlsCfg, t)
	assert(s != nil, "server creation failed")

	log := newLogger(t)
	gt := NewServer(lc, cfg, log)
	gt.Start()

	// Now create a mock client to send data to mock server
	c := newQuicClient("udp", lc.Addr, &ctlsCfg, t)
	assert(c != nil, "client creation failed")

	c.start(10)

	assert(c.nw == s.nr, "i/o mismatch: client TX %d, server RX %d", c.nw, s.nr)
	assert(c.nr == s.nw, "i/o mismatch: server TX %d, client RX %d", s.nw, c.nr)

	c.stop()
	s.stop()
	gt.Stop()
	log.Close()
}

// Client -> tcp
// gotun -> backend quic
func TestTcpToQuicAuth(t *testing.T) {
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

	cfg := testSetup(8008, 8009)
	lc := cfg.Listen[0]

	// we want outgoing connect to be quic
	lc.Connect.Quic = true

	cfg.Dump(&logWriter{t})

	cert, err := pki.ServerCert("server.name", lc.Addr)
	assert(err == nil, "can't create server cert: %s", err)

	tlsCfg := &tls.Config{
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
	ctlsCfg := *tlsCfg
	ctlsCfg.Certificates = []tls.Certificate{clientCert}

	// outbound connection is a Quic client
	lc.clientCfg = &ctlsCfg

	// create a server on the other end of a connector
	s := newQuicServer("udp", lc.Connect.Addr, tlsCfg, t)
	assert(s != nil, "server creation failed")

	gt := NewServer(lc, cfg, log)
	gt.Start()

	// Now create a mock client to send data to mock server
	c := newTcpClient("tcp", lc.Addr, nil, t)
	assert(c != nil, "client creation failed")

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		err := c.start(10)
		assert(err == nil, "tcp client can't connect: %s", err)
		wg.Done()
	}()

	// now we test muxing multiple inbound TCPs to a single
	// quic session + multiple streams

	c2 := newTcpClient("tcp", lc.Addr, nil, t)
	assert(c2 != nil, "second client creation failed")

	wg.Add(1)
	go func() {
		err := c2.start(10)
		assert(err == nil, "tcp client can't connect: %s", err)
		wg.Done()
	}()

	wg.Wait()
	assert(c.nw+c2.nw == s.nr, "i/o mismatch: client TX %d; %d, server RX %d", c.nw, c2.nw, s.nr)
	assert(c.nr+c2.nr == s.nw, "i/o mismatch: server TX %d, client RX %d; %d", s.nw, c.nr, c2.nr)

	c.stop()
	s.stop()
	gt.Stop()
	log.Close()
}
