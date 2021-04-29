// tcp_test.go - test tcp/tls endpoints

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"
)

// return a configured Conf
func testSetup(lport, cport int) *Conf {

	// TCP connect
	// We'll spin up a simple server on the connect endpoint

	laddr := fmt.Sprintf("127.0.0.1:%d", lport)
	caddr := fmt.Sprintf("127.0.0.1:%d", cport)

	lc := &ListenConf{
		Addr: laddr,

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

// Client -> gotun TCP
// gotun -> backend TCP
func TestTcpToTls(t *testing.T) {
	assert := newAsserter(t)

	// create a logger
	log := newLogger(t)

	cfg := testSetup(9000, 9001)

	lc := cfg.Listen[0]

	pki, err := newPKI()
	assert(err == nil, "can't create PKI: %s", err)

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
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
	}

	// client config
	ctlsCfg := *tlsCfg
	ctlsCfg.Certificates = []tls.Certificate{}
	lc.clientCfg = &ctlsCfg

	// create a TLS server on the other end of a connector
	s := newTcpServer("tcp", lc.Connect.Addr, tlsCfg, t)
	assert(s != nil, "server creation failed")

	gt := NewServer(lc, cfg, log)
	gt.Start()

	// Now create a mock client to send data to mock server
	c := newTcpClient("tcp", lc.Addr, nil, t)
	assert(c != nil, "client creation failed")

	err = c.start(10)
	assert(err == nil, "can't start tcp client: %s", err)

	assert(c.nw == s.nr, "i/o mismatch: client TX %d, server RX %d", c.nw, s.nr)
	assert(c.nr == s.nw, "i/o mismatch: server TX %d, client RX %d", s.nw, c.nr)

	c.stop()
	s.stop()
	gt.Stop()
	log.Close()
}

func TestTcpToTcp(t *testing.T) {
	assert := newAsserter(t)

	// create a logger
	log := newLogger(t)

	cfg := testSetup(9010, 9011)

	lc := cfg.Listen[0]

	// create a server on the other end of a connector
	s := newTcpServer("tcp", lc.Connect.Addr, nil, t)
	assert(s != nil, "server creation failed")

	gt := NewServer(lc, cfg, log)
	gt.Start()

	// Now create a mock client to send data to mock server
	c := newTcpClient("tcp", lc.Addr, nil, t)
	assert(c != nil, "client creation failed")

	err := c.start(10)
	assert(err == nil, "can't start tcp client: %s", err)

	assert(c.nw == s.nr, "i/o mismatch: client TX %d, server RX %d", c.nw, s.nr)
	assert(c.nr == s.nw, "i/o mismatch: server TX %d, client RX %d", s.nw, c.nr)

	c.stop()
	s.stop()
	gt.Stop()
	log.Close()
}

// Client -> gotun TLS
// gotun -> backend TCP
func TestTlsToTcp(t *testing.T) {
	assert := newAsserter(t)

	pki, err := newPKI()
	assert(err == nil, "can't create PKI: %s", err)

	cfg := testSetup(9005, 9006)
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
	c := newTcpClient("tcp", lc.Addr, &ctlsCfg, t)
	assert(c != nil, "client creation failed")

	c.start(10)

	assert(c.nw == s.nr, "i/o mismatch: client TX %d, server RX %d", c.nw, s.nr)
	assert(c.nr == s.nw, "i/o mismatch: server TX %d, client RX %d", s.nw, c.nr)

	c.stop()
	s.stop()
	gt.Stop()
	log.Close()
}

// Client -> gotun TLS with client auth
// gotun -> backend TCP
func TestClientTlsToTcp(t *testing.T) {
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

	cfg := testSetup(9008, 9009)
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
	c := newTcpClient("tcp", lc.Addr, &ctlsCfg, t)
	assert(c != nil, "client creation failed")

	c.start(10)

	assert(c.nw == s.nr, "i/o mismatch: client TX %d, server RX %d", c.nw, s.nr)
	assert(c.nr == s.nw, "i/o mismatch: server TX %d, client RX %d", s.nw, c.nr)

	c.stop()
	s.stop()
	gt.Stop()
	log.Close()
}

// Client -> gotun TLS with client auth
// gotun -> backend Quic
func TestClientTlsToQuic(t *testing.T) {
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

	cfg := testSetup(9012, 9013)
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
		RootCAs:      spool,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    cpool,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
	}

	// mock quic server TLS config
	mtlsCfg := *tlsCfg
	mtlsCfg.ClientAuth = tls.NoClientCert
	mtlsCfg.ClientCAs = nil
	mtlsCfg.NextProtos = []string{"relay"}

	// tls client config for gotun
	qtlsCfg := *tlsCfg
	qtlsCfg.ClientAuth = tls.NoClientCert
	qtlsCfg.ClientCAs = nil
	qtlsCfg.Certificates = nil
	qtlsCfg.NextProtos = []string{"relay"}

	lc.serverCfg = tlsCfg
	lc.clientCfg = &qtlsCfg
	lc.Connect.Quic = true

	cfg.Dump(log)

	// client TLS config; we need the proper root and client certs
	ctlsCfg := *tlsCfg
	ctlsCfg.Certificates = []tls.Certificate{clientCert}

	// create a server on the other end of a connector
	s := newQuicServer("tcp", lc.Connect.Addr, &mtlsCfg, t)
	assert(s != nil, "server creation failed")

	gt := NewServer(lc, cfg, log)
	gt.Start()

	// Now create a mock client to send data to mock server
	c := newTcpClient("tcp", lc.Addr, &ctlsCfg, t)
	assert(c != nil, "client creation failed")

	err = c.start(10)
	assert(err == nil, "can't start tls client: %s", err)

	assert(c.nw == s.nr, "i/o mismatch: client TX %d, server RX %d", c.nw, s.nr)
	assert(c.nr == s.nw, "i/o mismatch: server TX %d, client RX %d", s.nw, c.nr)

	c.stop()
	s.stop()
	gt.Stop()
	log.Close()
}

// Client -> gotun TLS with *bad* client auth
// gotun -> backend TCP
func TestClientBadTlsToTcp(t *testing.T) {
	assert := newAsserter(t)

	pki, err := newPKI()
	assert(err == nil, "can't create PKI: %s", err)

	pkic, err := newPKI()
	assert(err == nil, "can't create client PKI: %s", err)

	spool := x509.NewCertPool()
	spool.AddCert(pki.ca)

	cpool := x509.NewCertPool()
	cpool.AddCert(pkic.ca)

	cfg := testSetup(9010, 9011)
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

	// This is a _bad_ client cert (different root)
	ctlsCfg.Certificates = []tls.Certificate{cert}

	// create a server on the other end of a connector
	s := newTcpServer("tcp", lc.Connect.Addr, nil, t)
	assert(s != nil, "server creation failed")

	log := newLogger(t)
	gt := NewServer(lc, cfg, log)
	gt.Start()

	// Now create a mock client to send data to mock server
	c := newTcpClient("tcp", lc.Addr, &ctlsCfg, t)
	assert(c != nil, "client creation failed")

	c.start(10)
	assert(c.nr == 0, "client read from closed conn %d bytes", c.nr)

	c.stop()
	s.stop()
	gt.Stop()
	log.Close()
}
