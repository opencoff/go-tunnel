// mockserver_test.go - mock servers

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lucas-clemente/quic-go"
)

const (
	IOSIZE int = 4096
)

type tcpserver struct {
	net.Listener
	t *testing.T

	// number of bytes read and written
	nr int
	nw int

	tls    *tls.Config
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newTcpServer(network, addr string, tcfg *tls.Config, t *testing.T) *tcpserver {
	assert := newAsserter(t)
	ln, err := net.Listen(network, addr)
	assert(err == nil, "can't listen: %s", err)

	s := &tcpserver{
		Listener: ln,
		t:        t,
		tls:      tcfg,
	}

	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.wg.Add(1)
	go s.accept()
	return s
}

func (s *tcpserver) stop() {
	s.cancel()
	s.Close()
	s.wg.Wait()
	s.t.Logf("stopped mock tcp server on %s", s.Addr())
}

func (s *tcpserver) accept() {
	defer s.wg.Done()

	assert := newAsserter(s.t)
	done := s.ctx.Done()
	addr := s.Addr().String()
	s.t.Logf("%s: mock tcp server waiting for new conn ..\n", addr)
	for {
		conn, err := s.Accept()
		select {
		case <-done:
			return
		default:
		}

		assert(err == nil, "accept %s: %s", addr, err)
		s.wg.Add(1)
		go s.relay(conn)
	}
}

func (s *tcpserver) relay(fd net.Conn) {
	there := fd.RemoteAddr().String()
	assert := newAsserter(s.t)
	done := s.ctx.Done()
	from := fmt.Sprintf("%s--%s", there, fd.LocalAddr().String())

	defer func() {
		s.wg.Done()
		fd.Close()
		s.t.Logf("mock tcp server: closed conn from %s\n", there)
	}()

	s.t.Logf("mock tcp server: new conn from %s\n", there)

	if s.tls != nil {
		econn := tls.Server(fd, s.tls)
		err := econn.Handshake()
		assert(err == nil, "TLS handshake failed: %s", err)
		fd = econn

		s.t.Logf("mock tcp server: Upgraded %s to TLS\n", there)
	}

	buf := make([]byte, IOSIZE)
	var csum [sha256.Size]byte

	// All timeouts are v short
	rto := 1 * time.Second

	h := sha256.New()
	for i := 0; ; i++ {
		fd.SetReadDeadline(time.Now().Add(rto))
		nr, err := readfull(fd, buf)
		select {
		case <-done:
			return
		default:
		}

		if errors.Is(err, io.EOF) || nr == 0 {
			s.t.Logf("%s: EOF? nr=%d, err %s\n", from, nr, err)
			return
		}
		assert(err == nil, "%s: read err: %s", from, err)

		s.nr += nr
		h.Reset()
		h.Write(buf[:nr])
		sum := h.Sum(csum[:0])

		//s.t.Logf("%s: %d: RX %d [%x]\n", from, i, nr, sum[:])
		fd.SetWriteDeadline(time.Now().Add(rto))
		nw, err := writefull(fd, sum[:])
		select {
		case <-done:
			return
		default:
		}

		assert(err == nil, "%s: write err: %s", from, err)
		assert(nw == len(sum[:]), "%s: partial write; exp %d, saw %d", from, len(sum[:]), nw)

		//s.t.Logf("%s: RX %d bytes, TX %d\n", from, nr, len(sum[:]))
		s.nw += len(sum[:])
	}
}

type tcpclient struct {
	net.Conn

	nr int
	nw int

	network string
	addr    string

	tls *tls.Config

	t      *testing.T
	ctx    context.Context
	cancel context.CancelFunc
}

func newTcpClient(network, addr string, tcfg *tls.Config, t *testing.T) *tcpclient {
	ctx, cancel := context.WithCancel(context.Background())

	c := &tcpclient{
		network: network,
		addr:    addr,
		tls:     tcfg,
		t:       t,
		ctx:     ctx,
		cancel:  cancel,
	}

	return c
}

func (c *tcpclient) start(n int) error {
	var err error
	dial := &net.Dialer{
		Timeout: 1 * time.Second,
	}

	c.Conn, err = dial.DialContext(c.ctx, c.network, c.addr)
	if err != nil {
		return err
	}

	c.t.Logf("mock tcp client: %s connected to %s\n", c.LocalAddr().String(), c.addr)
	return c.loop(n)
}

func (c *tcpclient) stop() {
	c.cancel()
	c.Close()
	c.t.Logf("mock tcp client %s-%s stopped\n", c.LocalAddr().String(), c.addr)
}

func (c *tcpclient) loop(n int) error {
	assert := newAsserter(c.t)
	done := c.ctx.Done()
	addr := c.RemoteAddr().String()
	from := fmt.Sprintf("%s-%s", c.LocalAddr().String(), addr)
	fd := c.Conn

	defer func() {
		c.Close()
		c.t.Logf("mock tcp client: closing conn %s\n", from)
	}()

	if c.tls != nil {
		econn := tls.Client(c, c.tls)
		err := econn.Handshake()
		if err != nil {
			return err
		}
		fd = econn
		c.t.Logf("mock tcp client: Upgraded %s to TLS\n", from)
	}

	buf := make([]byte, IOSIZE)
	rand.Read(buf)

	var sumr, csuma [sha256.Size]byte

	h := sha256.New()
	for i := 0; i < n; i++ {
		nw, err := writefull(fd, buf)
		select {
		case <-done:
			return nil
		default:
		}
		assert(err == nil, "%s: write err: %s", from, err)
		assert(nw == len(buf), "%s: partial write, exp %d, saw %d", from, len(buf), nw)

		c.nw += nw

		h.Reset()
		h.Write(buf)
		suma := h.Sum(csuma[:0])

		//c.t.Logf("%s: %d: TX %d [%x]\n", from, i, nw, suma[:])

		nr, err := readfull(fd, sumr[:])
		select {
		case <-done:
			return nil
		default:
		}

		if errors.Is(err, io.EOF) || nr == 0 {
			c.t.Logf("%s: EOF? nr %d\n", from, nr)
			return nil
		}
		assert(err == nil, "%s: read err: %s", from, err)
		assert(nr == len(sumr[:]), "%s: partial read, exp %d, saw %d", from, len(sumr[:]), nr)

		assert(byteEq(suma[:], sumr[:]), "%s: cksum mismatch;\nexp %x\nsaw %x", from, suma[:], sumr[:])
		inc(buf)
		c.nr += len(sumr[:])
		//c.t.Logf("%s: TX %d, RX %d\n", addr, nw, len(sumr[:]))
	}
	return nil
}

func writefull(fd io.Writer, b []byte) (int, error) {
	var z int
	n := len(b)
	for n > 0 {
		nw, err := fd.Write(b)
		if err != nil {
			return z, err
		}

		n -= nw
		z += nw
		b = b[nw:]
	}

	return z, nil
}

func readfull(fd io.Reader, b []byte) (int, error) {
	var z int
	n := len(b)
	for n > 0 {
		nr, err := fd.Read(b)
		if err != nil {
			return z, err
		}

		n -= nr
		z += nr
		b = b[nr:]
	}
	return z, nil
}

type quicserver struct {
	quic.Listener

	t *testing.T

	nr int
	nw int

	tls    *tls.Config
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newQuicServer(network, addr string, tcfg *tls.Config, t *testing.T) *quicserver {
	assert := newAsserter(t)

	la, err := net.ResolveUDPAddr("udp", addr)
	assert(err == nil, "can't resolve addr %s: %s", addr, err)

	ln, err := net.ListenUDP("udp", la)
	assert(err == nil, "can't listen UDP %s: %s", addr, err)

	q, err := quic.Listen(ln, tcfg, &quic.Config{})
	assert(err == nil, "can't listen quic %s: %s", addr, err)

	qs := &quicserver{
		Listener: q,
		t:        t,
	}

	qs.ctx, qs.cancel = context.WithCancel(context.Background())
	qs.wg.Add(1)
	go qs.accept()
	return qs
}

func (q *quicserver) stop() {
	q.cancel()
	q.Close()
	q.wg.Wait()
	q.t.Logf("stopped mock quic server on %s", q.Addr())
}

func (q *quicserver) accept() {
	assert := newAsserter(q.t)
	defer q.wg.Done()

	q.t.Logf("mock quic server listening on %s ..\n", q.Addr().String())
	done := q.ctx.Done()
	for {
		sess, err := q.Accept(q.ctx)
		select {
		case <-done:
			return
		default:
		}

		assert(err == nil, "can't accept quic: %s", err)

		q.wg.Add(1)
		go q.serveSession(sess)
	}
}

func (q *quicserver) serveSession(sess quic.Session) {
	defer q.wg.Done()

	assert := newAsserter(q.t)
	done := q.ctx.Done()
	for {
		conn, err := sess.AcceptStream(q.ctx)
		select {
		case <-done:
			return
		default:
		}
		assert(err == nil, "can't accept quic-stream: %s", err)

		qc := &qconn{
			Stream: conn,
			s:      sess,
		}

		q.t.Logf("mock quic server accepted new stream %d from %s\n", conn.StreamID(), qc.RemoteAddr().String())
		q.wg.Add(1)
		go q.relay(qc)
	}
}

func (q *quicserver) relay(fd *qconn) {
	assert := newAsserter(q.t)
	done := q.ctx.Done()
	addr := fd.RemoteAddr().String()
	from := fmt.Sprintf("%s-%s", fd.LocalAddr().String(), addr)

	defer func() {
		q.wg.Done()
		fd.Close()
		q.t.Logf("mock quic server: closed conn from %s\n", from)
	}()

	buf := make([]byte, IOSIZE)
	var csum [sha256.Size]byte

	// All timeouts are v short
	rto := 5 * time.Second

	h := sha256.New()
	for i := 0; ; i++ {
		fd.SetReadDeadline(time.Now().Add(rto))
		nr, err := readfull(fd, buf)
		select {
		case <-done:
			return
		default:
		}

		if errors.Is(err, io.EOF) || nr == 0 {
			q.t.Logf("%s: EOF? nr=%d, err %s\n", from, nr, err)
			return
		}
		assert(err == nil, "%s: read err: %s", from, err)

		q.nr += nr
		h.Reset()
		h.Write(buf[:nr])
		sum := h.Sum(csum[:0])

		//q.t.Logf("%s: %d: RX %d [%x]\n", from, i, nr, sum[:])
		fd.SetWriteDeadline(time.Now().Add(rto))
		nw, err := writefull(fd, sum[:])
		select {
		case <-done:
			return
		default:
		}

		assert(err == nil, "%s: write err: %s", from, err)
		assert(nw == len(sum[:]), "%s: partial write; exp %d, saw %d", from, len(sum[:]), nw)

		//q.t.Logf("%s: RX %d bytes, TX %d\n", from, nr, len(sum[:]))
		q.nw += len(sum[:])
	}
}

type quicclient struct {
	*qconn

	session quic.Session

	nr int
	nw int

	t *testing.T

	ctx    context.Context
	cancel context.CancelFunc
}

// abstraction to make this look like a net.Conn
type qconn struct {
	quic.Stream
	s quic.Session
}

// qAddr is defined in quicdial.go
func (qc *qconn) LocalAddr() net.Addr {
	return &qAddr{
		a:  qc.s.LocalAddr(),
		id: qc.StreamID(),
	}
}

func (qc *qconn) RemoteAddr() net.Addr {
	return &qAddr{
		a:  qc.s.RemoteAddr(),
		id: qc.StreamID(),
	}
}

func newQuicClient(network, addr string, tcfg *tls.Config, t *testing.T) *quicclient {
	assert := newAsserter(t)
	ctx, cancel := context.WithCancel(context.Background())

	d, err := quic.DialAddrContext(ctx, addr, tcfg, &quic.Config{})
	assert(err == nil, "can't dial quic %s: %s", addr, err)

	st := d.ConnectionState()
	t.Logf("mock quic client: connected to %s [%s]\n", addr, st.ServerName)

	fd, err := d.OpenStream()
	assert(err == nil, "can't open quic stream to %s: %s", addr, err)

	t.Logf("mock quic client: connected to %s\n", addr)
	qc := &qconn{
		Stream: fd,
		s:      d,
	}

	q := &quicclient{
		qconn:   qc,
		session: d,
		t:       t,
		ctx:     ctx,
		cancel:  cancel,
	}

	return q
}

func (q *quicclient) start(n int) {
	assert := newAsserter(q.t)
	done := q.ctx.Done()
	addr := q.RemoteAddr().String()
	from := fmt.Sprintf("%s-%s", q.LocalAddr().String(), addr)

	defer func() {
		q.cancel()
		q.Close()
		q.t.Logf("mock quic client: closing conn %s\n", from)
	}()

	buf := make([]byte, IOSIZE)
	rand.Read(buf)
	fd := q.qconn

	var sumr, csuma [sha256.Size]byte

	h := sha256.New()
	for i := 0; i < n; i++ {
		nw, err := writefull(fd, buf)
		select {
		case <-done:
			return
		default:
		}
		assert(err == nil, "%s: write err: %s", from, err)
		assert(nw == len(buf), "%s: partial write, exp %d, saw %d", from, len(buf), nw)

		q.nw += nw

		h.Reset()
		h.Write(buf)
		suma := h.Sum(csuma[:0])

		//c.t.Logf("%s: %d: TX %d [%x]\n", from, i, nw, suma[:])

		nr, err := readfull(fd, sumr[:])
		select {
		case <-done:
			return
		default:
		}

		if errors.Is(err, io.EOF) || nr == 0 {
			q.t.Logf("%s: EOF? nr %d\n", from, nr)
			return
		}
		assert(err == nil, "%s: read err: %s", from, err)
		assert(nr == len(sumr[:]), "%s: partial read, exp %d, saw %d", from, len(sumr[:]), nr)

		assert(byteEq(suma[:], sumr[:]), "%s: cksum mismatch;\nexp %x\nsaw %x", from, suma[:], sumr[:])
		inc(buf)
		q.nr += len(sumr[:])
		//c.t.Logf("%s: TX %d, RX %d\n", addr, nw, len(sumr[:]))
	}
	return
}

func (q *quicclient) stop() {
	q.cancel()
	q.Close()
}

type pki struct {
	ca     *x509.Certificate
	cakey  *ecdsa.PrivateKey
	serial *big.Int
}

func newPKI() (*pki, error) {
	// Serial number
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	// Generate a EC Private Key
	eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: can't generate ECC P256 key: %s", err)
	}

	pubkey := eckey.Public().(*ecdsa.PublicKey)
	akid := cksum(pubkey)

	now := time.Now().UTC()

	subj := pkix.Name{
		Country:            []string{"USA"},
		Organization:       []string{"mock CA"},
		OrganizationalUnit: []string{"mock CA OU"},
		CommonName:         "Mock CA",
	}

	// Create the request template
	template := x509.Certificate{
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		PublicKeyAlgorithm:    x509.ECDSA,
		SerialNumber:          serial,
		Subject:               subj,
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(5 * time.Minute),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,

		SubjectKeyId:   akid,
		AuthorityKeyId: akid,

		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	// self-sign the certificate authority
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, pubkey, eckey)
	if err != nil {
		return nil, fmt.Errorf("ca: can't create root cert: %s", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	p := &pki{
		ca:     cert,
		cakey:  eckey,
		serial: big.NewInt(0).Set(cert.SerialNumber),
	}

	return p, nil
}

func (p *pki) ServerCert(nm string, ips string) (tls.Certificate, error) {
	if i := strings.LastIndex(ips, ":"); i > 0 {
		ips = ips[:i]
	}
	ip := net.ParseIP(ips)
	if ip == nil {
		return tls.Certificate{}, fmt.Errorf("can't parse IP '%s'", ips)
	}

	return p.newCert(nm, ip, true)
}

func (p *pki) ClientCert(nm string) (tls.Certificate, error) {
	return p.newCert(nm, nil, false)
}

func (p *pki) newSerial() *big.Int {
	n := big.NewInt(0).Add(p.serial, big.NewInt(1))
	p.serial = n
	return n
}

// issue a new server cert
func (p *pki) newCert(nm string, ip net.IP, isServer bool) (tls.Certificate, error) {
	var tcert tls.Certificate

	// Generate a EC Private Key
	eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tcert, fmt.Errorf("can't generate ECC P256 key: %s", err)
	}

	var val []byte
	var keyUsage x509.KeyUsage
	var extKeyUsage x509.ExtKeyUsage
	var ipaddrs []net.IP

	if isServer {
		// nsCert = Client
		val, err = asn1.Marshal(asn1.BitString{Bytes: []byte{0x40}, BitLength: 2})
		if err != nil {
			return tcert, fmt.Errorf("can't marshal nsCertType: %s", err)
		}
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment
		extKeyUsage = x509.ExtKeyUsageServerAuth
	} else {

		// nsCert = Client
		val, err = asn1.Marshal(asn1.BitString{Bytes: []byte{0x80}, BitLength: 2})
		if err != nil {
			return tcert, fmt.Errorf("can't marshal nsCertType: %s", err)
		}
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
		extKeyUsage = x509.ExtKeyUsageClientAuth
	}

	if len(ip) > 0 {
		ipaddrs = []net.IP{ip}
	}
	pubkey := eckey.Public().(*ecdsa.PublicKey)
	skid := cksum(pubkey)
	now := time.Now().UTC()
	subj := pkix.Name{
		Country:            []string{"USA"},
		Organization:       []string{"mock cert"},
		OrganizationalUnit: []string{"mock cert OU"},
		CommonName:         nm,
	}

	csr := &x509.Certificate{
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		PublicKeyAlgorithm:    x509.ECDSA,
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(5 * time.Minute),
		SerialNumber:          p.newSerial(),
		Issuer:                p.ca.Subject,
		Subject:               subj,
		BasicConstraintsValid: true,

		SubjectKeyId: skid,

		DNSNames:    []string{nm},
		IPAddresses: ipaddrs,

		KeyUsage:    keyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{extKeyUsage},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1},
				Value: val,
			},
		},
	}

	// Sign with CA's private key
	cn := subj.CommonName
	der, err := x509.CreateCertificate(rand.Reader, csr, p.ca, pubkey, p.cakey)
	if err != nil {
		return tcert, fmt.Errorf("server cert '%s' can't be created: %s", cn, err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	tcert.Certificate = append(tcert.Certificate, der)
	tcert.Leaf = cert
	tcert.PrivateKey = eckey

	return tcert, nil
}

func newSerial() (*big.Int, error) {
	min := big.NewInt(1)
	min.Lsh(min, 127)

	max := big.NewInt(1)
	max.Lsh(max, 130)

	for {
		serial, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, fmt.Errorf("ca: can't generate serial#: %s", err)
		}

		if serial.Cmp(min) > 0 {
			return serial, err
		}
	}
}

// hash publickey; we use it as a salt for encryption and also SubjectKeyId
func cksum(pk *ecdsa.PublicKey) []byte {
	pm := elliptic.Marshal(pk.Curve, pk.X, pk.Y)
	return hash(pm)
}

func hash(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}

func inc(b []byte) []byte {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] > 0 {
			break
		}
	}

	return b
}
