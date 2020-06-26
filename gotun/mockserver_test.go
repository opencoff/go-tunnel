// mockserver_test.go - mock servers


package main

import (
	"fmt"
	"net"
	"time"
	"math/big"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"testing"
)


type tcpserver struct {
}

func newTCPServer(network, addr string, secure bool, t *testing.T) *tcpserver {
	return nil
}

type quicserver struct {
}


type pki struct {
	ca  *x509.Certificate
	cakey *ecdsa.PrivateKey
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
		Country: []string{"USA"},
		Organization: []string{"mock CA"},
		OrganizationalUnit: []string{"mock CA OU"},
		CommonName: "Mock CA",
	}

	// Create the request template
	template := x509.Certificate{
		SignatureAlgorithm:    x509.ECDSAWithSHA512,
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
		ca: cert,
		cakey: eckey,
		serial: big.NewInt(0).Set(cert.SerialNumber),
	}

	return p, nil
}

func (p *pki) ServerCert(nm string, ip net.IP) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	return p.newCert(nm, ip, true)
}

func (p *pki) ClientCert(nm string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	return p.newCert(nm, nil, false)
}

func (p *pki) newSerial() *big.Int {
	n := big.NewInt(0).Add(p.serial, big.NewInt(1))
	p.serial = n
	return n
}


// issue a new server cert
func (p *pki) newCert(nm string, ip net.IP, isServer bool) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// Generate a EC Private Key
	eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("can't generate ECC P256 key: %s", err)
	}

	var val []byte
	var keyUsage x509.KeyUsage
	var extKeyUsage x509.ExtKeyUsage
	var ipaddrs []net.IP

	if isServer {
		// nsCert = Client
		val, err = asn1.Marshal(asn1.BitString{Bytes: []byte{0x40}, BitLength: 2})
		if err != nil {
			return nil, nil, fmt.Errorf("can't marshal nsCertType: %s", err)
		}
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment
		extKeyUsage = x509.ExtKeyUsageServerAuth
	} else {

		// nsCert = Client
		val, err = asn1.Marshal(asn1.BitString{Bytes: []byte{0x80}, BitLength: 2})
		if err != nil {
			return nil, nil, fmt.Errorf("can't marshal nsCertType: %s", err)
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
		Country: []string{"USA"},
		Organization: []string{"mock CA"},
		OrganizationalUnit: []string{"mock CA OU"},
		CommonName: nm,
	}

	csr := &x509.Certificate{
		SignatureAlgorithm:    x509.ECDSAWithSHA512,
		PublicKeyAlgorithm:    x509.ECDSA,
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(5 * time.Minute),
		SerialNumber:          p.newSerial(),
		Issuer:                p.ca.Subject,
		Subject:               subj,
		BasicConstraintsValid: true,

		SubjectKeyId: skid,

		DNSNames:       []string{nm},
		IPAddresses:    ipaddrs,

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
		return nil, nil, fmt.Errorf("server cert '%s' can't be created: %s", cn, err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	return cert, eckey, nil
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
	panic("can't gen new CA serial")
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
