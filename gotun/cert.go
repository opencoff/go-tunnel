// cert.go -- load certs and keys; this is largely a copy of crypto/tls.go
//
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// Changes made by Sudhi Herle:
//   * add password support for loading private keys
//
// Notes:
// ======
// * There is no easy way to load a cert + encrypted key in go.
//   This file attempts to remedy that.
//
// * It has no dependency on the method of entering the password.
//
// * Only this file is licensed under different terms as above.

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
)

// LoadX509KeyPair reads and parses a public/private key pair from a pair
// of files. If the supplied password is non-empty, it is used to decrypt
// the keyfile. The files must contain PEM encoded data. The certificate file
// may contain intermediate certificates following the leaf certificate to
// form a certificate chain. On successful return, Certificate.Leaf will
// be nil because the parsed form of the certificate is not retained.
func LoadX509KeyPair(certFile, keyFile, passwd string) (tls.Certificate, error) {
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	return X509KeyPair(certBytes, keyBytes, passwd)
}

// X509KeyPair parses a public/private key pair from a pair of
// PEM encoded data. On successful return, Certificate.Leaf will be nil because
// the parsed form of the certificate is not retained.
func X509KeyPair(certBytes, keyBytes []byte, passwd string) (tls.Certificate, error) {
	fail := func(err error) (tls.Certificate, error) { return tls.Certificate{}, err }

	var cert tls.Certificate
	var skippedBlockTypes []string
	for {
		var certPem *pem.Block
		certPem, certBytes = pem.Decode(certBytes)
		if certPem == nil {
			break
		}
		if certPem.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certPem.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certPem.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return fail(errors.New("tls: failed to find any PEM data in certificate input"))
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return fail(errors.New("tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched"))
		}
		return fail(fmt.Errorf("tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
	}

	// XXX Why do we pick Certificate[0]? Shouldn't we find the right cert matching the
	// privkey?

	skippedBlockTypes = skippedBlockTypes[:0]
	var keyPem *pem.Block
	for {
		keyPem, keyBytes = pem.Decode(keyBytes)
		if keyPem == nil {
			if len(skippedBlockTypes) == 0 {
				return fail(errors.New("tls: failed to find any PEM data in key input"))
			}
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				return fail(errors.New("tls: found a certificate rather than a key in the PEM for the private key"))
			}
			return fail(fmt.Errorf("tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
		}
		if keyPem.Type == "PRIVATE KEY" || strings.HasSuffix(keyPem.Type, " PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyPem.Type)
	}

	// We don't need to parse the public key for TLS, but we so do anyway
	// to check that it looks sane and matches the private key.
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fail(err)
	}

	var rawkey []byte = keyPem.Bytes

	if x509.IsEncryptedPEMBlock(keyPem) {
		rawkey, err = x509.DecryptPEMBlock(keyPem, []byte(passwd))
		if err != nil {
			return fail(err)
		}
	}

	cert.PrivateKey, err = parsePrivateKey(rawkey)
	if err != nil {
		return fail(err)
	}

	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if pub.N.Cmp(priv.N) != 0 {
			return fail(errors.New("tls: private key does not match public key"))
		}
	case *ecdsa.PublicKey:
		priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return fail(errors.New("tls: private key does not match public key"))
		}
	default:
		return fail(errors.New("tls: unknown public key algorithm"))
	}

	return cert, nil
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}
