// lexer.go -- lexical scanner for the config file
//
// (c) 2018 Sudhi Herle
//
// License: GPLv2
//


package config


import (
	"testing"
	"bytes"
)


type elt struct {
	ty TokenType
	lit string
}


var tokList = []elt{
	{EOF, "# comment"},
	{EOF, "# comment\n"},
	{EOL, "\n\n"},
	{EOL, "# comment\n\n"},
	{LOG, "log"},
	{CONFDIR, "confdir"},
	{UID, "uid"},
	{GID, "gid"},
	{LISTEN, "listen"},
	{CONNECT, "connect"},
	{QUIC, "quic"},
	{TCP, "tcp"},
	{UDP, "udp"},
	{TLS, "tls"},
	{ACL, "acl"},
	{TIMEOUT, "timeout"},
	{BIND, "bind"},
	{READ, "read"},
	{WRITE, "write"},
	{ALLOW, "allow"},
	{DENY, "deny"},
	{SOCKS, "socks"},
	{PER_IP, "per-ip"},
	{CACHE, "cache"},
	{PKI, "pki"},
	{CERT, "cert"},
	{KEY, "key"},
	{CA, "ca"},
	{CLIENTCA, "client-ca"},
	{PROXYPROTO, "proxy-proto"},
}

type elts struct {
	ty []TokenType
	lit string
}

var tokList2 = []elts{
	{[]TokenType{LISTEN, QUIC, STRING, PKI, STRING, TIMEOUT, STRING}, "listen quic eth0:8080 pki PKI-A timeout TIMEOUT-B"},
}

func TestLexerSimple(t *testing.T) {
	assert := newAsserter(t)

	for _, e := range tokList {
		b := bytes.NewReader([]byte(e.lit))
		s := NewScanner(b)

		tok := s.Scan()
		assert(tok.Type == e.ty, "%q: tok mismatch: exp %s, saw %s", e.lit, e.ty, tok.Type)
	}

}


func TestLexerLines(t *testing.T) {
	assert := newAsserter(t)

	for _, e := range tokList2 {
		b := bytes.NewReader([]byte(e.lit))
		s := NewScanner(b)

		exp := e.ty
		i := 0
		for tok := s.Scan(); tok.Type != EOF; tok = s.Scan() {
			assert(tok.Type == exp[i], "%q: exp %s saw %s", e.lit, exp[i], tok.Type)
			i++
		}
	}
}
