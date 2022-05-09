// lexer.go -- lexical scanner for the config file
//
// (c) 2018 Sudhi Herle
//
// License: GPLv2
//

package config

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// TokenType denotes one of the scanned tokens.
type TokenType int

const (
	ILLEGAL TokenType = iota

	EOF

	// reserved Keywords
	keywordBegin

	LOG
	CONFDIR

	UID
	GID

	LISTEN
	CONNECT

	QUIC
	TCP
	UDP
	TLS

	ACL
	TIMEOUT
	RATELIMIT
	BIND
	READ
	WRITE
	ALLOW
	DENY
	SOCKS
	PER_IP
	CACHE

	PKI
	CERT
	KEY
	CA
	CLIENTCA

	PROXYPROTO


	// end of reserved keywords
	keywordEnd

	OPENPAREN
	CLOSEPAREN

	// End of logical line
	// a sequence of two consecutive \n constitutes
	// end of logical line
	EOL

	// Identifiers, words, IP addr etc.
	STRING
)

// keep this in the same order as the list above
// The keywords are between keywordBegin and keywordEnd
var reservedWordlist = []string{
	"log",
	"confdir",

	"uid",
	"gid",

	"listen",
	"connect",

	"quic",
	"tcp",
	"udp",
	"tls",

	"acl",
	"timeout",
	"ratelimit",
	"bind",
	"read",
	"write",
	"allow",
	"deny",
	"socks",
	"per-ip",
	"cache",

	"pki",
	"cert",
	"key",
	"ca",
	"client-ca",

	"proxy-proto",
}

var reservedWords map[string]TokenType

func init() {
	reservedWords = make(map[string]TokenType)

	for i, w := range reservedWordlist {
		reservedWords[w] = TokenType(i + int(keywordBegin) + 1)
	}
}

const eof rune = rune(0)

// Stringer interface implementation for TokenType
func (t TokenType) String() string {
	if t > keywordBegin && t < keywordEnd {
		j := int(t) - int(keywordBegin) - 1
		s := reservedWordlist[j]
		return strings.ToUpper(s)
	}

	switch t {
	case EOF:
		return "EOF"
	case OPENPAREN:
		return "OPENPAREN"
	case CLOSEPAREN:
		return "CLOSEPAREN"
	case STRING:
		return "STRING"
	case EOL:
		return "EOL"
	default:
		return fmt.Sprintf("TOK_%d", int(t))
	}
}

// Scanner holds the lexical scanner's state.
type Scanner struct {
	r *bufio.Reader

	ch   rune
	tok  Token
	line int

	// set to true if the prev char we saw was a newline
	// needed to detect end-of-logical line
	prevNL bool
}

// Token represents a scanned lexical token.
type Token struct {
	Type TokenType   // type of scanned token
	Text string      // text corresponding to the token
	Line int         // line where token was found
}

// Stringer interface implementation for Token
func (t Token) String() string {
	return fmt.Sprintf("%s [%s]", t.Type, t.Text)
}

// NewScanner returns a new instance of the scanner that reads from 'r'
func NewScanner(r io.Reader) *Scanner {
	s := &Scanner{
		r:    bufio.NewReader(r),
		line: 1,
	}

	ch := s.read()
	if ch == '\uFEFF' {
		ch = s.read()
	}
	s.ch = ch
	return s
}

// Scan and return the next Token
func (s *Scanner) Scan() Token {
	return s.scan()
}

// Next returns nil and false on EOF and return
// true and token otherwise.
func (s *Scanner) Next() (*Token, bool) {
	s.tok = s.Scan()
	if s.tok.Type == EOF {
		return nil, false
	}
	return &s.tok, true
}


func (s *Scanner) String() string {
	return fmt.Sprintf("%d: tok %s, prevNl: %v, ch: %q", s.line, s.tok, s.prevNL, s.ch)
}

func (s *Scanner) scan() (t Token) {
	ch := s.next()

redo:
	for ; ch != eof; ch = s.next() {
		if ch == ' ' {
			continue
		}
		if ch == '\n' {
			if s.prevNL {
				return tok(EOL, string(ch), s.line)
			}
			continue
		}
		break
	}


	switch ch {
	case eof:
		return tok(EOF, "", s.line)
	case '{':
		t = tok(OPENPAREN, string(ch), s.line)
		return t
	case '}':
		t = tok(CLOSEPAREN, string(ch), s.line)
		return t

	case '#':
		ch = s.skipComment(ch)
		goto redo

		// If we handled quoted strings, we'd do it here.
		// case '"': // quoted strings ...

	default:
		// fall through below.
	}

	n := s.line
	w := s.scanWord(ch)
	l := strings.ToLower(w)
	if tt, ok := reservedWords[l]; ok {
		t = tok(tt, w, n)
		return t
	}
	t = tok(STRING, w, n)
	return t
}

// read next unicode character and return it; fill the next rune from the
// input stream.  Return eof if at end of source
func (s *Scanner) next() rune {
	ch := s.peek()

	if ch == eof {
		s.prevNL = false
		return eof
	}

	s.ch = s.read()
	if ch == '\n' {
		s.line++
		if s.peek() == '\n' {
			s.ch = s.read()
			s.line++
			s.prevNL = true
		}
	} else {
		s.prevNL = false
	}

	return ch
}

// Return next run in input without advancing the scanner.
func (s *Scanner) peek() rune {
	return s.ch
}

// Read next unicode character from the input buffer.
// Return special EOF rune at end of file
func (s *Scanner) read() rune {
	ch, _, err := s.r.ReadRune()
	if err != nil {
		return eof
	}
	return ch
}

// skip comments and return last rune read
func (s *Scanner) skipComment(ch rune) rune {
	for ch = s.next(); ch != eof; ch = s.next() {
		if ch == '\n' {
			break
		}
	}

	return ch
}

// scan the next word (delimited by whitespace or LF)
func (s *Scanner) scanWord(ch rune) string {
	var b strings.Builder

	b.WriteRune(ch)

	for ch = s.next(); ch != eof; ch = s.next() {
		if ch == ' ' || ch == '\n' {
			break
		}
		b.WriteRune(ch)
	}

	return b.String()
}

// handy constructor for a new token
func tok(t TokenType, s string, n int) Token {
	return Token{
		Type: t,
		Text: s,
		Line: n,
	}
}
