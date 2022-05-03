// parser.go -- config file parser
//
// (c) 2018 Sudhi Herle
//
// License: GPLv2
//
// This is written as a simple recursive-descent parser with a
// one token lookahead.

package cfg // lib/cfg

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"path"

	"github.com/opencoff/go-ratelimit"
)

// Parser abstracts the parser state.
type Parser struct {
	s *Scanner

	// cur token
	cur Token

	// lookahead token
	peek Token
}


// NewParser creates a new instance of the parser from a given io.Reader
func NewParser(r io.Reader) *Parser {
	p := &Parser{
		s: NewScanner(r),
	}

	p.cur = p.s.Scan()
	p.peek = p.s.Scan()
	return p
}

// Parse parses the input stream and yields a parsed config struct.
// On errors, 'c' is nil and 'err' is appropriately set.
func (p *Parser) Parse() (c *Config, err error) {

	// we use panic at the lowest levels of parsing to abort a long chain of 'return'.
	// we catch the panic here and set 'err' in the outer scope.
	defer func() {
		if e := recover(); e != nil {
			if err = e.(error); err != nil {
				c = nil
			}
		}
	}()

	c = &Config{
	}

	//p.dump("start")
	t := p.cur
	for t.Type != EOF {
		//p.dump("top-level")
		switch t.Type {
		case CONFDIR:
			p.parseConfDir(c)

		case LOG:
			p.parseLog(c)

		case UID:
			p.parseDePriv(c)

		case LISTEN:
			p.parseListen(c)

		case RATELIMIT:
			p.parseRatelimit(c)

		case ACL:
			p.parseAcl(c)

		case PKI:
			p.parsePki(c)


		case EOL:
			// nothing to do

		default:
			p.errorf("Unknown token type %s (%s)", t.Type, t.Text)
		}
		t = p.next()
	}

	return
}


func (p *Parser) parseConfDir(c *Config) {
	t = p.expect(STRING)
	c.ConfDir = path.Clean(t.Text)
}

func (p *Parser) parseLog(c *Config) {
	t = p.expect(STRING)
	c.LogName = t.Text
	if p.peekNext(STRING) {
		t = p.next()
		c.LogLevel = t.Text
	}
	return
}

// expect expects the _next_ token to be 'tok'
func (p *Parser) expect(tok TokenType) Token {
	t = p.next()
	if t.Type != tok {
		p.errorf("expected '%s', saw '%s' <%s>", tok, t.Type, t.Text)
	}
	return t
}

func (p *Parser) parseDePriv(c *Config) {
}

func (p *Parser) parseListen(c *Config) {
}

func (p *Parser) parseRatelimit(c *Config) {
}

func (p *Parser) parseAcl(c *Config) {
}

func (p *Parser) parsePki(c *Config) {
}


// peek at the lookahead and if it matches 't', make it the current token
func (p *Parser) maybePeek(t TokenType) bool {
	if p.peek.Type == t {
		p.next()
		return true
	}
	return false
}

// expect next token to be 't'
func (p *Parser) matchNext(t TokenType) Token {
	n := p.next()
	if n.Type == t {
		return n
	}
	p.errorf("expected '%s', saw %s <%s>", t, p.cur.Type, p.cur.Text)
	return n
}

// expect current to be token-type 't'
func (p *Parser) match(t TokenType) {
	if p.cur.Type == t {
		return
	}
	p.errorf("expected '%s', saw %s", t, p.cur.Type)
}

// Advance the token stream
func (p *Parser) next() Token {
	p.cur = p.peek
	p.peek = p.s.Scan()
	return p.cur
}

func (p *Parser) errorf(f string, a ...interface{}) {
	pe := &ParseError{
		Token:   p.cur,
		Message: fmt.Sprintf(f, a...),
	}

	// top level function will call recover()
	panic(pe)
}

type ParseError struct {
	Token   Token
	Message string
}

// error interface
func (pe ParseError) Error() string {
	return fmt.Sprintf("%d: syntax error: %s", pe.Token.Line, pe.Message)
}

func (p *Parser) dump(s string) {
	fmt.Printf("%s: cur=%s, peek=%s\n", s, p.cur, p.peek)
}

func (p *Parser) newZone(c *Config, nm string) *Zone {
	z, ok := c.Zones[nm]
	if !ok {
		z = &Zone{
			Name:   nm,
		}
		rl, err := ratelimit.New(0, 1)
		if err != nil {
			p.errorf("can't create default ratelimiter: %s", err)
		}

		pl, err := ratelimit.NewPerIP(0, 1, 4)
		if err != nil {
			p.errorf("can't create default Per-IP ratelimiter: %s", err)
		}

		z.GRl = rl
		z.HRl = pl
		c.Zones[nm] = z
	}
	return z
}

// Return true if rr is a standalone name (no '.') OR it is a subdomain of zname.
// And false otherwise.
func isSubDomainOf(rr, zname string) (string, bool) {
	if i := strings.IndexRune(rr, '.'); i > 0 {
		return rr, strings.HasSuffix(rr, zname)
	}
	return rr + "." + zname, true
}
