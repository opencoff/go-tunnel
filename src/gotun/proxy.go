// proxy.go -- http proxy server logic
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

/*
import (
	//"io"
	//"fmt"
	"context"
	"net"
	"sync"
	"time"
	//"strings"
	//"net/url"
	"net/http"

	"lib/httproxy"

	L "github.com/opencoff/go-lib/logger"
	"github.com/opencoff/go-lib/ratelimit"
)

// XXX These should be in a config file
const dialerTimeout = 30       // seconds
const dialerKeepAlive = 30     // seconds
const tlsHandshakeTimeout = 30 // seconds
const readTimeout = 20         // seconds
const readHeaderTimeout = 10   // seconds
const writeTimeout = 60        // seconds; 3x read timeout. Enough time?
const flushInterval = 10       // seconds
const perHostIdleConn = 1024   // XXX too big?
const idleConnTimeout = 120    // seconds

const defaultIOSize = 8192 // bytes

type HTTPProxy struct {
	*net.TCPListener

	// listen address
	conf *ListenConf

	stop chan bool
	wg   sync.WaitGroup

	grl *ratelimit.Ratelimiter
	prl *ratelimit.PerIPRatelimiter

	// logger
	log  *L.Logger
	ulog *L.Logger

	// Transport for downstream connection
	tr *http.Transport

	srv *http.Server
}

func NewHTTPProxy(lc *ListenConf, log, ulog *L.Logger) (Proxy, error) {
	addr := lc.Listen
	la, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		die("Can't resolve %s: %s", addr, err)
	}

	ln, err := net.ListenTCP("tcp", la)
	if err != nil {
		die("Can't listen on %s: %s", addr, err)
	}

	// create a sub-logger with the listener's prefix.
	log = log.New(ln.Addr().String(), 0)

	p := &HTTPProxy{conf: lc, log: log, ulog: ulog, stop: make(chan bool)}

	// Conf file specifies ratelimit as N conns/sec
	rl, err := ratelimit.New(lc.Ratelimit.Global, 1)
	if err != nil {
		die("%s: Can't create global ratelimiter: %s", addr, err)
	}

	pl, err := ratelimit.NewPerIPRatelimiter(lc.Ratelimit.PerHost, 1)
	if err != nil {
		die("%s: Can't create per-host ratelimiter: %s", addr, err)
	}

	dialer := &net.Dialer{Timeout: dialerTimeout * time.Second,
		KeepAlive: dialerKeepAlive * time.Second,
	}
	tr := &http.Transport{Dial: dialer.Dial,
		TLSHandshakeTimeout: tlsHandshakeTimeout * time.Second,
		MaxIdleConnsPerHost: perHostIdleConn,
		IdleConnTimeout:     idleConnTimeout * time.Second,
	}

	stdlog := log.StdLogger()

	rp := &httproxy.Proxy{
		Transport:     tr,
		FlushInterval: flushInterval * time.Second,
		ErrorLog:      stdlog,
		// XXX BufferPool: make a new buffer pool
		Director:   p.validateReq,
		BufferPool: newBufPool(defaultIOSize),
	}

	s := &http.Server{
		Addr:              addr,
		Handler:           rp,
		ReadTimeout:       readTimeout * time.Second,
		ReadHeaderTimeout: readHeaderTimeout * time.Second,
		WriteTimeout:      writeTimeout * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB. Sufficient?
		ErrorLog:          stdlog,
	}
	p.TCPListener = ln
	p.srv = s
	p.grl = rl
	p.prl = pl

	return p, nil
}

// Start listener
func (p *HTTPProxy) Start() {

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		lc := p.conf

		p.log.Info("Starting gotun ..")
		p.log.Info("Ratelimit: Global %d req/s, Per-host: %d req/s",
			lc.Ratelimit.Global, lc.Ratelimit.PerHost)

		// This calls our over-ridden "Accept()" method. Finally, it
		// will call srv.Handler.ServeHTTP() -- ie, the reverse
		// proxy implementation.
		p.srv.Serve(p)
	}()
}

// Stop server
// XXX Hijacked Websocket conns are not shutdown here
func (p *HTTPProxy) Stop() {
	close(p.stop)

	cx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	p.srv.Shutdown(cx)

	p.wg.Wait()
	p.log.Info("gotun shutdown")
}

// Accept() new socket connections from the listener
// Note:
//	 - HTTPProxy is also a TCPListener
//	 - http.Server.Serve() is passed a Listener object (p)
//	 - And, Serve() calls Accept() before starting service
//	   go-routines
func (p *HTTPProxy) Accept() (net.Conn, error) {
	ln := p.TCPListener
	for {
		ln.SetDeadline(time.Now().Add(2 * time.Second))

		nc, err := ln.Accept()

		select {
		case _ = <-p.stop:
			if err == nil {
				nc.Close()
			}
			return nil, &errShutdown

		default:
		}

		if err != nil {
			if ne, ok := err.(net.Error); ok {
				if ne.Timeout() || ne.Temporary() {
					continue
				}
			}
			return nil, err
		}

		// First enforce a global ratelimit
		if p.grl.Limit() {
			p.log.Debug("global ratelimit reached: %s", nc.RemoteAddr().String())
			nc.Close()
			continue
		}

		// Then a per-host ratelimit
		if p.prl.Limit(nc.RemoteAddr()) {
			p.log.Debug("per-host ratelimit reached: %s", nc.RemoteAddr().String())
			nc.Close()
			continue
		}

		if !AclOK(p.conf, nc) {
			p.log.Debug("ACL failure: %s", nc.RemoteAddr().String())
			nc.Close()
			continue
		}

		return nc, nil
	}
}

// Authentication and req modification callback from the reverse
// proxy.
// XXX For now, we assume everything is OK.
func (p *HTTPProxy) validateReq(r *http.Request) (int, error) {

	// XXX Change r.URL to point to new internal host, fixup Host
	// headers and so on ..
	return http.StatusOK, nil
}

var errShutdown = proxyErr{Err: "server shutdown", temp: false}

type proxyErr struct {
	error
	Err  string
	temp bool // is temporary error?
}

// net.Error interface implementation
func (e *proxyErr) String() string  { return e.Err }
func (e *proxyErr) Temporary() bool { return e.temp }
func (e *proxyErr) Timeout() bool   { return false }

// simple buffer pool
type bufPool struct {
	p sync.Pool
}

func newBufPool(siz int) httproxy.BufferPool {
	b := &bufPool{
		p: sync.Pool{
			New: func() interface{} {
				return make([]byte, siz)
			},
		},
	}
	return b
}

func (b *bufPool) Get() []byte {
	return b.p.Get().([]byte)
}

func (b *bufPool) Put(z []byte) {
	b.p.Put(z)
}
*/

// vim: noexpandtab:
