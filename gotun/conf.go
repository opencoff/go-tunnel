// conf.go -- config file processing.
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	yaml "gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"net"
	"path"
	"strings"
)

// List of config entries
type Conf struct {
	Logging  string        `yaml:"log"`
	LogLevel string        `yaml:"loglevel"`
	Uid      string        `yaml:"uid"`
	Gid      string        `yaml:"gid"`
	ConfDir  string        `yaml: config-dir"`
	Listen   []*ListenConf `yaml:"listen"`
}

type ListenConf struct {
	Addr    string   `yaml:"address"`
	Allow   []subnet `yaml:"allow"`
	Deny    []subnet `yaml:"deny"`
	Timeout Timeouts `yaml:"timeout"`

	Quic bool `yaml:"quic"`
	// optional TLS info; will listen on TLS socket if provided
	Tls *TlsServerConf `yaml:"tls"`

	// rate limit -- perhost and global
	Ratelimit *RateLimit `yaml:"ratelimit"`

	Connect ConnectConf `yaml:"connect"`

	// parsed Server & client configs
	serverCfg *tls.Config
	clientCfg *tls.Config
}

type RateLimit struct {
	Global  int `yaml:"global"`
	PerHost int `yaml:"perhost"`
}

// An IP/Subnet
type subnet struct {
	net.IPNet
}

// List of various timeouts in units of seconds
type Timeouts struct {
	Connect int
	Read    int
	Write   int
}

// Connect info
type ConnectConf struct {
	Addr          string `yaml:"address"`
	Bind          string
	ProxyProtocol string
	Quic          bool           `yaml:"quic"`
	Tls           *TlsClientConf `yaml:"tls"`
}

// Tls Conf
type TlsServerConf struct {
	Quic       bool
	Sni        string
	Cert       string
	Key        string
	ClientCert string

	// this can be a file or dir. It is needed to verify the client provided
	// certificate.
	ClientCA string
}

// Tls client conf
type TlsClientConf struct {
	Quic bool

	// This can be a file or a dir. This is for verifying the
	// server provided certificate.
	Ca   string
	Cert string
	Key  string

	Server string `yaml:"servername"`

	tlsCfg *tls.Config
}

// Parse config file in YAML format and return
func ReadYAML(fn string) (*Conf, error) {
	yml, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("can't read config file %s: %s", fn, err)
	}

	var cfg Conf
	err = yaml.Unmarshal(yml, &cfg)
	if err != nil {
		return nil, fmt.Errorf("can't parse config file %s: %s", fn, err)
	}

	if err = validate(&cfg); err != nil {
		return nil, err
	}
	return defaults(&cfg), nil
}

// Setup sane defaults if needed
func defaults(c *Conf) *Conf {
	for _, l := range c.Listen {
		if l.Ratelimit == nil {
			l.Ratelimit = &RateLimit{}
		}
		if l.Ratelimit.Global <= 0 {
			l.Ratelimit.Global = 1000
		}
		if l.Ratelimit.PerHost <= 0 {
			l.Ratelimit.PerHost = 10
		}
		t := &l.Timeout
		if t.Connect == 0 {
			t.Connect = 5
		}
		if t.Read == 0 {
			t.Read = 30
		}

		if t.Write == 0 {
			t.Write = 30
		}

	}

	if len(c.LogLevel) == 0 {
		c.LogLevel = "INFO"
	}

	if len(c.Logging) == 0 {
		c.Logging = "SYSLOG"
	}

	return c
}

// basic sanity check on the parsed config file
func validate(conf *Conf) error {
	for _, l := range conf.Listen {
		c := &l.Connect
		if len(c.Addr) == 0 {
			return fmt.Errorf("listener %s has missing connect info", l.Addr)
		}

		i := strings.IndexByte(l.Addr, ':')
		if i < 0 {
			return fmt.Errorf("%s: listen address is missing port", l.Addr)
		}

		if i = strings.IndexByte(c.Addr, ':'); i < 0 {
			return fmt.Errorf("%s: Connect address %s is missing port", l.Addr, c.Addr)
		}
		nm := c.Addr[:i]

		switch c.ProxyProtocol {
		case "v1":
		default:
			if len(c.ProxyProtocol) > 0 {
				return fmt.Errorf("%s: no support for proxy-protocol %s", l.Addr, c.ProxyProtocol)
			}
		}
		if t := c.Tls; t != nil {
			if len(t.Ca) == 0 {
				return fmt.Errorf("%s: TLS connect requires a valid CA", l.Addr)
			}
			// if what we are connecting to is not an IP address, treat it as a
			// hostname and let crypto/tls validate hostname against the cert.
			if ip := net.ParseIP(nm); ip == nil {
				if len(t.Server) == 0 {
					t.Server = nm
				}
			}
		}

		if t := l.Tls; t != nil {
			if len(t.Sni) > 0 {
				dir := conf.Path(t.Sni)
				if !isdir(dir) {
					return fmt.Errorf("%s: TLS SNI requires a certificate dir", l.Addr)
				}
			} else {
				if len(t.Cert) == 0 || len(t.Key) == 0 {
					return fmt.Errorf("%s: TLS server requires a valid certificate & key", l.Addr)
				}
			}

			if len(t.ClientCert) > 0 {
				auth := strings.ToLower(t.ClientCert)
				switch auth {
				case "required", "optional":
					if len(t.ClientCA) == 0 {
						return fmt.Errorf("%s: TLS client-auth requires a valid CA certificate", l.Addr)
					}

				case "no", "disabled", "false":
					break

				default:
					return fmt.Errorf("%s: unknown client-auth type %s", l.Addr, t.ClientCert)
				}

				t.ClientCert = auth
			}
			l.serverCfg = l.ParseTlsServerConf(conf)
		}

		if t := c.Tls; t != nil {
			l.clientCfg = l.ParseTlsClientConf(conf)
		}
	}
	return nil
}

func (lc *ListenConf) IsQuic() bool {
	return lc.Tls != nil && lc.Quic
}

func (tc *ConnectConf) IsQuic() bool {
	return tc.Tls != nil && tc.Quic
}

// parse TLS server config
func (lc *ListenConf) ParseTlsServerConf(c *Conf) *tls.Config {
	t := lc.Tls
	cfg := &tls.Config{
		MinVersion:             tls.VersionTLS12,
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
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
	}

	// We handle SNI later when we setup the server instance.
	if len(t.Sni) == 0 {
		crt := c.Path(t.Cert)
		key := c.Path(t.Key)

		if err := c.IsFileSafe(crt); err != nil {
			die("insecure perms on %s! ..", crt)
		}

		if err := c.IsFileSafe(key); err != nil {
			die("insecure perms on %s ..", key)
		}

		cert, err := tls.LoadX509KeyPair(crt, key)
		if err != nil {
			die("%s: can't load server cert {%s, %s}: %s", lc.Addr, t.Cert, t.Key, err)
		}

		cfg.Certificates = []tls.Certificate{cert}
	}

	needCA := true
	switch t.ClientCert {
	case "required":
		cfg.ClientAuth = tls.RequireAndVerifyClientCert

	case "optional":
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
		// XXX We may have to write a VerifyPeerCertificate() callback to verify

	default:
		needCA = false
		cfg.ClientAuth = tls.NoClientCert
	}

	if needCA {
		cfg.ClientCAs = c.ReadCA(t.ClientCA)
	}

	return cfg
}

func (lc *ListenConf) ParseTlsClientConf(c *Conf) *tls.Config {
	t := lc.Connect.Tls
	cfg := &tls.Config{
		ServerName:               t.Server,
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true,
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
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
	}

	var err error

	cfg.RootCAs = c.ReadCA(t.Ca)
	if err != nil {
		die("%s: can't load TLS client CA from %s: %s", lc.Addr, t.Ca, err)
	}

	crt := c.Path(t.Cert)
	key := c.Path(t.Key)

	if err := c.IsFileSafe(crt); err != nil {
		die("insecure perms on %s! ..", crt)
	}

	if err := c.IsFileSafe(key); err != nil {
		die("insecure perms on %s ..", key)
	}

	cert, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		die("%s: can't load TLS client cert/key {%s, %s}: %s", lc.Addr, crt, key, err)
	}

	cfg.Certificates = []tls.Certificate{cert}
	if len(cfg.ServerName) == 0 {
		warn("TLS Client towards %s has no server-name; UNABLE TO VERIFY server presented cert", lc.Connect.Addr)
		cfg.InsecureSkipVerify = true
	}

	return cfg
}

func (c *Conf) ReadCA(nm string) *x509.CertPool {
	nm = c.Path(nm)
	fdv, err := c.SafeOpen(nm)
	if err != nil {
		die("can't read %s: %s", nm, err)
	}

	p := x509.NewCertPool()
	for i := range fdv {
		fd := fdv[i]
		fn := fd.Name()
		if !strings.HasSuffix(fn, ".pem") {
			fd.Close()
			continue
		}

		pem, err := ioutil.ReadAll(fd)
		if err != nil {
			fd.Close()
			die("can't read %s: %s", fn, err)
		}

		p.AppendCertsFromPEM(pem)
		fd.Close()
	}

	n := len(p.Subjects())
	if n == 0 {
		die("%s: No CA Certs!", nm)
	}

	return p
}

// Custom unmarshaler for IPNet
func (ipn *subnet) UnmarshalYAML(unm func(v interface{}) error) error {
	var s string

	// First unpack the bytes as a string. We then parse the string
	// as a CIDR
	err := unm(&s)
	if err != nil {
		return err
	}

	_, net, err := net.ParseCIDR(s)
	if err == nil {
		ipn.IP = net.IP
		ipn.Mask = net.Mask
	}
	return err
}

// turn relative paths to absolute
func (c *Conf) Path(nm string) string {
	if path.IsAbs(nm) {
		return nm
	}
	return path.Join(c.ConfDir, nm)
}

// Print config in human readable format
func (c *Conf) Dump(w io.Writer) {
	fmt.Fprintf(w, "config: %d listeners\n", len(c.Listen))

	for _, l := range c.Listen {
		fmt.Fprintf(w, "listen on %s", l.Addr)
		if t := l.Tls; t != nil {
			if len(t.Sni) > 0 {
				fmt.Fprintf(w, " with tls sni using certstore %s", t.Sni)
			} else {
				fmt.Fprintf(w, " with tls using cert %s, key %s",
					t.Cert, t.Key)
			}
			if t.ClientCert == "required" {
				fmt.Fprintf(w, " requiring client auth")
			} else if t.ClientCert == "optional" {
				fmt.Fprintf(w, " with optional client auth")
			}
		}
		c := &l.Connect
		fmt.Fprintf(w, "\n\tconnect to %s", c.Addr)
		if len(c.Bind) > 0 {
			fmt.Fprintf(w, " from %s", c.Bind)
		}
		if len(c.ProxyProtocol) > 0 {
			fmt.Fprintf(w, " using proxy-protocol %s", c.ProxyProtocol)
		}
		if t := c.Tls; t != nil {
			fmt.Fprintf(w, " using tls")
			if len(t.Cert) > 0 {
				fmt.Fprintf(w, " cert %s, key %s", t.Cert, t.Key)
			}
			fmt.Fprintf(w, " and ca-bundle %s", t.Ca)
		}
		fmt.Fprintf(w, "\n")
	}
}
