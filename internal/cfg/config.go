// config.go - representation of a parsed config file
//
// (c) 2018 Sudhi Herle
//
// License: GPLv2
//

package config

/*
import (
)


type ListenProto int

const (
	UDP ListenProto = iota
	TCP
	TLS
	QUIC
)

type ListenInfo {
	Proto ListenProto
	Addr  []net.Addr
	Acl   *Acl
	Limit *ratelimit.Limiter
	ServerTls   *tls.Config

	Timeout	 *Timeouts

	Connect	net.Addr
	IsSocks bool	// true if connect is a socks addr
	ClientTls  *tls.Config
}

type Timeouts struct {
	Connect time.Duration
	Read	time.Duration
	Write	time.Duration
}

type Acl {
	Allow []net.IPNet
	Deny  []net.IPNet
}

type Config struct {
	ConfDir	string

	LogName	string
	LogLevel string

	Uid int
	Gid int

	Listen	[]ListenInfo

	// Auxillary info needed during parsing of the config file
	aux	*auxInfo
}

// auxillary name lookup info
type auxInfo struct {
	rl  map[string]*ratelimit.Limiter
	acl map[string]*Acl
	timeout map[string]*Timeouts
	pki map[string]*tls.Config
}

type pki struct {
	Cert	string
	Key	string
	Ca	string
	clientCa string
}
*/
