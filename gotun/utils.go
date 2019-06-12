// utils.go - misc utilities used by HTTP and Socks proxies
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// Return true if the err represents a TCP PIPE or RESET error
func isReset(err error) bool {
	if oe, ok := err.(*net.OpError); ok {
		if se, ok := oe.Err.(*os.SyscallError); ok {
			if se.Err == syscall.EPIPE || se.Err == syscall.ECONNRESET {
				return true
			}
		}
	}
	return false
}

// Format a time duration
func format(t time.Duration) string {
	u0 := t.Nanoseconds() / 1000
	ma, mf := u0/1000, u0%1000

	if ma == 0 {
		return fmt.Sprintf("%3.3d us", mf)
	}

	return fmt.Sprintf("%d.%3.3d ms", ma, mf)
}

// Return true if the new connection 'conn' passes the ACL checks
// Return false otherwise
func AclOK(cfg *ListenConf, conn net.Conn) bool {
	h, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		//p.log.Debug("%s can't extract TCP Addr", conn.RemoteAddr().String())
		return false
	}

	for _, n := range cfg.Deny {
		if n.Contains(h.IP) {
			return false
		}
	}

	if len(cfg.Allow) == 0 {
		return true
	}

	for _, n := range cfg.Allow {
		if n.Contains(h.IP) {
			return true
		}
	}

	return false
}
