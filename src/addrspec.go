// addrspec.go -- manipulate socks5 and our wire framing

package main

import (
	"hash"
	"hash/fnv"
	"net/netip"
	L "github.com/opencoff/go-logger"
)

type Proto uint8
const (
	P_TCP  Proto = 0x01
	P_UDP  Proto = 0x03
)

func (p Proto) String() string {
	switch p {
	case P_TCP:
		return "tcp"
	case P_UDP:
		return "udp"
	default:
	}
	return ""
}

type AddrType uint8
const (
	A_INVALID AddrType = 0x0
	A_IPV4    AddrType = 0x01
	A_HOST    AddrType = 0x03
	A_IPV6    AddrType = 0x04
)

type AddrSpec struct {
	Typ  AddrType
	Proto Proto
	Port  uint16
	Addr  netip.Addr
	Host  string
}

func checksum(b []byte) uint32 {
	h := fnv.New32()
	h.Write(b)
	return h.Sum32()
}


// Marshal the address+proto on the tunnel:
//    u8  proto (TCP|UDP)
//    u8  atype (v4|v6|name)
//    u16 port
//
//    u16 alen
//    u16 resv - zeroes
//
//    *u8 bytes of addr
//    u32 checksum (FNV)
//    --
//
func (a *AddrSpec) Marshal(b []byte) int {
	alen := 0
	switch a.Typ {
	case A_IPV4:
		alen = 4
	case A_IPV6:
		alen = 16
	case A_HOST:
		alen = len(a.Host)
	}

	// tot = total number of bytes encoded excluding the checksum
	tot := 4 + 4 + alen
	if len(b) < (4 + tot) {
		return 0
	}

	b[0] = a.Proto
	b[1] = a.Typ
	binary.BigEndian.PutUint16(b[2:], a.Port)
	binary.BigEndian.PutUint16(b[4:], uint16(alen))

	// resv bytes
	b[6] = 0
	b[7] = 0

	switch a.Typ {
	case A_IPV4, A_IPV6:
		sl := a.Addr.AsSlice()
		copy(b[8:], sl, alen)

	case A_HOST:
		copy(b[8:], []byte(a.Host), alen)
	}

	cs := checksum(b[:tot])
	binary.BigEndian.PutUint32(b[tot:], cs)
	return tot + 4
}


// Unmarshal address+proto from the wire
// (see wire format above)
// Return # of bytes consumed
func (a *AddrSpec) Unmarshal(b []byte) int {
	// 16 bytes is the smallest packet:
	//   - 4 bytes of proto, atype, port,
	//   - 4 bytes of alen, padding
	//   - 4 bytes of IPv4
	//   - 4 bytes of checksum
	if len(b) < 16 {
		return 0
	}

	pcsum := binary.BigEndian.Uint32(b[len(b)-4:])
	csum := checksum(b[:len(b)-4])
	if pcsum != csum {
		return 0
	}

	switch b[0] {
	// allow
	case P_TCP, P_UDP:
		a.Proto = b[0]

	// deny
	default:
		return 0
	}


	var alen int
	var port uint16
	var data []byte


	port = binary.BigEndian.Uint16(b[2:])
	alen = int(binary.BigEndian.Uint16(b[4:]))
	if len(b) < (12 + alen) {
		return 0
	}

	a.Typ = b[1]
	switch a.Typ {
	case A_IPV4, A_IPV6:
		a.Addr = netip.AddrFromSlice(b[8:])
	case A_HOST:
		a.Host = string(b[8:)
	}

	return 12+alen
}


// parseAddrSpec parses a socks5 address:port in 'abuf'
// Returns number of bytes consumed.
func (a *AddrSpec) parseAddrSpec(abuf []byte, log *L.Logger) (n int, err error) {
	var daddr []byte

	want := 0

	n += 1
	switch abuf[0] {
	case A_IPV4:
		want = 4
		daddr = abuf[1:]

	case A_HOST:
		n += 1
		want = int(abuf[1])
		daddr = abuf[2:]

	case A_IPV6:
		want = 16
		daddr = abuf[1:]

	default:
		count("bad-addrtype", 1)
		log.Debug("unknown client addrtype %#x", abuf[0])
		err = errUnsupportedAddr
		return
	}

	// 2: port#
	// 1: the addr type (abuf[0])
	if len(abuf) < (want + 2 + 1) {
		count("too-small", 1)
		log.Debug("insufficient client-conn-addr bytes; want %d, have %d", (want+2+1), len(abuf))
		err = errMsgTooSmall
		return
	}

	pbuf := daddr[want:]
	a.Port = (uint16(pbuf[0]) << 8) + uint16(pbuf[1])
	a.Typ = abuf[0]

	switch a.Typ {
	case A_IPV4, A_IPV6:
		a.Addr = netip.AddrFromSlice(daddr[:want])

	case A_HOST:
		a.Host = string(daddr[:want])
	}
	n += (want + 2)

	/*
	switch abuf[0] {
	case A_IPV4:
		addr := fmt.Sprintf("%d.%d.%d.%d", daddr[0], daddr[1], daddr[2], daddr[3], port)
		a.Typ = A_IPV4
		a.Addr, err = netip.ParseAddr(addr)
		if err != nil {
			count("bad-addr", 1)
			log.Debug("bad IPv4 client conn addr: %s", err)
			return
		}

	case A_HOST:
		var s strings.Builder
		for i := 0; i < want; i++ {
			s.WriteByte(daddr[i])
		}
		a.Typ = A_HOST
		a.Host = s.String()

	case A_IPV6:
		var s strings.Builder
		s.WriteString(fmt.Sprintf("%02x", daddr[0]))
		for i := 1; i < want; i++ {
			s.WriteString(fmt.Sprintf(":%02x", daddr[i]))
		}
		a.Addr, err = netip.ParseAddr(s.String())
		if err != nil {
			count("bad-addr", 1)
			log.Debug("bad IPv6 client conn addr: %s", err)
			return
		}
	}
	*/
	return
}

