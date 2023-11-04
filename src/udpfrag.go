// udpfrag.go - handles udp fragments
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"time"
)

type buffer struct {
	b []byte

	off int
}

// socks5 fragment number is a uint8 (starting with 1); the last
// fragment has the high bit set to 1. This means, we have a total
// of 127 fragments possible.
const _maxfrags uint = 128
const _words uint = _maxfrags / 8

type fragmap struct {
	bm [_words]uint64

	bufs [_maxfrags]buffer

	// index of the final fragment
	last  int
	mtime time.Time
}

// newFragmap creates a new instance of a fragmap
func newFragmap() *fragmap {
	b := &fragmap{
		last:  -1,
		mtime: time.Now(),
	}
	return b
}

func (b *fragmap) init() {
	bm := b.bm[:]
	for i := range bm {
		bm[i] = 0
	}
	b.last = -1
	b.mtime = time.Now()
}

// Age returns the duration since the last update
func (b *fragmap) Age() time.Duration {
	return time.Since(b.mtime)
}

// Add adds a new fragment for this client; it tracks buffers that are
// obtained from a pool and records the offset where client data begins.
// When all fragments are complete, it returns true and the list of fragments.
// It returns false until all fragments are complete.
func (b *fragmap) Add(i uint8, buf []byte, offset int) ([]buffer, bool) {
	// frag == 0 implies sender doesn't use fragments. ie we treat it as
	// the sole and final frag.
	if i == 0 {
		x := &b.bufs[0]
		x.b = buf
		x.off = offset
		return b.bufs[:1], true
	}

	b.mtime = time.Now()

	// Socks5 UDP Frag numbering starts with 1. So, we normalize
	// it to start at 0.
	i -= 1

	if (i & 0x80) > 0 {
		i &= ^uint8(0x80)
		b.last = int(i)
	}

	b.bm[i/64] |= (1 << (i % 64))
	b.bufs[i].b = buf
	b.bufs[i].off = offset

	// This logic handles out of order fragments
	if b.last >= 0 {
		// check all bits from [0:b.last] to see if they're set
		w := b.last / 64
		r := b.last % 64

		if w > 0 {
			// XXX Unroll if need be.
			for j := 0; j < w; j++ {
				if b.bm[j] != ^uint64(0) {
					return nil, false
				}
			}
		}

		if r > 0 {
			if b.bm[w] != _mask[r] {
				return nil, false
			}
		}
		return b.bufs[:b.last+1], true
	}
	return nil, false
}

// fragmap masks for a single word; we use this to mopup the last word.
var _mask = [...]uint64{
	0x00000001,
	0x00000003,
	0x00000007,
	0x0000000f,
	0x0000001f,
	0x0000003f,
	0x0000007f,
	0x000000ff,
	0x000001ff,
	0x000003ff,
	0x000007ff,
	0x00000fff,
	0x00001fff,
	0x00003fff,
	0x00007fff,
	0x0000ffff,
	0x0001ffff,
	0x0003ffff,
	0x0007ffff,
	0x000fffff,
	0x001fffff,
	0x003fffff,
	0x007fffff,
	0x00ffffff,
	0x01ffffff,
	0x03ffffff,
	0x07ffffff,
	0x0fffffff,
	0x1fffffff,
	0x3fffffff,
	0x7fffffff,
	0xffffffff,
	0x1ffffffff,
	0x3ffffffff,
	0x7ffffffff,
	0xfffffffff,
	0x1fffffffff,
	0x3fffffffff,
	0x7fffffffff,
	0xffffffffff,
	0x1ffffffffff,
	0x3ffffffffff,
	0x7ffffffffff,
	0xfffffffffff,
	0x1fffffffffff,
	0x3fffffffffff,
	0x7fffffffffff,
	0xffffffffffff,
	0x1ffffffffffff,
	0x3ffffffffffff,
	0x7ffffffffffff,
	0xfffffffffffff,
	0x1fffffffffffff,
	0x3fffffffffffff,
	0x7fffffffffffff,
	0xffffffffffffff,
	0x1ffffffffffffff,
	0x3ffffffffffffff,
	0x7ffffffffffffff,
	0xfffffffffffffff,
	0x1fffffffffffffff,
	0x3fffffffffffffff,
	0x7fffffffffffffff,
}
// EOF
