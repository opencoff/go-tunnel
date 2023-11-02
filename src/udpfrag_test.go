// udpfrag_test.go - tests for fragment handling
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"testing"
)

func TestSingleFrag(t *testing.T) {
	assert := newAsserter(t)

	f := newFragmap()
	b0 := make([]byte, 128, 128)

	s, ok := f.Add(1|0x80, b0, 16)
	assert(ok, "single fragment rejected")
	assert(len(s) == 1, "single frag exp 1, saw %d", len(s))
	assert(s[0].off == 16, "single frag off want 16, saw %d", s[0].off)
}

func TestTwoFrag(t *testing.T) {
	assert := newAsserter(t)

	f := newFragmap()
	b0 := make([]byte, 128, 128)
	b1 := make([]byte, 128, 128)

	s, ok := f.Add(1, b0, 16)
	assert(!ok, "false accept of first frag")

	s, ok = f.Add(2|0x80, b1, 16)
	assert(ok, "failed accept of second & final frag")
	assert(len(s) == 2, "frags exp 2, saw %d", len(s))
	assert(s[0].off == 16, "single frag off want 16, saw %d", s[0].off)
}

func TestManyFrag(t *testing.T) {
	assert := newAsserter(t)

	f := newFragmap()
	b0 := make([]byte, 128, 128)
	b1 := make([]byte, 128, 128)
	b2 := make([]byte, 128, 128)

	s, ok := f.Add(1, b0, 16)
	assert(!ok, "false accept of first frag")

	// send frag #3 out of order
	s, ok = f.Add(3|0x80, b2, 16)
	assert(!ok, "false accept of third frag")

	s, ok = f.Add(2, b1, 16)
	assert(ok, "failed accept of second & final frag")
	assert(len(s) == 3, "frags exp 3, saw %d", len(s))

	for i, b := range s {
		assert(b.off == 16, "%d: frag off %d != 16", i, b.off)
		assert(len(b.b) == 128, "%d: frag len %d != 128", i, len(b.b))
	}
}
