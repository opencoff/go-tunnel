package main

import (
	"testing"
)

type sizeTest struct {
	in  string
	out uint64
	err bool
}

var sizesTests = []sizeTest{
	{"", 0, false},
	{"10", 10, false},
	{"4k", 4096, false},
	{"10M", 10 * 1048576, false},
	{"80G", 80 * _GB, false},
	{"10T", 10 * _TB, false},

	{"4x", 0, true},
	{"boo", 0, true},

	// overflow
	{"1048576E", 0, true},
}

func TestSize(t *testing.T) {
	assert := newAsserter(t)

	for i, t := range sizesTests {
		v, err := parseSize(t.in)
		if t.err {
			assert(err != nil, "%2d: %s: expected to fail", i, t.in)
		} else {
			assert(err == nil, "%2d: %s: unexpected err: %s", i, t.in, err)
			assert(t.out == v, "%2d: %s: exp %v, saw %v", i, t.in, t.out, v)
		}
	}
}
