// size.go -- Parse strings with a size suffix
//
// (c) 2016 Sudhi Herle <sudhi@herle.net>
//
// Licensing Terms: GPLv2
//
// If you need a commercial license for this work, please contact
// the author.
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.
package main

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	_kB uint64 = 1 << 10
	_MB uint64 = 1 << 20
	_GB uint64 = 1 << 30
	_TB uint64 = 1 << 40
	_PB uint64 = 1 << 50
	_EB uint64 = 1 << 60
)

var multmap map[string]uint64 = map[string]uint64{
	"":  1,
	"k": _kB,
	"K": _kB,
	"M": _MB,
	"G": _GB,
	"T": _TB,
	"P": _PB,
	"E": _EB,
}

const validSuffix = "kKMGTPE"

// Parse a string that has a size suffix (one of k, M, G, T, P, E).
// The suffix denotes multiples of 1024.
// e.g., "32k", "2M"
func parseSize(in string) (uint64, error) {
	var m uint64 = 1

	s := strings.TrimSpace(in)
	n := len(s)
	if n == 0 {
		return 0, nil
	}

	if i := strings.LastIndexAny(s, validSuffix); i > 0 {
		z := s[i:]
		if x, ok := multmap[z]; ok {
			m = x
			s = s[:i]
		} else {
			return 0, fmt.Errorf("uknown size suffix %s", z)
		}
	}

	u, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}

	v := u * m
	if v < u || v < m {
		return 0, fmt.Errorf("size: value %s overflows a uint64", in)
	}

	return v, nil
}
