// lexer.go -- lexical scanner for the config file
//
// (c) 2018 Sudhi Herle
//
// License: GPLv2
//


package config


import (
	"testing"
	"fmt"
	"runtime"
)


// make an assert() function for use in environment 't' and return it
func newAsserter(t *testing.T) func(cond bool, msg string, args ...interface{}) {
	return func(cond bool, msg string, args ...interface{}) {
		if cond {
			return
		}

		_, file, line, ok := runtime.Caller(1)
		if !ok {
			file = "???"
			line = 0
		}

		s := fmt.Sprintf(msg, args...)
		t.Fatalf("%s: %d: Assertion failed: %s\n", file, line, s)
	}
}

