// utils_test.go -- Test harness utilities for sign
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
	"crypto/subtle"
	"fmt"
	L "github.com/opencoff/go-logger"
	"runtime"
	"testing"
)

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

// io.Writer for logging
type logWriter struct {
	*testing.T
}

func (a *logWriter) Write(b []byte) (int, error) {
	var nl string

	if b[len(b)-1] != '\n' {
		nl = "\n"
	}
	a.Logf("# %s%s", string(b), nl)
	return len(b), nil
}

func newLogger(t *testing.T) L.Logger {
	assert := newAsserter(t)
	a := &logWriter{T: t}
	log, err := L.New(a, L.LOG_DEBUG, "gotun-test", 0)
	assert(err == nil, "can't create logger: %s", err)
	return log
}

// Return true if two byte arrays are equal
func byteEq(x, y []byte) bool {
	return subtle.ConstantTimeCompare(x, y) == 1
}
