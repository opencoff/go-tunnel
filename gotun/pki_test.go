// pki_test.go - simple tests to validate the pki test-harness

package main

import (
	"testing"
)

// return a configured Conf

func TestPKI(t *testing.T) {
	assert := newAsserter(t)

	pk, err := newPKI()
	assert(err == nil, "can't create PKI: %s", err)

	_, err = pk.ServerCert("myserver.com", "127.0.0.1")
	assert(err == nil, "can't create server cert: %s", err)

	_, err = pk.ClientCert("client@foo.com")
	assert(err == nil, "can't create client cert: %s", err)
}
