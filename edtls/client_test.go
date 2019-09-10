package edtls

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"testing"
)

func TestClientVerificationFailure(t *testing.T) {
	testKeyPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c := Server(server, nil)
		defer c.Close()
		_, _ = io.Copy(ioutil.Discard, c)
	}()

	c := Client(client, testKeyPub, nil)
	err = c.Handshake()
	if err != ErrVerificationFailed {
		t.Fatalf("expected ErrVerificationFailed, got %T: %v", err, err)
	}

	wg.Wait()
}
