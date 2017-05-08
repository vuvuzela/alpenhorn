package edtls

import (
	"crypto/rand"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"testing"

	"golang.org/x/crypto/ed25519"
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
		c, err := Server(server, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = io.Copy(ioutil.Discard, c)
	}()

	c, err := Client(client, testKeyPub, nil)
	if err == nil {
		c.Close()
		t.Fatal("expected an error")
	}
	if err != ErrVerificationFailed {
		t.Fatalf("expected ErrVerificationFailed, got %T: %v", err, err)
	}

	wg.Wait()
}
