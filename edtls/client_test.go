package edtls

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"io/ioutil"
	"net"
	"testing"
)

func TestClientVerificationFailure(t *testing.T) {
	_, serverKeyPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	pipe := localPipe()
	defer pipe.Close()

	go func() {
		c := Server(pipe.server, serverKeyPriv)
		_, _ = io.Copy(ioutil.Discard, c)
	}()

	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	c := Client(pipe.client, otherPub, clientKey)
	err = c.Handshake()
	if err != ErrVerificationFailed {
		t.Fatalf("expected ErrVerificationFailed, got %T: %v", err, err)
	}
}

type pipe struct {
	listener net.Listener
	server   net.Conn
	client   net.Conn
}

func (p pipe) Close() {
	p.client.Close()
	p.server.Close()
	p.listener.Close()
}

func localPipe() pipe {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	addr := l.Addr()
	c, err := net.Dial(addr.Network(), addr.String())
	if err != nil {
		panic(err)
	}
	s, err := l.Accept()
	if err != nil {
		panic(err)
	}
	return pipe{
		listener: l,
		client:   c,
		server:   s,
	}
}
