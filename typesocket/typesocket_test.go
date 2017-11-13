package typesocket

import (
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/edtls"
)

type Ping struct {
	Count int
}

func TestTypeSocket(t *testing.T) {
	serverPublic, serverPrivate, _ := ed25519.GenerateKey(rand.Reader)

	serverMux := NewMux(map[string]interface{}{
		"Ping": func(c Conn, p Ping) {
			log.Printf("server: ping %d -> %d", p.Count, p.Count+1)
			if err := c.Send("Ping", Ping{p.Count + 1}); err != nil {
				t.Fatal(err)
			}
		},
	})
	hub := &Hub{
		Mux:   serverMux,
		conns: make(map[*serverConn]bool),
	}
	httpMux := http.NewServeMux()
	httpMux.Handle("/ws", hub)
	l, err := edtls.Listen("tcp", "127.0.0.1:0", serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go http.Serve(l, httpMux)

	done := make(chan struct{})
	clientMux := NewMux(map[string]interface{}{
		"Ping": func(c Conn, p Ping) {
			if p.Count > 10 {
				close(done)
				log.Printf("client done: %d", p.Count)
			} else {
				log.Printf("client: ping %d -> %d", p.Count, p.Count+1)
				if err := c.Send("Ping", Ping{p.Count + 1}); err != nil {
					t.Fatal(err)
				}
			}
		},
	})

	time.Sleep(500 * time.Millisecond)
	conn, err := Dial(fmt.Sprintf("wss://%s/ws", l.Addr().String()), serverPublic)
	if err != nil {
		t.Fatal(err)
	}
	go conn.Serve(clientMux)
	defer conn.Close()
	if err := conn.Send("Ping", Ping{0}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("timeout")
	}
}
