package typesocket

import (
	"log"
	"net/http"
	"testing"
	"time"
)

type Ping struct {
	Count int
}

func TestTypeSocket(t *testing.T) {
	serverMux := NewMux(map[string]interface{}{
		"Ping": func(c Conn, p Ping) {
			log.Printf("server: ping %d -> %d", p.Count, p.Count+1)
			c.Send("Ping", Ping{p.Count + 1})
		},
	})
	hub := &Hub{
		Mux:   serverMux,
		conns: make(map[*serverConn]bool),
	}
	http.Handle("/ws", hub)
	go http.ListenAndServe("127.0.0.1:8080", nil)

	clientMux := NewMux(map[string]interface{}{
		"Ping": func(c Conn, p Ping) {
			if p.Count < 10 {
				log.Printf("client: ping %d -> %d", p.Count, p.Count+1)
				c.Send("Ping", Ping{p.Count + 1})
			}
		},
	})
	time.Sleep(1 * time.Second)
	conn, err := Dial("ws://127.0.0.1:8080/ws", clientMux)
	if err != nil {
		t.Fatal(err)
	}
	conn.Send("Ping", Ping{0})
	time.Sleep(5 * time.Second)
}
