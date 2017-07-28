// Package typesocket implements a websocket server and client.
package typesocket

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// The Hub and serverConn methods are based on
// https://github.com/gorilla/websocket/blob/master/examples/chat/

const (
	// Time allowed to write a message to the peer.
	writeWait = 30 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 300 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = 20 * time.Second

	// Maximum message size allowed from peer.
	maxMessageSize = 4096
)

type Hub struct {
	Mux Mux

	// OnConnect is called when a client connects to the server.
	OnConnect func(Conn) error

	mu    sync.Mutex
	conns map[*serverConn]bool
}

type serverConn struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte

	mu     sync.Mutex
	closed bool
}

// readPump pumps messages from the websocket connection to the hub.
func (c *serverConn) readPump() {
	defer func() {
		c.mu.Lock()
		if !c.closed {
			c.closed = true
			close(c.send)
		}
		c.mu.Unlock()
		c.hub.unregister(c)
		c.conn.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	for {
		var e envelope
		err := c.conn.ReadJSON(&e)
		if err != nil {
			switch {
			case websocket.IsCloseError(err, websocket.CloseGoingAway):
				// all good
			case websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway):
				log.Errorf("hub: unexpected close error: %v", err)
			default:
				log.Errorf("hub: ReadJSON error: %s", err)
			}
			break
		}
		c.hub.Mux.openEnvelope(c, &e)
	}
}

// write writes a message with the given message type and payload.
func (c *serverConn) write(mt int, payload []byte) error {
	c.conn.SetWriteDeadline(time.Now().Add(writeWait))
	return c.conn.WriteMessage(mt, payload)
}

// writePump pumps messages from the hub to the websocket connection.
func (c *serverConn) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				// The hub closed the channel.
				c.write(websocket.CloseMessage, []byte{})
				return
			}

			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				log.Errorf("hub: write error: %s", err)
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				log.Errorf("hub: write (close) error: %s", err)
				return
			}
		case <-ticker.C:
			if err := c.write(websocket.PingMessage, []byte{}); err != nil {
				log.Errorf("hub: write (ping) error: %s", err)
				return
			}
		}
	}
}

func (c *serverConn) Send(msgID string, v interface{}) error {
	msg, err := encodeMessage(msgID, v)
	if err != nil {
		return err
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("connection closed")
	}

	select {
	case c.send <- msg:
		c.mu.Unlock()
		return nil
	default:
		c.closed = true
		close(c.send)
		c.mu.Unlock()
		c.hub.unregister(c)
		return errors.New("failed to send")
	}
}

func (c *serverConn) Close() error {
	return c.conn.Close()
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("hub: Upgrade error: %s", err)
		return
	}

	c := &serverConn{
		hub:  h,
		conn: ws,
		send: make(chan []byte, 64),
	}
	h.register(c)

	if h.OnConnect != nil {
		err := h.OnConnect(c)
		if err != nil {
			http.Error(w, "connection error", http.StatusInternalServerError)
			return
		}
	}

	go c.writePump()
	c.readPump()
}

func (h *Hub) register(c *serverConn) {
	h.mu.Lock()
	if h.conns == nil {
		h.conns = make(map[*serverConn]bool)
	}
	h.conns[c] = true
	h.mu.Unlock()
}

func (h *Hub) unregister(c *serverConn) {
	h.mu.Lock()
	_, ok := h.conns[c]
	if ok {
		delete(h.conns, c)
	}
	h.mu.Unlock()
}

func (h *Hub) Broadcast(msgID string, v interface{}) error {
	msg, err := encodeMessage(msgID, v)
	if err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	for conn := range h.conns {
		conn.mu.Lock()
		if conn.closed {
			conn.mu.Unlock()
			continue
		}

		select {
		case conn.send <- msg:
		default:
			delete(h.conns, conn)
			conn.closed = true
			close(conn.send)
		}
		conn.mu.Unlock()
	}
	return nil
}
