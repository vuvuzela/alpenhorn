package typesocket

import (
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/log"
)

type ClientConn struct {
	mu       sync.Mutex
	ws       *websocket.Conn
	lastPing time.Time
	latency  time.Duration
}

type Conn interface {
	Send(msgID string, v interface{}) error

	Close() error
}

func Dial(addr string, peerKey ed25519.PublicKey) (*ClientConn, error) {
	tlsConfig := edtls.NewTLSClientConfig(nil, peerKey)

	dialer := &websocket.Dialer{
		TLSClientConfig:  tlsConfig,
		HandshakeTimeout: 10 * time.Second,
	}
	ws, _, err := dialer.Dial(addr, nil)
	if err != nil {
		return nil, err
	}
	conn := &ClientConn{
		ws: ws,
	}

	ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPingHandler(conn.pingHandler)
	ws.SetPongHandler(conn.pongHandler)

	go conn.sendPingsLoop(pingPeriod)

	return conn, nil
}

func (c *ClientConn) pingHandler(message string) error {
	c.ws.SetReadDeadline(time.Now().Add(pongWait))
	// The code below is copied from the default ping handler.
	err := c.ws.WriteControl(websocket.PongMessage, []byte(message), time.Now().Add(writeWait))
	if err == websocket.ErrCloseSent {
		return nil
	} else if e, ok := err.(net.Error); ok && e.Temporary() {
		return nil
	}
	return err
}

func (c *ClientConn) pongHandler(message string) error {
	// If we hear back from the server, don't close the connection for another pongWait time.
	c.ws.SetReadDeadline(time.Now().Add(pongWait))
	c.mu.Lock()
	defer c.mu.Unlock()
	c.latency = time.Now().Sub(c.lastPing)
	return nil
}

func (c *ClientConn) Close() error {
	c.mu.Lock()
	c.ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, ""))
	c.mu.Unlock()

	return c.ws.Close()
}

func (c *ClientConn) Latency() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.latency
}

func (c *ClientConn) sendPingsLoop(period time.Duration) {
	ticker := time.NewTicker(period)
	defer func() {
		ticker.Stop()
		c.ws.Close()
	}()
	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			c.lastPing = time.Now()
			if err := c.ws.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(writeWait)); err != nil {
				c.mu.Unlock()
				log.Errorf("client: write (ping) error: %s", err)
				return
			}
			c.mu.Unlock()
		}
	}
}

func (c *ClientConn) Send(msgID string, v interface{}) error {
	msg, err := json.Marshal(v)
	if err != nil {
		return err
	}
	e := &envelope{
		ID:      msgID,
		Message: msg,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.ws.SetWriteDeadline(time.Now().Add(writeWait))
	if err := c.ws.WriteJSON(e); err != nil {
		log.WithFields(log.Fields{"call": "WriteJSON"}).Error(err)
		return err
	}

	return nil
}

func (c *ClientConn) Serve(mux Mux) error {
	defer c.Close()

	for {
		var e envelope
		if err := c.ws.ReadJSON(&e); err != nil {
			if websocket.IsCloseError(err, websocket.CloseGoingAway) {
				return err
			}
			return err
		}
		go mux.openEnvelope(c, &e)
	}
}
