package typesocket

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/log"
)

type clientConn struct {
	mu  sync.Mutex
	ws  *websocket.Conn
	mux Mux

	closeErr chan error
}

type Conn interface {
	Send(msgID string, v interface{}) error

	Close() error
}

func Dial(addr string, peerKey ed25519.PublicKey, mux Mux) (Conn, error) {
	tlsConfig := edtls.NewTLSClientConfig(nil, peerKey)

	dialer := &websocket.Dialer{
		TLSClientConfig:  tlsConfig,
		HandshakeTimeout: 25 * time.Second,
	}
	ws, _, err := dialer.Dial(addr, nil)
	if err != nil {
		return nil, err
	}
	conn := &clientConn{
		ws:  ws,
		mux: mux,

		closeErr: make(chan error, 1),
	}
	go conn.readLoop()
	return conn, nil
}

func (c *clientConn) Close() error {
	c.mu.Lock()
	c.ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, ""))
	c.mu.Unlock()

	select {
	case err := <-c.closeErr:
		return err
	case <-time.After(1 * time.Second):
		return c.ws.Close()
	}
}

func (c *clientConn) Send(msgID string, v interface{}) error {
	const writeWait = 10 * time.Second

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
	//c.ws.SetWriteDeadline(time.Now().Add(writeWait))
	if err := c.ws.WriteJSON(e); err != nil {
		log.WithFields(log.Fields{"call": "WriteJSON"}).Error(err)
		return err
	}

	return nil
}

func (c *clientConn) readLoop() {
	defer func() {
		c.closeErr <- c.ws.Close()
	}()
	for {
		var e envelope
		if err := c.ws.ReadJSON(&e); err != nil {
			if websocket.IsCloseError(err, websocket.CloseGoingAway) {
				return
			}
			log.WithFields(log.Fields{"call": "ReadJSON"}).Error(err)
			return
		}
		go c.mux.openEnvelope(c, &e)
	}
}
