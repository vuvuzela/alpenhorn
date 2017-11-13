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

type ClientConn struct {
	mu sync.Mutex
	ws *websocket.Conn
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

	return conn, nil
}

func (c *ClientConn) Close() error {
	c.mu.Lock()
	c.ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, ""))
	c.mu.Unlock()

	return c.ws.Close()
}

func (c *ClientConn) Send(msgID string, v interface{}) error {
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
