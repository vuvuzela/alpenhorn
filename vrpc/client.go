// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package vrpc extends net/rpc.
package vrpc

import (
	"log"
	"net/rpc"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/edtls"
)

type Client struct {
	Network  string
	Address  string
	TheirKey ed25519.PublicKey

	myKey     ed25519.PrivateKey
	callQueue chan *Call

	shutdown chan struct{}
	errc     chan error

	mu       sync.Mutex // protects following
	closed   bool
	numConns int
}

func Dial(network, address string, theirKey ed25519.PublicKey, myKey ed25519.PrivateKey, connections int) (*Client, error) {
	c := &Client{
		Network:  network,
		Address:  address,
		TheirKey: theirKey,

		myKey:     myKey,
		callQueue: make(chan *Call, 64),
		shutdown:  make(chan struct{}),
		errc:      make(chan error, 1),
		numConns:  connections,
	}

	for i := 0; i < connections; i++ {
		go c.worker()
	}

	return c, nil
}

func (c *Client) connect() *rpc.Client {
	for {
		conn, err := edtls.Dial(c.Network, c.Address, c.TheirKey, c.myKey)
		if err != nil {
			log.Printf("error connecting to rpc server: %s\nretrying in 10 seconds...", err)
			time.Sleep(10 * time.Second)
			continue
		}
		return rpc.NewClient(conn)
	}
}

// Call is an RPC. The call may be retried if the connection
// fails, so RPCs should be idempotent.
type Call struct {
	Method string
	Args   interface{}
	Reply  interface{}
	Error  error
	done   chan *Call
}

func (c *Client) worker() {
	rc := c.connect()
	results := make(chan *rpc.Call, 32)
	callMap := make(map[*rpc.Call]*Call)
	for {
		select {
		case call := <-c.callQueue:
			rpcCall := rc.Go(call.Method, call.Args, call.Reply, results)
			callMap[rpcCall] = call
		case rpcCall := <-results:
			call := callMap[rpcCall]
			delete(callMap, rpcCall)
			if needsReconnect(rpcCall.Error) {
				rc = c.connect()
				rpcCall := rc.Go(call.Method, call.Args, call.Reply, results)
				callMap[rpcCall] = call
			} else {
				call.Error = rpcCall.Error
				call.done <- call
			}
		case <-c.shutdown:
			c.errc <- rc.Close()
		}
	}
}

func needsReconnect(err error) bool {
	if err == nil {
		return false
	}

	switch err.(type) {
	case rpc.ServerError:
		return false
	default:
		return true
	}
}

func (c *Client) Call(method string, args interface{}, reply interface{}) error {
	done := make(chan *Call, 1)
	call := &Call{
		Method: method,
		Args:   args,
		Reply:  reply,
		done:   done,
	}
	c.callQueue <- call
	<-done
	return call.Error
}

func (c *Client) CallMany(calls []*Call) error {
	if len(calls) == 0 {
		return nil
	}

	done := make(chan *Call, len(calls))

	for _, call := range calls {
		call.done = done
		c.callQueue <- call
	}

	var err error
	var received int
	for call := range done {
		if err == nil && call.Error != nil {
			err = call.Error
		}

		received++
		if received == len(calls) {
			break
		}
	}

	return err
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return rpc.ErrShutdown
	}
	c.closed = true

	close(c.shutdown)
	var err error
	for i := 0; i < c.numConns; i++ {
		e := <-c.errc
		if err == nil && e != nil {
			err = e
		}
	}
	return err
}
