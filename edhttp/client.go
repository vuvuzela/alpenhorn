// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package edhttp is an HTTP client that connects to HTTP servers
// on edtls listeners.
package edhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/errors"
)

type Client struct {
	Key ed25519.PrivateKey

	initOnce sync.Once
	client   *http.Client

	mu         sync.RWMutex
	serverKeys map[string]ed25519.PublicKey
}

func (c *Client) init() {
	c.initOnce.Do(func() {
		c.serverKeys = make(map[string]ed25519.PublicKey)

		c.client = &http.Client{
			Transport: &http.Transport{
				DialTLS: func(network, addr string) (net.Conn, error) {
					c.mu.RLock()
					serverKey := c.serverKeys[addr]
					c.mu.RUnlock()
					if serverKey == nil {
						return nil, errors.New("no edtls key for %s", addr)
					}
					return edtls.Dial(network, addr, serverKey, c.Key)
				},

				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return nil, errors.New("edhttp does not allow unencrypted tcp connections")
				},
			},
		}
	})
}

// assertKey tells the client to expect an edTLS certificate
// signed by key when connecting to the given address.
func (c *Client) assertKey(address string, key ed25519.PublicKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	k := c.serverKeys[address]
	if k != nil {
		if bytes.Equal(k, key) {
			return nil
		}
		return errors.New("multiple keys for address: %s", address)
	}

	c.serverKeys[address] = key
	return nil
}

func (c *Client) assertKeyURL(urlStr string, key ed25519.PublicKey) error {
	u, err := url.Parse(urlStr)
	if err != nil {
		return err
	}

	return c.assertKey(u.Host, key)
}

func (c *Client) Do(key ed25519.PublicKey, req *http.Request) (*http.Response, error) {
	c.init()
	if err := c.assertKey(req.URL.Host, key); err != nil {
		return nil, err
	}
	return c.client.Do(req)
}

func (c *Client) Get(key ed25519.PublicKey, url string) (*http.Response, error) {
	c.init()
	if err := c.assertKeyURL(url, key); err != nil {
		return nil, err
	}
	return c.client.Get(url)
}

func (c *Client) Post(key ed25519.PublicKey, url string, contentType string, body io.Reader) (*http.Response, error) {
	c.init()
	if err := c.assertKeyURL(url, key); err != nil {
		return nil, err
	}
	return c.client.Post(url, contentType, body)
}

func (c *Client) PostJSON(key ed25519.PublicKey, url string, v interface{}) (*http.Response, error) {
	c.init()
	if err := c.assertKeyURL(url, key); err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	err := json.NewEncoder(buf).Encode(v)
	if err != nil {
		return nil, errors.New("json encoding error: %s", err)
	}

	return c.client.Post(url, "application/json", buf)
}
