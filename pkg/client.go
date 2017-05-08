// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pkg

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"

	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/crypto/bls"
	"vuvuzela.io/crypto/ibe"
)

// A Client connects to a PKG server to extract private keys.
// Before a client can extract keys, it must register the username
// and login key with the PKG server. The client must then verify
// ownership of the username, unless the PKG server is running in
// first-come-first-serve mode.
type Client struct {
	// ServerAddr is the host:port address of the PKG server.
	ServerAddr string

	// ServerKey is the long-term signing key of the PKG server.
	ServerKey ed25519.PublicKey

	// Username is identity in Identity-Based Encryption.
	Username string

	// LoginKey is used to authenticate to the PKG server.
	LoginKey ed25519.PrivateKey

	// UserLongTermKey is the user's long-term signing key. The
	// PKG server attests to this key during extraction. JSON
	// ignores this field since it does not need to be persisted.
	UserLongTermKey ed25519.PublicKey `json:"-"`
}

// Register attempts to register the client's username and login key
// with the PKG server. It only needs to be called once per PKG server.
func (c *Client) Register() error {
	loginPublicKey := c.LoginKey.Public()
	args := &registerArgs{
		Username: c.Username,
		LoginKey: loginPublicKey.(ed25519.PublicKey),
	}

	var reply string
	err := c.postJSON("register", args, &reply)
	if err != nil {
		return err
	}
	return nil
}

// Verify is used to verify ownership of a username (email address)
// when the PKG is not in first-come-first-serve mode.
func (c *Client) Verify(token []byte) error {
	args := &verifyArgs{
		Username: c.Username,
		Token:    token,
	}
	args.Sign(c.LoginKey)

	var reply string
	err := c.postJSON("verify", args, &reply)
	if err != nil {
		return err
	}
	return nil
}

type ExtractResult struct {
	PrivateKey  *ibe.IdentityPrivateKey
	IdentitySig bls.Signature
}

// Extract obtains the user's IBE private key for the given round from the PKG.
func (c *Client) Extract(round uint32) (*ExtractResult, error) {
	myPub, myPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic("box.GenerateKey: " + err.Error())
	}

	args := &extractArgs{
		Round:            round,
		Username:         c.Username,
		ReturnKey:        myPub,
		UserLongTermKey:  c.UserLongTermKey,
		ServerSigningKey: c.ServerKey,
	}
	args.Sign(c.LoginKey)

	reply := new(extractReply)
	err = c.postJSON("extract", args, reply)
	if err != nil {
		return nil, err
	}

	if reply.Round != round {
		return nil, errors.New("expected reply for round %d, but got %d", round, reply.Round)
	}
	if reply.Username != c.Username {
		return nil, errors.New("expected reply for username %q, but got %q", c.Username, reply.Username)
	}
	if l := len(reply.EncryptedPrivateKey); l < 32 {
		return nil, errors.New("unexpectedly short ciphertext (%d bytes)", l)
	}
	if !reply.Verify(c.ServerKey) {
		return nil, errors.New("invalid signature")
	}

	theirPub := new([32]byte)
	copy(theirPub[:], reply.EncryptedPrivateKey[0:32])
	ctxt := reply.EncryptedPrivateKey[32:]
	msg, ok := box.Open(nil, ctxt, new([24]byte), theirPub, myPriv)
	if !ok {
		return nil, errors.New("box authentication failed")
	}

	ibeKey := new(ibe.IdentityPrivateKey)
	if err := ibeKey.UnmarshalBinary(msg); err != nil {
		return nil, errors.Wrap(err, "unmarshalling ibe identity key")
	}

	return &ExtractResult{
		PrivateKey:  ibeKey,
		IdentitySig: reply.IdentitySig,
	}, nil
}

func (c *Client) postJSON(urlPath string, args interface{}, reply interface{}) error {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(args); err != nil {
		return errors.Wrap(err, "json.Encode")
	}

	url := fmt.Sprintf("https://%s/%s", c.ServerAddr, urlPath)
	req, err := http.NewRequest("POST", url, buf)
	if err != nil {
		return err
	}
	req.Close = true

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				return edtls.Dial(network, addr, c.ServerKey, nil)
			},
		},
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "POST error")
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "reading http response body")
	}
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, reply); err != nil {
			return errors.Wrap(err, "json.Unmarshal")
		}
		return nil
	} else {
		var pkgErr Error
		if err := json.Unmarshal(body, &pkgErr); err != nil {
			return errors.New(
				"error response (%s) with unparseable body: %q",
				resp.Status, body,
			)
		}
		return pkgErr
	}
}
