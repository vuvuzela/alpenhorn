// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package alpenhorn

import (
	"encoding/json"
	"io/ioutil"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/internal/ioutil2"
)

//easyjson:readable
type persistedState struct {
	Username           string
	LongTermPublicKey  ed25519.PublicKey
	LongTermPrivateKey ed25519.PrivateKey
	PKGLoginKey        ed25519.PrivateKey

	CoordinatorAddress string
	CoordinatorKey     ed25519.PublicKey

	AddFriendConfig *config.SignedConfig
	DialingConfig   *config.SignedConfig

	IncomingFriendRequests []*IncomingFriendRequest
	OutgoingFriendRequests []*OutgoingFriendRequest
	SentFriendRequests     []*sentFriendRequest
	Friends                map[string]*persistedFriend
	Registrations          map[string]*pkg.Client
}

// persistedFriend is the persisted representation of the Friend type.
// We use this because Friend.extraData is unexported but must be persisted.
//easyjson:readable
type persistedFriend struct {
	Username    string
	LongTermKey ed25519.PublicKey
	ExtraData   []byte
}

// LoadClient loads a client from persisted state at the given path.
// You should set the client's KeywheelPersistPath before connecting.
func LoadClient(clientPersistPath string) (*Client, error) {
	clientData, err := ioutil.ReadFile(clientPersistPath)
	if err != nil {
		return nil, err
	}

	st := new(persistedState)
	err = json.Unmarshal(clientData, st)
	if err != nil {
		return nil, err
	}

	c := &Client{
		ClientPersistPath: clientPersistPath,
	}
	c.loadStateLocked(st)
	return c, nil
}

func (c *Client) loadStateLocked(st *persistedState) {
	c.Username = st.Username
	c.LongTermPublicKey = st.LongTermPublicKey
	c.LongTermPrivateKey = st.LongTermPrivateKey
	c.PKGLoginKey = st.PKGLoginKey

	c.CoordinatorAddress = st.CoordinatorAddress
	c.CoordinatorKey = st.CoordinatorKey

	c.addFriendConfig = st.AddFriendConfig
	c.addFriendConfigHash = st.AddFriendConfig.Hash()

	c.dialingConfig = st.DialingConfig
	c.dialingConfigHash = st.DialingConfig.Hash()

	c.incomingFriendRequests = st.IncomingFriendRequests
	c.outgoingFriendRequests = st.OutgoingFriendRequests
	c.sentFriendRequests = st.SentFriendRequests

	for _, req := range c.incomingFriendRequests {
		req.client = c
	}
	for _, req := range c.outgoingFriendRequests {
		req.client = c
	}
	for _, req := range c.sentFriendRequests {
		req.client = c
	}

	c.friends = make(map[string]*Friend, len(st.Friends))
	for username, friend := range st.Friends {
		c.friends[username] = &Friend{
			Username:    friend.Username,
			LongTermKey: friend.LongTermKey,
			extraData:   friend.ExtraData,
			client:      c,
		}
	}

	c.registrations = st.Registrations
}

// Persist writes the client's state to disk. The client persists
// itself automatically, so Persist is only needed when creating
// a new client.
func (c *Client) Persist() error {
	c.mu.Lock()
	err := c.persistLocked()
	c.mu.Unlock()
	return err
}

// persistLocked persists the client state and keywheel state, assuming
// c.mu is locked. The keywheel and client state are always persisted
// at the same time to avoid leaking metadata.
func (c *Client) persistLocked() error {
	var err error
	if c.ClientPersistPath != "" {
		err = c.persistClient()
	}
	if c.KeywheelPersistPath != "" {
		if e := c.persistKeywheel(); err == nil {
			err = e
		}
	}
	return err
}

func (c *Client) persistClient() error {
	st := &persistedState{
		Username:           c.Username,
		LongTermPublicKey:  c.LongTermPublicKey,
		LongTermPrivateKey: c.LongTermPrivateKey,
		PKGLoginKey:        c.PKGLoginKey,

		CoordinatorAddress: c.CoordinatorAddress,
		CoordinatorKey:     c.CoordinatorKey,

		AddFriendConfig: c.addFriendConfig,
		DialingConfig:   c.dialingConfig,

		IncomingFriendRequests: c.incomingFriendRequests,
		OutgoingFriendRequests: c.outgoingFriendRequests,
		SentFriendRequests:     c.sentFriendRequests,

		Friends:       make(map[string]*persistedFriend, len(c.friends)),
		Registrations: c.registrations,
	}

	for username, friend := range c.friends {
		st.Friends[username] = &persistedFriend{
			Username:    friend.Username,
			LongTermKey: friend.LongTermKey,
			ExtraData:   friend.extraData,
		}
	}

	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}

	return ioutil2.WriteFileAtomic(c.ClientPersistPath, data, 0600)
}

func (c *Client) persistKeywheel() error {
	data, err := c.wheel.MarshalBinary()
	if err != nil {
		return err
	}

	return ioutil2.WriteFileAtomic(c.KeywheelPersistPath, data, 0600)
}
