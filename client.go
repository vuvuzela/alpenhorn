// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package alpenhorn implements an Alpenhorn client.
package alpenhorn

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/edhttp"
	"vuvuzela.io/alpenhorn/keywheel"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/alpenhorn/typesocket"
)

// An EventHandler specifies how an application should react to
// events in the Alpenhorn client.
type EventHandler interface {
	// Error is called when the Alpenhorn client experiences an error.
	Error(error)

	// ConfirmedFriend is called when the add-friend protocol is completed
	// between two friends, resulting in a new Friend object.
	ConfirmedFriend(*Friend)

	// SentFriendRequest is called when an OutgoingFriendRequest is sent
	// to the entry server.
	SentFriendRequest(*OutgoingFriendRequest)

	// ReceivedFriendRequest is called when the client receives a friend request.
	// The application should eventually call .Approve() or .Remove() on the
	// IncomingFriendRequest.
	ReceivedFriendRequest(*IncomingFriendRequest)

	// UnexpectedSigningKey is called when an incoming friend request corresponds
	// to a friend request the user sent but has a different long term key than
	// what the user specified.
	UnexpectedSigningKey(*IncomingFriendRequest, *OutgoingFriendRequest)

	// SentCall is called when an OutgoingCall is sent to the entry server.
	SentCall(*OutgoingCall)

	// ReceivedCall is called when the client receives a call from a friend.
	ReceivedCall(*IncomingCall)

	// NewConfig is called when the configuration for the add-friend or dialing
	// protocol changes. The chain starts with the new config and ends with the
	// client's previous config.
	NewConfig(chain []*config.SignedConfig)
}

type Client struct {
	Username           string
	LongTermPublicKey  ed25519.PublicKey
	LongTermPrivateKey ed25519.PrivateKey
	PKGLoginKey        ed25519.PrivateKey

	CoordinatorAddress string
	CoordinatorKey     ed25519.PublicKey

	Handler EventHandler

	// ClientPersistPath is where the client writes its state when it changes.
	// If empty, the client does not persist state.
	ClientPersistPath string

	// KeywheelPersistPath is the path where the client's keywheel is stored.
	// This field is not persisted along with the rest of the client's state,
	// so it must be set before calling Connect.
	//
	// The client state and keywheel are persisted in separate files for
	// forward secrecy. The client state is long-term and should be backed
	// up regularly. The keywheel is ephemeral and should not be backed up
	// (doing so hurts forward secrecy, and the keywheel can be recreated
	// from the client state).
	KeywheelPersistPath string

	// wheel is the Alpenhorn keywheel. It is loaded from the KeywheelPersistPath
	// when the client connects.
	wheel keywheel.Wheel

	once         sync.Once
	edhttpClient *edhttp.Client

	lastDialingRound uint32 // updated atomically

	// mu protects everything up to the end of the struct.
	mu sync.Mutex

	addFriendRounds     map[uint32]*addFriendRoundState
	addFriendConfigHash string
	addFriendConfig     *config.SignedConfig
	registrations       map[string]*pkg.Client

	dialingRounds     map[uint32]*dialingRoundState
	dialingConfigHash string
	dialingConfig     *config.SignedConfig

	friends                map[string]*Friend
	incomingFriendRequests []*IncomingFriendRequest
	outgoingFriendRequests []*OutgoingFriendRequest
	sentFriendRequests     []*sentFriendRequest
	outgoingCalls          []*OutgoingCall

	connected     bool
	addFriendConn typesocket.Conn
	dialingConn   typesocket.Conn
}

func regid(serverKey ed25519.PublicKey, username string) string {
	h := sha256.Sum256(append(serverKey, []byte(username)...))
	return hex.EncodeToString(h[:])
}

// Register registers the username with the given PKG.
func (c *Client) Register(username string, pkgAddr string, pkgKey ed25519.PublicKey) error {
	regID := regid(pkgKey, username)

	c.mu.Lock()
	if c.registrations == nil {
		c.registrations = make(map[string]*pkg.Client)
	}
	_, ok := c.registrations[regID]
	c.mu.Unlock()

	if ok {
		// already registered
		return nil
	}

	pkgc := &pkg.Client{
		PublicServerConfig: pkg.PublicServerConfig{
			Key:     pkgKey,
			Address: pkgAddr,
		},
		Username:        c.Username,
		LoginKey:        c.PKGLoginKey,
		UserLongTermKey: c.LongTermPublicKey,
	}
	err := pkgc.Register()
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.registrations[regID] = pkgc
	err = c.persistLocked()
	c.mu.Unlock()

	return err
}

func (c *Client) getRegistration(username string, serverKey ed25519.PublicKey) *pkg.Client {
	regID := regid(serverKey, username)
	c.mu.Lock()
	reg := c.registrations[regID]
	c.mu.Unlock()
	return reg
}

// Connect connects to the Alpenhorn servers specified in the client's
// connection settings and starts participating in the add-friend and
// dialing protocols.
func (c *Client) Connect() error {
	c.once.Do(func() {
		c.edhttpClient = new(edhttp.Client)
	})

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return errors.New("already connected")
	}

	if c.CoordinatorAddress == "" {
		return errors.New("no coordinator address")
	}
	if len(c.CoordinatorKey) != ed25519.PublicKeySize {
		return errors.New("no coordinator key")
	}
	if c.addFriendConfig == nil {
		return errors.New("no addfriend config")
	}
	if c.dialingConfig == nil {
		return errors.New("no dialing config")
	}

	if c.KeywheelPersistPath != "" {
		keywheelData, err := ioutil.ReadFile(c.KeywheelPersistPath)
		if os.IsNotExist(err) {
			err := c.persistKeywheel()
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			err := c.wheel.UnmarshalBinary(keywheelData)
			if err != nil {
				return err
			}
		}
	}

	if c.friends == nil {
		c.friends = make(map[string]*Friend)
	}

	c.addFriendRounds = make(map[uint32]*addFriendRoundState)
	afwsAddr := fmt.Sprintf("wss://%s/addfriend/ws", c.CoordinatorAddress)
	addFriendConn, err := typesocket.Dial(afwsAddr, c.CoordinatorKey, c.addFriendMux())
	if err != nil {
		return err
	}

	c.dialingRounds = make(map[uint32]*dialingRoundState)
	dwsAddr := fmt.Sprintf("wss://%s/dialing/ws", c.CoordinatorAddress)
	dialingConn, err := typesocket.Dial(dwsAddr, c.CoordinatorKey, c.dialingMux())
	if err != nil {
		addFriendConn.Close()
		return err
	}

	c.connected = true
	c.addFriendConn = addFriendConn
	c.dialingConn = dialingConn

	return nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return errors.New("not connected")
	}

	c.connected = false
	err1 := c.dialingConn.Close()
	err2 := c.addFriendConn.Close()

	if err1 != nil {
		return err1
	}
	return err2
}
