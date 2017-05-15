// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package alpenhorn implements an Alpenhorn client.
package alpenhorn

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"sync"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/errors"
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
}

type ConnectionSettings struct {
	EntryAddr string
	PKGAddrs  []string
	PKGKeys   []ed25519.PublicKey
	Mixers    []ed25519.PublicKey
	CDNKey    ed25519.PublicKey
}

type Client struct {
	Username           string
	LongTermPublicKey  ed25519.PublicKey
	LongTermPrivateKey ed25519.PrivateKey

	ConnectionSettings

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

	pkgClients []*pkg.Client
	cdnClient  *http.Client

	mu                     sync.Mutex
	incomingFriendRequests []*IncomingFriendRequest
	outgoingFriendRequests []*OutgoingFriendRequest
	sentFriendRequests     []*sentFriendRequest
	outgoingCalls          []*OutgoingCall
	friends                map[string]*Friend
	registrations          map[string]*pkg.Client

	addFriendRounds map[uint32]*addFriendRoundState
	addFriendConn   typesocket.Conn
	dialingConn     typesocket.Conn

	lastDialingRound uint32 // updated atomically
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

	// We could use our long-term signing key as the login key, but then it
	// would have to be always online.
	_, loginPrivateKey, _ := ed25519.GenerateKey(rand.Reader)

	pkgc := &pkg.Client{
		ServerAddr: pkgAddr,
		ServerKey:  pkgKey,
		Username:   c.Username,
		LoginKey:   loginPrivateKey,
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

	c.pkgClients = make([]*pkg.Client, 0, len(c.PKGKeys))
	for i := range c.PKGKeys {
		pkgClient := c.getRegistration(c.Username, c.PKGKeys[i])
		if pkgClient == nil {
			return errors.New("username %q not registered with pkg %s", c.Username, c.PKGAddrs[i])
		}
		pkgClient.UserLongTermKey = c.LongTermPublicKey
		c.pkgClients = append(c.pkgClients, pkgClient)
	}

	c.cdnClient = &http.Client{
		Transport: &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				return edtls.Dial(network, addr, c.CDNKey, nil)
			},
		},
	}

	if c.friends == nil {
		c.friends = make(map[string]*Friend)
	}

	c.addFriendRounds = make(map[uint32]*addFriendRoundState)
	afwsAddr := fmt.Sprintf("ws://%s/afws", c.EntryAddr)
	addFriendConn, err := typesocket.Dial(afwsAddr, c.addFriendMux())
	if err != nil {
		return err
	}
	c.addFriendConn = addFriendConn

	dwsAddr := fmt.Sprintf("ws://%s/dws", c.EntryAddr)
	dialingConn, err := typesocket.Dial(dwsAddr, c.dialingMux())
	if err != nil {
		return err
	}
	c.dialingConn = dialingConn

	return nil
}
