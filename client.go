// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package alpenhorn implements an Alpenhorn client.
package alpenhorn

import (
	"fmt"
	"sync"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/edhttp"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/keywheel"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/alpenhorn/typesocket"
)

// Use github.com/davidlazar/easyjson:
//go:generate easyjson -output_filename client_json.go .

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

	// SendingCall is called when an OutgoingCall is about to be sent to the
	// entry server. The application can finalize the call to get its session key.
	SendingCall(*OutgoingCall)

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

	ConfigClient *config.Client

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

	// wheel is the Alpenhorn keywheel. It is persisted to the KeywheelPersistPath.
	wheel keywheel.Wheel

	initOnce     sync.Once
	edhttpClient *edhttp.Client

	lastDialingRound uint32 // updated atomically

	// mu protects everything up to the end of the struct.
	mu sync.Mutex

	addFriendRounds     map[uint32]*addFriendRoundState
	addFriendConfigHash string
	addFriendConfig     *config.SignedConfig

	dialingRounds     map[uint32]*dialingRoundState
	dialingConfigHash string
	dialingConfig     *config.SignedConfig

	friends                map[string]*Friend
	incomingFriendRequests []*IncomingFriendRequest
	outgoingFriendRequests []*OutgoingFriendRequest
	sentFriendRequests     []*sentFriendRequest
	outgoingCalls          []*OutgoingCall

	addFriendConn typesocket.Conn
	dialingConn   typesocket.Conn
}

func (c *Client) init() {
	c.initOnce.Do(func() {
		c.edhttpClient = new(edhttp.Client)

		if c.friends == nil {
			c.friends = make(map[string]*Friend)
		}

		c.addFriendRounds = make(map[uint32]*addFriendRoundState)
		c.dialingRounds = make(map[uint32]*dialingRoundState)
	})
}

// Register registers the username with the given PKG.
func (c *Client) Register(server pkg.PublicServerConfig) error {
	c.init()

	pkgc := &pkg.Client{
		Username:        c.Username,
		LoginKey:        c.PKGLoginKey,
		UserLongTermKey: c.LongTermPublicKey,
		HTTPClient:      c.edhttpClient,
	}
	err := pkgc.Register(server)
	if err != nil {
		return err
	}

	return err
}

type PKGStatus struct {
	Server pkg.PublicServerConfig
	Error  error
}

func (c *Client) PKGStatus() []PKGStatus {
	c.init()

	pkgc := &pkg.Client{
		Username:        c.Username,
		LoginKey:        c.PKGLoginKey,
		UserLongTermKey: c.LongTermPublicKey,
		HTTPClient:      c.edhttpClient,
	}
	c.mu.Lock()
	conf := c.addFriendConfig
	c.mu.Unlock()
	addFriendConfig := conf.Inner.(*config.AddFriendConfig)

	statuses := make([]PKGStatus, len(addFriendConfig.PKGServers))
	for i, pkgServer := range addFriendConfig.PKGServers {
		statuses[i].Server = pkgServer
		statuses[i].Error = pkgc.CheckStatus(pkgServer)
	}
	return statuses
}

func (c *Client) ConnectAddFriend() (chan error, error) {
	c.init()

	if c.ConfigClient == nil {
		return nil, errors.New("no config client")
	}

	c.mu.Lock()
	if c.addFriendConfig == nil {
		c.mu.Unlock()
		return nil, errors.New("no addfriend config")
	}
	c.mu.Unlock()

	// Fetch the current config to get the coordinator's key and address.
	addFriendConfig, err := c.ConfigClient.CurrentConfig("AddFriend")
	if err != nil {
		return nil, errors.Wrap(err, "fetching addfriend config")
	}
	addFriendInner := addFriendConfig.Inner.(*config.AddFriendConfig)

	afwsAddr := fmt.Sprintf("wss://%s/addfriend/ws", addFriendInner.Coordinator.Address)
	addFriendConn, err := typesocket.Dial(afwsAddr, addFriendInner.Coordinator.Key)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.addFriendConn = addFriendConn
	c.mu.Unlock()

	disconnect := make(chan error, 1)
	go func() {
		disconnect <- addFriendConn.Serve(c.addFriendMux())
	}()

	return disconnect, nil
}

func (c *Client) ConnectDialing() (chan error, error) {
	c.init()

	if c.ConfigClient == nil {
		return nil, errors.New("no config client")
	}

	c.mu.Lock()
	if c.dialingConfig == nil {
		c.mu.Unlock()
		return nil, errors.New("no dialing config")
	}
	c.mu.Unlock()

	dialingConfig, err := c.ConfigClient.CurrentConfig("Dialing")
	if err != nil {
		return nil, errors.Wrap(err, "fetching dialing config")
	}
	dialingInner := dialingConfig.Inner.(*config.DialingConfig)

	dwsAddr := fmt.Sprintf("wss://%s/dialing/ws", dialingInner.Coordinator.Address)
	dialingConn, err := typesocket.Dial(dwsAddr, dialingInner.Coordinator.Key)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.dialingConn = dialingConn
	c.mu.Unlock()

	disconnect := make(chan error, 1)
	go func() {
		disconnect <- dialingConn.Serve(c.dialingMux())
	}()

	return disconnect, nil
}

func (c *Client) CloseAddFriend() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.addFriendConn != nil {
		return c.addFriendConn.Close()
	}
	return nil
}

func (c *Client) CloseDialing() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.dialingConn != nil {
		return c.dialingConn.Close()
	}
	return nil
}
