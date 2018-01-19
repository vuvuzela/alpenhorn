// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package config

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"reflect"
	"sync"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/mixnet"
	"vuvuzela.io/alpenhorn/pkg"
)

// Use github.com/davidlazar/easyjson:
//go:generate easyjson .

// SignedConfig is an entry in a hash chain of configs.
//easyjson:nounmarshal,readable
type SignedConfig struct {
	// Service is the name of the service this config corresponds to
	// (e.g., "AddFriend", "Dialing", or "Convo").
	Service string

	Created        time.Time
	Expires        time.Time
	PrevConfigHash string

	// Inner is the configuration specific to a service. The type of
	// the inner config should correspond to the the service name in
	// the signed config.
	Inner InnerConfig

	// Guardians is the set of keys that must sign the next config
	// to replace this config.
	Guardians []Guardian

	// Signatures is a map from base32-encoded signing keys to signatures.
	Signatures map[string][]byte
}

type InnerConfig interface {
	Validate() error

	// The InnerConfig must be marshalable as JSON.
}

//easyjson:readable
type Guardian struct {
	Username string
	Key      ed25519.PublicKey
}

const configVersion byte = 1

func (c *SignedConfig) SigningMessage() []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("SignedConfig")
	buf.WriteByte(configVersion)

	clone := *c
	clone.Signatures = nil

	err := json.NewEncoder(buf).Encode(clone)
	if err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func VerifyConfigChain(configs ...*SignedConfig) error {
	if len(configs) < 2 {
		panic("short config chain")
	}

	for i, curr := range configs {
		if i == len(configs)-1 {
			break
		}
		prev := configs[i+1]

		if curr.PrevConfigHash != prev.Hash() {
			return errors.New("config %d: bad PrevConfigHash", i)
		}

		msg := curr.SigningMessage()
		verified := make(map[string]bool)
		for _, guardian := range prev.Guardians {
			keystr := base32.EncodeToString(guardian.Key)
			sig, ok := curr.Signatures[keystr]
			if !ok {
				return errors.New("config %d: missing signature for key %s: %s", i, guardian.Username, keystr)
			}
			if !ed25519.Verify(guardian.Key, msg, sig) {
				return errors.New("config %d: invalid signature for key %s: %s", i, guardian.Username, keystr)
			}
			verified[keystr] = true
		}
		for _, guardian := range curr.Guardians {
			keystr := base32.EncodeToString(guardian.Key)
			if verified[keystr] {
				continue
			}
			sig, ok := curr.Signatures[keystr]
			if !ok {
				return errors.New("config %d: missing signature for key %s: %s", i, guardian.Username, keystr)
			}
			if !ed25519.Verify(guardian.Key, msg, sig) {
				return errors.New("config %d: invalid signature for key %s: %s", i, guardian.Username, keystr)
			}
		}
	}

	return nil
}

func (c *SignedConfig) Verify() error {
	msg := c.SigningMessage()
	for _, guardian := range c.Guardians {
		keystr := base32.EncodeToString(guardian.Key)
		sig, ok := c.Signatures[keystr]
		if !ok {
			return errors.New("missing signature for key %s: %s", guardian.Username, keystr)
		}
		if !ed25519.Verify(guardian.Key, msg, sig) {
			return errors.New("invalid signature for key %s: %s", guardian.Username, keystr)
		}
	}
	return nil
}

func (c *SignedConfig) Validate() error {
	for i, guardian := range c.Guardians {
		if len(guardian.Key) != ed25519.PublicKeySize {
			return errors.New("invalid key for guardian %i: %v", i, guardian.Key)
		}
		if guardian.Username == "" {
			return errors.New("invalid username for guardian %d: %q", i, guardian.Username)
		}
	}

	if c.Service == "" {
		return errors.New("empty service name")
	}
	if c.Inner == nil {
		return errors.New("no inner config")
	}
	return c.Inner.Validate()
}

func (c *SignedConfig) Hash() string {
	msg := c.SigningMessage()
	h := sha512.Sum512_256(msg)
	return base32.EncodeToString(h[:])
}

//easyjson:readable
type configMsg struct {
	Created        time.Time
	Expires        time.Time
	PrevConfigHash string

	Service string
	Inner   json.RawMessage

	Guardians []Guardian

	Signatures map[string][]byte
}

var (
	registerMu sync.Mutex
	// registeredServices is a map from service name (e.g., "AddFriend")
	// to its corresponding inner config type.
	registeredServices = make(map[string]reflect.Type)
)

func RegisterService(service string, innerConfigType InnerConfig) {
	registerMu.Lock()
	registeredServices[service] = reflect.TypeOf(innerConfigType).Elem()
	registerMu.Unlock()
}

func init() {
	RegisterService("AddFriend", &AddFriendConfig{})
	RegisterService("Dialing", &DialingConfig{})
}

func (c *SignedConfig) UnmarshalJSON(data []byte) error {
	msg := new(configMsg)
	err := json.Unmarshal(data, msg)
	if err != nil {
		return err
	}

	registerMu.Lock()
	innerType, ok := registeredServices[msg.Service]
	registerMu.Unlock()
	if !ok {
		return errors.New("unregistered service unmarshaling config: %q", msg.Service)
	}

	rawInner := reflect.New(innerType).Interface()
	err = json.Unmarshal(msg.Inner, rawInner)
	if err != nil {
		return err
	}
	inner := rawInner.(InnerConfig)

	c.Created = msg.Created
	c.Expires = msg.Expires
	c.PrevConfigHash = msg.PrevConfigHash
	c.Service = msg.Service
	c.Inner = inner
	c.Guardians = msg.Guardians
	c.Signatures = msg.Signatures

	return nil
}

//easyjson:readable
type AddFriendConfig struct {
	Coordinator CoordinatorConfig
	PKGServers  []pkg.PublicServerConfig
	MixServers  []mixnet.PublicServerConfig
	CDNServer   CDNServerConfig
	// RegistarHost is the server that PKGs use to verify registration tokens.
	RegistrarHost string
}

//easyjson:readable
type DialingConfig struct {
	Coordinator CoordinatorConfig
	MixServers  []mixnet.PublicServerConfig
	CDNServer   CDNServerConfig
}

//easyjson:readable
type CoordinatorConfig struct {
	Key     ed25519.PublicKey
	Address string
}

//easyjson:readable
type CDNServerConfig struct {
	Key     ed25519.PublicKey
	Address string
}

func (c *AddFriendConfig) Validate() error {
	if c.Coordinator.Address == "" {
		return errors.New("empty address for coordinator")
	}
	if len(c.Coordinator.Key) != ed25519.PublicKeySize {
		return errors.New("invalid key for coordinator: %#v", c.Coordinator.Key)
	}

	for i, mix := range c.MixServers {
		if len(mix.Key) != ed25519.PublicKeySize {
			return errors.New("invalid key for mixer %d: %v", i, mix.Key)
		}
		if mix.Address == "" {
			return errors.New("empty address for mix server %d", i)
		}
	}

	if c.CDNServer.Address == "" {
		return errors.New("empty address for cdn server")
	}
	if len(c.CDNServer.Key) != ed25519.PublicKeySize {
		return errors.New("invalid key for cdn: %v", c.CDNServer.Key)
	}

	for i, pkg := range c.PKGServers {
		if len(pkg.Key) != ed25519.PublicKeySize {
			return errors.New("invalid key for pkg %d: %v", i, pkg.Key)
		}
		if pkg.Address == "" {
			return errors.New("empty address for pkg %d", i)
		}
	}

	return nil
}

func (c *DialingConfig) Validate() error {
	if c.Coordinator.Address == "" {
		return errors.New("empty address for coordinator")
	}
	if len(c.Coordinator.Key) != ed25519.PublicKeySize {
		return errors.New("invalid key for coordinator: %#v", c.Coordinator.Key)
	}

	for i, mix := range c.MixServers {
		if len(mix.Key) != ed25519.PublicKeySize {
			return errors.New("invalid key for mixer %d: %v", i, mix.Key)
		}
		if mix.Address == "" {
			return errors.New("empty address for mix server %d", i)
		}
	}

	if c.CDNServer.Address != "" && len(c.CDNServer.Key) != ed25519.PublicKeySize {
		return errors.New("invalid key for cdn: %v", c.CDNServer.Key)
	}

	return nil
}
