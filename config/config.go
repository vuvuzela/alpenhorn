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
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/vuvuzela/mixnet"
)

// Use github.com/davidlazar/easyjson:
//go:generate easyjson .

const SignedConfigVersion = 1

// SignedConfig is an entry in a hash chain of configs.
type SignedConfig struct {
	Version int

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

func (c *SignedConfig) SigningMessage() []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("SignedConfig")

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
	if c.Version <= 0 {
		return errors.New("invalid version number: %d", c.Version)
	}
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
type signedConfigV1 struct {
	Version int

	Created        time.Time
	Expires        time.Time
	PrevConfigHash string

	Service string
	Inner   json.RawMessage

	Guardians []Guardian

	Signatures map[string][]byte
}

func (c *SignedConfig) MarshalJSON() ([]byte, error) {
	switch c.Version {
	case 1:
		innerJSON, err := json.Marshal(c.Inner)
		if err != nil {
			return nil, err
		}
		c1 := &signedConfigV1{
			Version: 1,

			Created:        c.Created,
			Expires:        c.Expires,
			PrevConfigHash: c.PrevConfigHash,

			Service: c.Service,
			Inner:   innerJSON,

			Guardians:  c.Guardians,
			Signatures: c.Signatures,
		}
		return json.Marshal(c1)
	default:
		return nil, errors.New("unknown SignedConfig version: %d", c.Version)
	}
}

func (c *SignedConfig) UnmarshalJSON(data []byte) error {
	version, err := getVersionFromJSON(data)
	if err != nil {
		return err
	}

	switch version {
	case 1:
		c1 := new(signedConfigV1)
		err := json.Unmarshal(data, c1)
		if err != nil {
			return err
		}

		inner, err := decodeInner(c1.Service, c1.Inner)
		if err != nil {
			return err
		}

		c.Version = 1

		c.Created = c1.Created
		c.Expires = c1.Expires
		c.PrevConfigHash = c1.PrevConfigHash

		c.Service = c1.Service
		c.Inner = inner

		c.Guardians = c1.Guardians
		c.Signatures = c1.Signatures
	default:
		return errors.New("unknown SignedConfig version: %d", c.Version)
	}

	return nil
}

func decodeInner(service string, rawJSON json.RawMessage) (InnerConfig, error) {
	registerMu.Lock()
	innerType, ok := registeredServices[service]
	registerMu.Unlock()
	if !ok {
		return nil, errors.New("unregistered service unmarshaling config: %q", service)
	}

	rawInner := reflect.New(innerType).Interface()
	err := json.Unmarshal(rawJSON, rawInner)
	if err != nil {
		return nil, err
	}
	inner := rawInner.(InnerConfig)
	return inner, nil
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

const AddFriendConfigVersion = 2

type AddFriendConfig struct {
	Version     int
	Coordinator CoordinatorConfig
	PKGServers  []pkg.PublicServerConfig
	MixServers  []mixnet.PublicServerConfig
	CDNServer   CDNServerConfig
	Registrar   RegistrarConfig
}

//easyjson:readable
type RegistrarConfig struct {
	Key     ed25519.PublicKey
	Address string
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

//easyjson:readable
type addFriendV1 struct {
	Version       int
	Coordinator   keyAddr
	PKGServers    []keyAddr
	MixServers    []keyAddr
	CDNServer     keyAddr
	RegistrarHost string
}

//easyjson:readable
type addFriendV2 struct {
	Version     int
	Coordinator keyAddr
	PKGServers  []keyAddr
	MixServers  []keyAddr
	CDNServer   keyAddr
	Registrar   keyAddr
}

//easyjson:readable
type keyAddr struct {
	Key     ed25519.PublicKey
	Address string
}

func (c *AddFriendConfig) v1() (*addFriendV1, error) {
	c1 := &addFriendV1{
		Version:       1,
		Coordinator:   keyAddr{c.Coordinator.Key, c.Coordinator.Address},
		PKGServers:    make([]keyAddr, len(c.PKGServers)),
		MixServers:    make([]keyAddr, len(c.MixServers)),
		CDNServer:     keyAddr{c.CDNServer.Key, c.CDNServer.Address},
		RegistrarHost: c.Registrar.Address,
	}
	for i, srv := range c.PKGServers {
		c1.PKGServers[i] = keyAddr{srv.Key, srv.Address}
	}
	for i, srv := range c.MixServers {
		c1.MixServers[i] = keyAddr{srv.Key, srv.Address}
	}
	return c1, nil
}

func (c *AddFriendConfig) v2() (*addFriendV2, error) {
	c2 := &addFriendV2{
		Version:     2,
		Coordinator: keyAddr{c.Coordinator.Key, c.Coordinator.Address},
		PKGServers:  make([]keyAddr, len(c.PKGServers)),
		MixServers:  make([]keyAddr, len(c.MixServers)),
		CDNServer:   keyAddr{c.CDNServer.Key, c.CDNServer.Address},
		Registrar:   keyAddr{c.Registrar.Key, c.Registrar.Address},
	}
	for i, srv := range c.PKGServers {
		c2.PKGServers[i] = keyAddr{srv.Key, srv.Address}
	}
	for i, srv := range c.MixServers {
		c2.MixServers[i] = keyAddr{srv.Key, srv.Address}
	}
	return c2, nil
}

func (c *AddFriendConfig) fromV1(c1 *addFriendV1) error {
	c.Version = 1
	c.Coordinator = CoordinatorConfig{c1.Coordinator.Key, c1.Coordinator.Address}
	c.PKGServers = make([]pkg.PublicServerConfig, len(c1.PKGServers))
	c.MixServers = make([]mixnet.PublicServerConfig, len(c1.MixServers))
	c.CDNServer = CDNServerConfig{c1.CDNServer.Key, c1.CDNServer.Address}
	for i, srv := range c1.PKGServers {
		c.PKGServers[i] = pkg.PublicServerConfig{Key: srv.Key, Address: srv.Address}
	}
	for i, srv := range c1.MixServers {
		c.MixServers[i] = mixnet.PublicServerConfig{Key: srv.Key, Address: srv.Address}
	}
	c.Registrar.Address = c1.RegistrarHost
	return nil
}

func (c *AddFriendConfig) fromV2(c2 *addFriendV2) error {
	c.Version = 2
	c.Coordinator = CoordinatorConfig{c2.Coordinator.Key, c2.Coordinator.Address}
	c.PKGServers = make([]pkg.PublicServerConfig, len(c2.PKGServers))
	c.MixServers = make([]mixnet.PublicServerConfig, len(c2.MixServers))
	c.CDNServer = CDNServerConfig{c2.CDNServer.Key, c2.CDNServer.Address}
	for i, srv := range c2.PKGServers {
		c.PKGServers[i] = pkg.PublicServerConfig{Key: srv.Key, Address: srv.Address}
	}
	for i, srv := range c2.MixServers {
		c.MixServers[i] = mixnet.PublicServerConfig{Key: srv.Key, Address: srv.Address}
	}
	c.Registrar = RegistrarConfig{c2.Registrar.Key, c2.Registrar.Address}
	return nil
}

func (c *AddFriendConfig) Validate() error {
	if c.Version <= 0 {
		return errors.New("invalid version number: %d", c.Version)
	}
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

func (c *AddFriendConfig) MarshalJSON() ([]byte, error) {
	switch c.Version {
	case 1:
		c1, err := c.v1()
		if err != nil {
			return nil, err
		}
		return json.Marshal(c1)
	case 2:
		c2, err := c.v2()
		if err != nil {
			return nil, err
		}
		return json.Marshal(c2)
	default:
		return nil, errors.New("unknown AddFriendConfig version: %d", c.Version)
	}
}

func (c *AddFriendConfig) UnmarshalJSON(data []byte) error {
	version, err := getVersionFromJSON(data)
	if err != nil {
		return err
	}
	switch version {
	case 1:
		c1 := new(addFriendV1)
		err := json.Unmarshal(data, c1)
		if err != nil {
			return err
		}
		return c.fromV1(c1)
	case 2:
		c2 := new(addFriendV2)
		err := json.Unmarshal(data, c2)
		if err != nil {
			return err
		}
		return c.fromV2(c2)
	default:
		return errors.New("unknown AddFriendConfig version: %d", version)
	}
}

const DialingConfigVersion = 1

type DialingConfig struct {
	Version     int
	Coordinator CoordinatorConfig
	MixServers  []mixnet.PublicServerConfig
	CDNServer   CDNServerConfig
}

//easyjson:readable
type dialingV1 struct {
	Version     int
	Coordinator keyAddr
	MixServers  []keyAddr
	CDNServer   keyAddr
}

func (c *DialingConfig) v1() (*dialingV1, error) {
	c1 := &dialingV1{
		Version:     1,
		Coordinator: keyAddr{c.Coordinator.Key, c.Coordinator.Address},
		MixServers:  make([]keyAddr, len(c.MixServers)),
		CDNServer:   keyAddr{c.CDNServer.Key, c.CDNServer.Address},
	}
	for i, srv := range c.MixServers {
		c1.MixServers[i] = keyAddr{srv.Key, srv.Address}
	}
	return c1, nil
}

func (c *DialingConfig) fromV1(c1 *dialingV1) error {
	c.Version = 1
	c.Coordinator = CoordinatorConfig{c1.Coordinator.Key, c1.Coordinator.Address}
	c.MixServers = make([]mixnet.PublicServerConfig, len(c1.MixServers))
	c.CDNServer = CDNServerConfig{c1.CDNServer.Key, c1.CDNServer.Address}
	for i, srv := range c1.MixServers {
		c.MixServers[i] = mixnet.PublicServerConfig{Key: srv.Key, Address: srv.Address}
	}
	return nil
}

func (c *DialingConfig) MarshalJSON() ([]byte, error) {
	switch c.Version {
	case 1:
		c1, err := c.v1()
		if err != nil {
			return nil, err
		}
		return json.Marshal(c1)
	default:
		return nil, errors.New("unknown DialingConfig version: %d", c.Version)
	}
}

func (c *DialingConfig) UnmarshalJSON(data []byte) error {
	version, err := getVersionFromJSON(data)
	if err != nil {
		return err
	}
	switch version {
	case 1:
		c1 := new(dialingV1)
		err := json.Unmarshal(data, c1)
		if err != nil {
			return err
		}
		return c.fromV1(c1)
	default:
		return errors.New("unknown DialingConfig version: %d", version)
	}
}

func (c *DialingConfig) Validate() error {
	if c.Version <= 0 {
		return errors.New("invalid version number: %d", c.Version)
	}
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

func getVersionFromJSON(data []byte) (int, error) {
	type ver struct {
		Version int
	}
	v := new(ver)
	err := json.Unmarshal(data, v)
	if err != nil {
		return -1, err
	}
	return v.Version, nil
}
