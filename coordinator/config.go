// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package coordinator

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/mixnet"
	"vuvuzela.io/alpenhorn/pkg"
)

// AlpenhornConfig is the public configuration for the add-friend or
// dialing protocols. The add-friend and dialing protocols each have their
// own configuration but they share the same type.
type AlpenhornConfig struct {
	Service string // "AddFriend" or "Dialing"

	Created        time.Time
	Expires        time.Time
	PrevConfigHash string

	// PKGServers is the PKG servers for the add-friend protocol.
	// This is empty for the dialing protocol configuration.
	PKGServers []pkg.PublicServerConfig `json:",omitempty"`

	MixServers []mixnet.PublicServerConfig
	CDNServer  CDNServerConfig
	Guardians  []Guardian

	// Signatures is a map from base32-encoded signing keys to signatures.
	Signatures map[string][]byte
}

type CDNServerConfig struct {
	Key     ed25519.PublicKey
	Address string
}

type Guardian struct {
	Username string
	Key      ed25519.PublicKey
}

const configVersion byte = 1

func (c *AlpenhornConfig) SigningMessage() []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("AlpenhornConfig")
	buf.WriteByte(configVersion)

	clone := *c
	clone.Signatures = nil

	err := json.NewEncoder(buf).Encode(clone)
	if err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func VerifyConfigChain(configs ...*AlpenhornConfig) error {
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
		for _, guardian := range prev.Guardians {
			keystr := base32.EncodeToString(guardian.Key)
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

func (c *AlpenhornConfig) Validate() error {
	for i, pkg := range c.PKGServers {
		if len(pkg.Key) != ed25519.PublicKeySize {
			return errors.New("invalid key for pkg %d: %v", i, pkg.Key)
		}
		if pkg.Address == "" {
			return errors.New("empty address for pkg %d", i)
		}
	}

	for i, mix := range c.MixServers {
		if len(mix.Key) != ed25519.PublicKeySize {
			return errors.New("invalid key for mix server %d: %v", i, mix.Key)
		}
		if mix.Address == "" {
			return errors.New("empty address for mix server %d", i)
		}
	}

	if c.CDNServer.Address != "" && len(c.CDNServer.Key) != ed25519.PublicKeySize {
		return errors.New("invalid key for cdn: %v", c.CDNServer.Key)
	}

	for i, guardian := range c.Guardians {
		if len(guardian.Key) != ed25519.PublicKeySize {
			return errors.New("invalid key for guardian %i: %v", i, guardian.Key)
		}
		if guardian.Username == "" {
			return errors.New("invalid username for guardian %d: %q", i, guardian.Username)
		}
	}

	return nil
}

func (c *AlpenhornConfig) Hash() string {
	msg := c.SigningMessage()
	h := sha512.Sum512_256(msg)
	return base32.EncodeToString(h[:])
}

func (srv *Server) newConfigHandler(w http.ResponseWriter, req *http.Request) {
	nextConfig := new(AlpenhornConfig)
	err := json.NewDecoder(req.Body).Decode(nextConfig)
	if err != nil {
		http.Error(w, "error unmarshaling json", http.StatusBadRequest)
		return
	}

	if nextConfig.Service != srv.Service {
		http.Error(w,
			fmt.Sprintf("invalid service type: got %q, want %q", nextConfig.Service, srv.Service),
			http.StatusBadRequest,
		)
		return
	}

	if err := nextConfig.Validate(); err != nil {
		http.Error(w, fmt.Sprintf("invalid config: %s", err), http.StatusBadRequest)
		return
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()

	if nextConfig.PrevConfigHash != srv.currentConfigHash {
		http.Error(w,
			fmt.Sprintf("prev config hash does not match current config hash: got %q want %q", nextConfig.PrevConfigHash, srv.currentConfigHash),
			http.StatusBadRequest,
		)
		return
	}

	prevConfig := srv.allConfigs[srv.currentConfigHash]
	if !nextConfig.Created.After(prevConfig.Created) {
		http.Error(w,
			fmt.Sprintf("new config was not created after previous config: %s <= %s", nextConfig.Created, prevConfig.Created),
			http.StatusBadRequest,
		)
		return
	}

	err = VerifyConfigChain(nextConfig, prevConfig)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	srv.currentConfigHash = nextConfig.Hash()
	srv.allConfigs[srv.currentConfigHash] = nextConfig

	w.Write([]byte("updated config"))
}

// CurrentConfig returns the current Alpenhorn configuration for
// testing/debugging. The result must not be modified.
func (srv *Server) CurrentConfig() *AlpenhornConfig {
	srv.mu.Lock()
	config := srv.allConfigs[srv.currentConfigHash]
	srv.mu.Unlock()
	return config
}

func (srv *Server) getConfigsHandler(w http.ResponseWriter, req *http.Request) {
	have := req.URL.Query().Get("have")
	if have == "" {
		http.Error(w, "no have hash specified in query", http.StatusBadRequest)
		return
	}
	want := req.URL.Query().Get("want")
	if have == "" {
		http.Error(w, "no want hash specified in query", http.StatusBadRequest)
		return
	}

	srv.mu.Lock()
	config, ok := srv.allConfigs[want]
	srv.mu.Unlock()
	if !ok {
		http.Error(w, "want hash not found", http.StatusBadRequest)
		return
	}

	configs := make([]*AlpenhornConfig, 1)
	configs[0] = config

	prevHash := config.PrevConfigHash
	for prevHash != have && prevHash != "" {
		srv.mu.Lock()
		prevConfig, ok := srv.allConfigs[prevHash]
		srv.mu.Unlock()
		if !ok {
			panic(fmt.Sprintf("prev config not found: hash %q", prevHash))
		}
		configs = append(configs, prevConfig)
		prevHash = prevConfig.PrevConfigHash
	}

	data, err := json.MarshalIndent(configs, "", "  ")
	if err != nil {
		panic("json marshal error")
	}

	w.Write(data)
}
