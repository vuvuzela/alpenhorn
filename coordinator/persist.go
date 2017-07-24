// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package coordinator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/internal/ioutil2"
)

// version is the current version number of the persisted state format.
const version byte = 1

type persistedState struct {
	Round             uint32
	CurrentConfigHash string
	Configs           map[string]*AlpenhornConfig
}

func (srv *Server) LoadPersistedState() error {
	data, err := ioutil.ReadFile(srv.PersistPath)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("no data: %s", srv.PersistPath)
	}

	ver := data[0]
	if ver != version {
		return fmt.Errorf("unexpected version: want version %d, got %d", version, ver)
	}

	var st persistedState
	err = json.Unmarshal(data[1:], &st)
	if err != nil {
		return err
	}

	srv.mu.Lock()
	srv.round = st.Round
	srv.allConfigs = st.Configs
	srv.currentConfigHash = st.CurrentConfigHash
	srv.mu.Unlock()

	return nil
}

// Bootstrap initializes the server for the first time. It creates
// the persisted state file for the server and sets the server's starting
// config. Bootstrap does not verify signatures on the starting config, so
// the config should be verified out-of-band. Future updates to the config
// will be verified using the config's Guardian keys.
//
// Bootstrap should only be called once, before the server is launched
// for the first time. Future launches of the server should call
// LoadPersistedState at startup to read the current config from disk.
func (srv *Server) Bootstrap(startingConfig *AlpenhornConfig) error {
	if err := startingConfig.Validate(); err != nil {
		return errors.Wrap(err, "invalid config")
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.allConfigs == nil {
		srv.allConfigs = make(map[string]*AlpenhornConfig)
	}
	hash := startingConfig.Hash()
	srv.allConfigs[hash] = startingConfig
	srv.currentConfigHash = hash

	return srv.persistLocked()
}

func (srv *Server) persistLocked() error {
	if srv.PersistPath == "" {
		return nil
	}

	st := &persistedState{
		Round:             srv.round,
		Configs:           srv.allConfigs,
		CurrentConfigHash: srv.currentConfigHash,
	}

	buf := new(bytes.Buffer)
	buf.WriteByte(version)
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "  ") // for easier debugging
	err := enc.Encode(st)
	if err != nil {
		return err
	}

	return ioutil2.WriteFileAtomic(srv.PersistPath, buf.Bytes(), 0600)
}
