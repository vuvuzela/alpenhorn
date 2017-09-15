// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package config

import (
	"bytes"
	"encoding/json"
	"io/ioutil"

	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/internal/ioutil2"
)

type persistedState struct {
	AllConfigs        map[string]*SignedConfig
	CurrentConfigHash string
}

const persistVersion byte = 1

func writeState(path string, state *persistedState) error {
	buf := new(bytes.Buffer)
	buf.WriteByte(persistVersion)
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "  ")
	err := enc.Encode(state)
	if err != nil {
		return errors.Wrap(err, "json.Encode")
	}

	return ioutil2.WriteFileAtomic(path, buf.Bytes(), 0600)
}

func (srv *Server) persistLocked() error {
	state := &persistedState{
		AllConfigs:        srv.allConfigs,
		CurrentConfigHash: srv.currentConfigHash,
	}
	return writeState(srv.persistPath, state)
}

func LoadServer(persistPath string) (*Server, error) {
	data, err := ioutil.ReadFile(persistPath)
	if err != nil {
		return nil, err
	}
	if data[0] != persistVersion {
		return nil, errors.New("unknown state version: got %d, want %d", data[0], persistVersion)
	}
	var state persistedState
	err = json.Unmarshal(data[1:], &state)
	if err != nil {
		return nil, errors.Wrap(err, "json.Unmarshal")
	}
	if len(state.AllConfigs) == 0 {
		return nil, errors.New("no configs in persisted state")
	}
	_, ok := state.AllConfigs[state.CurrentConfigHash]
	if !ok {
		return nil, errors.New("current config %q not found in persisted state", state.CurrentConfigHash)
	}

	return &Server{
		persistPath: persistPath,

		allConfigs:        state.AllConfigs,
		currentConfigHash: state.CurrentConfigHash,
	}, nil
}

func CreateServerState(persistPath string, startingConfig *SignedConfig) error {
	if err := startingConfig.Validate(); err != nil {
		return err
	}

	hash := startingConfig.Hash()
	state := &persistedState{
		AllConfigs:        map[string]*SignedConfig{hash: startingConfig},
		CurrentConfigHash: hash,
	}

	return writeState(persistPath, state)
}
