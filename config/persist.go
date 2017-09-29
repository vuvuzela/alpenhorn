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
	AllConfigs    map[string]*SignedConfig
	CurrentConfig map[string]string
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
		AllConfigs:    srv.allConfigs,
		CurrentConfig: srv.currentConfig,
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

	for service, hash := range state.CurrentConfig {
		_, ok := state.AllConfigs[hash]
		if !ok {
			return nil, errors.New("current %q config (%q) not found in persisted state", service, hash)
		}
	}

	return &Server{
		persistPath: persistPath,

		allConfigs:    state.AllConfigs,
		currentConfig: state.CurrentConfig,
	}, nil
}

func CreateServer(persistPath string) (*Server, error) {
	server := &Server{
		persistPath:   persistPath,
		allConfigs:    make(map[string]*SignedConfig),
		currentConfig: make(map[string]string),
	}
	err := server.persistLocked()
	return server, err
}
