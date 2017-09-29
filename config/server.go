// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

type Server struct {
	persistPath string

	mu         sync.Mutex
	allConfigs map[string]*SignedConfig

	// currentConfig is a map from service name to current config hash.
	currentConfig map[string]string
}

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/getchain") {
		srv.getChainHandler(w, r)
	} else if strings.HasPrefix(r.URL.Path, "/current") {
		srv.getCurrentHandler(w, r)
	} else if strings.HasPrefix(r.URL.Path, "/new") {
		srv.newConfigHandler(w, r)
	} else if r.URL.Path == "/" {
		w.Write([]byte("Alpenhorn config server."))
	} else {
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (srv *Server) newConfigHandler(w http.ResponseWriter, req *http.Request) {
	nextConfig := new(SignedConfig)
	if err := json.NewDecoder(req.Body).Decode(nextConfig); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := nextConfig.Validate(); err != nil {
		http.Error(w, fmt.Sprintf("invalid config: %s", err), http.StatusBadRequest)
		return
	}

	service := nextConfig.Service

	srv.mu.Lock()
	defer srv.mu.Unlock()

	prevHash, ok := srv.currentConfig[service]
	if !ok {
		http.Error(w,
			fmt.Sprintf("unknown service type: %q", service),
			http.StatusBadRequest,
		)
		return
	}

	if nextConfig.PrevConfigHash != prevHash {
		http.Error(w,
			fmt.Sprintf("prev config hash does not match current config hash: got %q want %q", nextConfig.PrevConfigHash, prevHash),
			http.StatusBadRequest,
		)
		return
	}

	prevConfig := srv.allConfigs[prevHash]

	if !nextConfig.Created.After(prevConfig.Created) {
		http.Error(w,
			fmt.Sprintf("new config was not created after previous config: %s <= %s", nextConfig.Created, prevConfig.Created),
			http.StatusBadRequest,
		)
		return
	}

	if err := VerifyConfigChain(nextConfig, prevConfig); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	nextHash := nextConfig.Hash()
	srv.currentConfig[service] = nextHash
	srv.allConfigs[nextHash] = nextConfig

	if err := srv.persistLocked(); err != nil {
		http.Error(w, fmt.Sprintf("error persisting state: %s", err), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("updated config"))
}

func (srv *Server) SetCurrentConfig(config *SignedConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()

	hash := config.Hash()
	srv.allConfigs[hash] = config
	srv.currentConfig[config.Service] = hash

	return srv.persistLocked()
}

// CurrentConfig returns the server's current config and its hash.
// The result must not be modified.
func (srv *Server) CurrentConfig(service string) (*SignedConfig, string) {
	srv.mu.Lock()
	hash := srv.currentConfig[service]
	config := srv.allConfigs[hash]
	srv.mu.Unlock()
	return config, hash
}

func (srv *Server) getCurrentHandler(w http.ResponseWriter, req *http.Request) {
	service := req.URL.Query().Get("service")
	if service == "" {
		http.Error(w, "no service specified in query", http.StatusBadRequest)
		return
	}

	srv.mu.Lock()
	hash, ok := srv.currentConfig[service]
	conf := srv.allConfigs[hash]
	srv.mu.Unlock()

	if !ok {
		http.Error(w, fmt.Sprintf("service not found: %q", service), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(conf)
}

func (srv *Server) getChainHandler(w http.ResponseWriter, req *http.Request) {
	have := req.URL.Query().Get("have")
	if have == "" {
		http.Error(w, "no have hash specified in query", http.StatusBadRequest)
		return
	}
	want := req.URL.Query().Get("want")
	if want == "" {
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

	configs := make([]*SignedConfig, 1)
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
