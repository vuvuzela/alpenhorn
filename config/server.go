// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package config

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
)

type Server struct {
	persistPath string

	mu                sync.Mutex
	allConfigs        map[string]*SignedConfig
	currentConfigHash string
}

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/get") {
		srv.getConfigsHandler(w, r)
	} else if strings.HasPrefix(r.URL.Path, "/new") {
		srv.newConfigHandler(w, r)
	} else if strings.HasPrefix(r.URL.Path, "/current") {
		srv.getCurrentHashHandler(w, r)
	} else {
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (srv *Server) newConfigHandler(w http.ResponseWriter, req *http.Request) {
	nextConfig := new(SignedConfig)
	if err := json.NewDecoder(req.Body).Decode(nextConfig); err != nil {
		log.Fatal(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
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

	if nextConfig.Service != prevConfig.Service {
		http.Error(w,
			fmt.Sprintf("invalid service type: got %q, want %q", nextConfig.Service, prevConfig.Service),
			http.StatusBadRequest,
		)
		return
	}

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

	srv.currentConfigHash = nextConfig.Hash()
	srv.allConfigs[srv.currentConfigHash] = nextConfig

	if err := srv.persistLocked(); err != nil {
		http.Error(w, fmt.Sprintf("error persisting state: %s", err), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("updated config"))
}

// CurrentConfig returns the server's current config and its hash.
// The result must not be modified.
func (srv *Server) CurrentConfig() (*SignedConfig, string) {
	srv.mu.Lock()
	hash := srv.currentConfigHash
	config := srv.allConfigs[hash]
	srv.mu.Unlock()
	return config, hash
}

func (srv *Server) getCurrentHashHandler(w http.ResponseWriter, req *http.Request) {
	srv.mu.Lock()
	hash := srv.currentConfigHash
	srv.mu.Unlock()
	w.Write([]byte(hash))
}

func (srv *Server) getConfigsHandler(w http.ResponseWriter, req *http.Request) {
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
