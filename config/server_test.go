// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package config

import (
	"crypto/rand"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/ed25519"
)

func TestServer(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "alpenhorn_config_test")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)
	persistPath := filepath.Join(tmpDir, "config-server-state")

	guardian1Public, guardian1Private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	_ = guardian1Private

	startingConfig := &SignedConfig{
		Version: 1,

		Created: time.Now(),
		Expires: time.Now().Add(24 * time.Hour),

		Service: "AddFriend",
		Inner: &AddFriendConfig{
			Version: 1,

			Coordinator: CoordinatorConfig{
				Key:     guardian1Public,
				Address: "localhost:1234",
			},
			CDNServer: CDNServerConfig{
				Address: "localhost:8080",
				Key:     guardian1Public,
			},
		},

		Guardians: []Guardian{
			{
				Username: "guardian1",
				Key:      guardian1Public,
			},
		},
	}

	server, err := CreateServer(persistPath)
	if err != nil {
		t.Fatal(err)
	}
	err = server.SetCurrentConfig(startingConfig)
	if err != nil {
		t.Fatal(err)
	}

	server, err = LoadServer(persistPath)
	if err != nil {
		t.Fatal(err)
	}

	_, currHash := server.CurrentConfig("AddFriend")
	if currHash != startingConfig.Hash() {
		t.Fatal("wrong current config hash")
	}

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		err := http.Serve(listener, server)
		if err != http.ErrServerClosed {
			t.Fatal(err)
		}
	}()
	client := &Client{
		ConfigServerURL: "http://" + listener.Addr().String(),
	}

	newConfig := &SignedConfig{
		Version: 1,

		Created: time.Now(),
		Expires: time.Now().Add(24 * time.Hour),

		PrevConfigHash: startingConfig.Hash(),

		Service: "AddFriend",
		Inner: &AddFriendConfig{
			Version: 1,

			Coordinator: CoordinatorConfig{
				Key:     guardian1Public,
				Address: "localhost:1234",
			},
			CDNServer: CDNServerConfig{
				Address: "localhost:8081",
				Key:     guardian1Public,
			},
		},
	}

	{
		// Try uploading a new config without the guardian's signature.
		err := client.SetCurrentConfig(newConfig)
		if err == nil {
			t.Fatal("expecting error")
		}
	}

	// Sign the new config and try again.
	newConfig.Signatures = make(map[string][]byte)
	gk := base32.EncodeToString(guardian1Public)
	newConfig.Signatures[gk] = ed25519.Sign(guardian1Private, newConfig.SigningMessage())

	{
		err := client.SetCurrentConfig(newConfig)
		if err != nil {
			t.Fatal(err)
		}
	}

	{
		conf, err := client.CurrentConfig("AddFriend")
		if err != nil {
			t.Fatal(err)
		}

		if conf.Hash() != newConfig.Hash() {
			t.Fatalf("bad response config: got %q, want %q", conf.Hash(), newConfig.Hash())
		}
	}

	{
		chain, err := client.FetchAndVerifyChain(startingConfig, newConfig.Hash())
		if err != nil {
			t.Fatal(err)
		}

		if chain[0].Hash() != newConfig.Hash() {
			t.Fatal("wrong config in chain")
		}
	}
}
