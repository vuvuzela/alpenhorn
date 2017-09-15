// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package config

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/edhttp"
	"vuvuzela.io/alpenhorn/edtls"
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
		Created: time.Now(),

		Service: "AddFriend",
		Inner: &AddFriendConfig{
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

	err = CreateServerState(persistPath, startingConfig)
	if err != nil {
		t.Fatal(err)
	}

	server, err := LoadServer(persistPath)
	if err != nil {
		t.Fatal(err)
	}

	if server.currentConfigHash != startingConfig.Hash() {
		t.Fatal("wrong current config hash")
	}

	coordinatorPublic, coordinatorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	listener, err := edtls.Listen("tcp", "localhost:0", coordinatorPrivate)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		err := http.Serve(listener, server)
		if err != http.ErrServerClosed {
			t.Fatal(err)
		}
	}()

	newConfig := &SignedConfig{
		Created:        time.Now(),
		PrevConfigHash: startingConfig.Hash(),

		Service: "AddFriend",
		Inner: &AddFriendConfig{
			CDNServer: CDNServerConfig{
				Address: "localhost:8081",
				Key:     guardian1Public,
			},
		},
	}
	client := &edhttp.Client{}
	baseURL := fmt.Sprintf("https://%s", listener.Addr().String())

	{
		// Try uploading a new config without the guardian's signature.
		resp, err := client.PostJSON(coordinatorPublic, baseURL+"/new", newConfig)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			msg, _ := ioutil.ReadAll(resp.Body)
			t.Fatalf("bad status code: %s: %q", resp.Status, msg)
		}
		resp.Body.Close()
	}

	// Sign the new config and try again.
	newConfig.Signatures = make(map[string][]byte)
	gk := base32.EncodeToString(guardian1Public)
	newConfig.Signatures[gk] = ed25519.Sign(guardian1Private, newConfig.SigningMessage())

	{
		resp, err := client.PostJSON(coordinatorPublic, baseURL+"/new", newConfig)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			msg, _ := ioutil.ReadAll(resp.Body)
			t.Fatalf("bad status code: %s: %q", resp.Status, msg)
		}
		resp.Body.Close()
	}

	{
		resp, err := client.Get(coordinatorPublic, baseURL+"/current")
		if err != nil {
			t.Fatal(err)
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("bad status code: %s: %q", resp.Status, body)
		}

		if string(body) != newConfig.Hash() {
			t.Fatalf("bad response body: got %q, want %q", string(body), newConfig.Hash())
		}
	}

	{
		url := fmt.Sprintf("%s/get?have=%s&want=%s", baseURL, startingConfig.Hash(), newConfig.Hash())
		resp, err := client.Get(coordinatorPublic, url)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			msg, _ := ioutil.ReadAll(resp.Body)
			t.Fatalf("bad status code: %s: %q", resp.Status, msg)
		}
		var chain []*SignedConfig
		err = json.NewDecoder(resp.Body).Decode(&chain)
		if err != nil {
			t.Fatal(err)
		}

		chain = append(chain, startingConfig)
		err = VerifyConfigChain(chain...)
		if err != nil {
			t.Fatal(err)
		}
	}
}
