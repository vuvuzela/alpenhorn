// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/edhttp"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/internal/debug"
)

type Client struct {
	ConfigURL  string
	ServerKey  ed25519.PublicKey
	HTTPClient *edhttp.Client
}

func (c Client) FetchAndVerifyConfig(have *SignedConfig, want string) (*SignedConfig, error) {
	url := fmt.Sprintf("%s/get?have=%s&want=%s", c.ConfigURL, have.Hash(), want)
	resp, err := c.HTTPClient.Get(c.ServerKey, url)
	if err != nil {
		return nil, errors.Wrap(err, "fetching new config")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("error fetching %q: %s", url, resp.Status)
	}

	var configs []*SignedConfig
	if err := json.NewDecoder(resp.Body).Decode(&configs); err != nil {
		return nil, errors.Wrap(err, "unmarshaling configs")
	}

	newConfig := configs[0]
	if err := newConfig.Validate(); err != nil {
		return nil, err
	}
	if newConfig.Hash() != want {
		return nil, errors.New("received config with wrong hash: want %q, got %q\n->%s\n", want, newConfig.Hash(), debug.Pretty(newConfig))
	}
	if newConfig.Service != have.Service {
		return nil, errors.New("received config for wrong service type: want %q, got %q", have.Service, newConfig.Service)
	}
	if !newConfig.Created.After(have.Created) {
		return nil, errors.New("new config not created after prev config: prev=%s  next=%s", have.Hash(), newConfig.Hash())
	}
	if time.Now().After(newConfig.Expires) {
		return nil, errors.New("config expired on %s", newConfig.Expires)
	}

	configs = append(configs, have)
	err = VerifyConfigChain(configs...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify new config")
	}

	return newConfig, nil
}
