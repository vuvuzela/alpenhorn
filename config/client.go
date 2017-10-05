// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/internal/debug"
)

var StdClient = &Client{
	ConfigServerURL: "https://configs.vuvuzela.io",
}

type Client struct {
	ConfigServerURL string
}

func (c *Client) CurrentConfig(service string) (*SignedConfig, error) {
	url := fmt.Sprintf("%s/current?service=%s", c.ConfigServerURL, service)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.New("Get %q: %s: %q", url, resp.Status, msg)
	}

	var config *SignedConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, errors.Wrap(err, "unmarshaling config")
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}
	if config.Service != service {
		return nil, errors.New("received config for wrong service type: want %q, got %q", service, config.Service)
	}
	if time.Now().After(config.Expires) {
		return nil, errors.New("config expired on %s", config.Expires)
	}
	if err := config.Verify(); err != nil {
		return nil, err
	}

	return config, nil
}

// FetchAndVerifyChain fetches and verifies a config chain starting with
// the have config and ending with the want config. The chain is returned
// in reverse order so chain[0].Hash() = want and chain[len(chain)-1] = have.
func (c *Client) FetchAndVerifyChain(have *SignedConfig, want string) ([]*SignedConfig, error) {
	url := fmt.Sprintf("%s/getchain?have=%s&want=%s", c.ConfigServerURL, have.Hash(), want)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.New("Get %q: %s: %q", url, resp.Status, msg)
	}

	var configs []*SignedConfig
	if err := json.NewDecoder(resp.Body).Decode(&configs); err != nil {
		return nil, errors.Wrap(err, "unmarshaling configs")
	}
	if len(configs) == 0 {
		return nil, errors.New("no configs returned from server")
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

	return configs, nil
}

func (c *Client) SetCurrentConfig(conf *SignedConfig) error {
	body := new(bytes.Buffer)
	err := json.NewEncoder(body).Encode(conf)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/new", c.ConfigServerURL)
	resp, err := http.Post(url, "application/json", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := ioutil.ReadAll(resp.Body)
		return errors.New("error setting %q config: %s: %q", conf.Service, resp.Status, msg)
	}

	return nil
}
