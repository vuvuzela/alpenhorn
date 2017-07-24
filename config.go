package alpenhorn

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"vuvuzela.io/alpenhorn/coordinator"
	"vuvuzela.io/alpenhorn/errors"
)

func (c *Client) fetchAndVerifyConfig(have *coordinator.AlpenhornConfig, want string) (*coordinator.AlpenhornConfig, error) {
	url := fmt.Sprintf("https://%s/%s/config?have=%s&want=%s", c.CoordinatorAddress, strings.ToLower(have.Service), have.Hash(), want)
	resp, err := c.edhttpClient.Get(c.CoordinatorKey, url)
	if err != nil {
		return nil, errors.Wrap(err, "fetching new config")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("error fetching %q: %s", url, resp.Status)
	}

	var configs []*coordinator.AlpenhornConfig
	if err := json.NewDecoder(resp.Body).Decode(&configs); err != nil {
		return nil, errors.Wrap(err, "unmarshaling configs")
	}

	config := configs[0]
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if config.Hash() != want {
		return nil, errors.New("received config with wrong hash: want %q, got %q", want, config.Hash())
	}
	if config.Service != have.Service {
		return nil, errors.New("received config for wrong service type: want %q, got %q", have.Service, config.Service)
	}
	if !config.Created.After(have.Created) {
		return nil, errors.New("new config not created after prev config: prev=%s  next=%s", have.Hash(), config.Hash())
	}
	if time.Now().After(config.Expires) {
		return nil, errors.New("config expired on %s", config.Expires)
	}

	configs = append(configs, have)
	err = coordinator.VerifyConfigChain(configs...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify new config")
	}

	return config, nil
}
