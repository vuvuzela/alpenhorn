// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package alpenhorn

import "vuvuzela.io/alpenhorn/config"

func (c *Client) Bootstrap(addFriendConfig, dialingConfig *config.SignedConfig) error {
	if err := addFriendConfig.Validate(); err != nil {
		return err
	}
	if err := dialingConfig.Validate(); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.addFriendConfig = addFriendConfig
	c.addFriendConfigHash = addFriendConfig.Hash()

	c.dialingConfig = dialingConfig
	c.dialingConfigHash = dialingConfig.Hash()

	return nil
}
