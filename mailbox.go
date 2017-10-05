// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package alpenhorn

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net/url"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/errors"
)

func (c *Client) fetchMailbox(cdnConfig config.CDNServerConfig, baseURL string, mailboxID uint32) ([]byte, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, errors.Wrap(err, "parsing mailbox url")
	}
	vals := u.Query()
	vals.Set("key", fmt.Sprintf("%d", mailboxID))
	u.RawQuery = vals.Encode()

	resp, err := c.edhttpClient.Get(cdnConfig.Key, u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	mailbox, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "reading mailbox body")
	}
	return mailbox, nil
}

func usernameToMailbox(username string, numMailboxes uint32) uint32 {
	h := sha256.Sum256([]byte(username))
	k := binary.BigEndian.Uint32(h[0:4])
	mbox := k%numMailboxes + 1
	// do this check at the end to minimize timing leak
	if username == "" {
		return 0
	} else {
		return mbox
	}
}
