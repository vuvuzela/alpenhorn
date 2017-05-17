// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package alpenhorn

import (
	"crypto/rand"
	"sync/atomic"

	"github.com/davidlazar/go-crypto/encoding/base32"
	log "github.com/sirupsen/logrus"

	"vuvuzela.io/alpenhorn/bloom"
	"vuvuzela.io/alpenhorn/coordinator"
	"vuvuzela.io/alpenhorn/dialing"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/typesocket"
	"vuvuzela.io/crypto/onionbox"
)

func (c *Client) dialingMux() typesocket.Mux {
	return typesocket.NewMux(map[string]interface{}{
		"mix":     c.sendDialingOnion,
		"mailbox": c.scanBloomFilter,
		"error":   c.dialingRoundError,
	})
}

func (c *Client) dialingRoundError(conn typesocket.Conn, v coordinator.RoundError) {
	log.Printf("dialing round error: %#v", v)
}

func (c *Client) sendDialingOnion(conn typesocket.Conn, v coordinator.MixRound) {
	round := v.MixSettings.Round

	for i, mixKey := range c.Mixers {
		if !v.MixSettings.Verify(mixKey, v.MixSignatures[i]) {
			err := errors.New("failed to verify mixnet settings: round %d, key %s", round, base32.EncodeToString(mixKey))
			c.Handler.Error(err)
			return
		}
	}

	atomic.StoreUint32(&c.lastDialingRound, round)

	call := c.nextOutgoingCall(round)
	mixMessage := new(dialing.MixMessage)
	mixMessage.Mailbox = usernameToMailbox(call.Username, v.MixSettings.NumMailboxes)
	copy(mixMessage.Token[:], call.dialToken[:])

	onion, _ := onionbox.Seal(mustMarshal(mixMessage), zeroNonce, v.MixSettings.OnionKeys)

	// respond to the entry server with our onion for this round
	omsg := coordinator.OnionMsg{
		Round: round,
		Onion: onion,
	}
	conn.Send("onion", omsg)

	if call.Username != "" {
		// notify the application
		c.Handler.SentCall(call)
	}
}

func (c *Client) nextOutgoingCall(round uint32) *OutgoingCall {
	c.mu.Lock()
	defer c.mu.Unlock()

	var call *OutgoingCall
	// TODO timing leak
	if len(c.outgoingCalls) > 0 {
		call = c.outgoingCalls[0]
		c.outgoingCalls = c.outgoingCalls[1:]

		call.sentRound = round
		call.dialToken = c.wheel.OutgoingDialToken(call.Username, round, call.Intent)
		call.sessionKey = c.wheel.SessionKey(call.Username, round)
	} else {
		call = &OutgoingCall{
			Username:  "",
			Intent:    0,
			sentRound: round,
			dialToken: new([32]byte),
		}
		rand.Read(call.dialToken[:])
	}

	return call
}

func (c *Client) scanBloomFilter(conn typesocket.Conn, v coordinator.MailboxURL) {
	mailboxID := usernameToMailbox(c.Username, v.NumMailboxes)
	mailbox, err := c.fetchMailbox(v.URL, mailboxID)
	if err != nil {
		c.Handler.Error(errors.Wrap(err, "fetching mailbox"))
		return
	}

	filter := new(bloom.Filter)
	if err := filter.UnmarshalBinary(mailbox); err != nil {
		c.Handler.Error(errors.Wrap(err, "decoding bloom filter"))
	}

	allTokens := c.wheel.IncomingDialTokens(c.Username, v.Round, intentsMax)
	for _, user := range allTokens {
		for intent, token := range user.Tokens {
			if filter.Test(token[:]) {
				call := &IncomingCall{
					Username:   user.FromUsername,
					Intent:     intent,
					SessionKey: c.wheel.SessionKey(user.FromUsername, v.Round),
				}
				c.Handler.ReceivedCall(call)
			}
		}
	}
	c.wheel.EraseKeys(v.Round)
}
