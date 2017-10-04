// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package alpenhorn

import (
	"crypto/rand"
	"sync/atomic"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/bloom"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/coordinator"
	"vuvuzela.io/alpenhorn/dialing"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/alpenhorn/typesocket"
	"vuvuzela.io/crypto/onionbox"
)

type dialingRoundState struct {
	Round        uint32
	Config       *config.DialingConfig
	ConfigParent *config.SignedConfig
}

func (c *Client) dialingMux() typesocket.Mux {
	return typesocket.NewMux(map[string]interface{}{
		"newround": c.newDialingRound,
		"mix":      c.sendDialingOnion,
		"mailbox":  c.scanBloomFilter,
		"error":    c.dialingRoundError,
	})
}

func (c *Client) dialingRoundError(conn typesocket.Conn, v coordinator.RoundError) {
	log.WithFields(log.Fields{"round": v.Round}).Errorf("dialing coordinator sent error: %s", v.Err)
}

func (c *Client) newDialingRound(conn typesocket.Conn, v coordinator.NewRound) {
	c.mu.Lock()
	defer c.mu.Unlock()

	st, ok := c.dialingRounds[v.Round]
	if ok {
		if st.ConfigParent.Hash() != v.ConfigHash {
			c.Handler.Error(errors.New("coordinator announced different configs round %d", v.Round))
		}
		return
	}

	// common case
	if v.ConfigHash == c.dialingConfigHash {
		c.dialingRounds[v.Round] = &dialingRoundState{
			Round:        v.Round,
			Config:       c.dialingConfig.Inner.(*config.DialingConfig),
			ConfigParent: c.dialingConfig,
		}
		return
	}

	configs, err := c.ConfigClient.FetchAndVerifyChain(c.dialingConfig, v.ConfigHash)
	if err != nil {
		c.Handler.Error(errors.Wrap(err, "fetching dialing config"))
		return
	}

	c.Handler.NewConfig(configs)

	newConfig := configs[0]
	c.dialingConfig = newConfig
	c.dialingConfigHash = v.ConfigHash

	if err := c.persistLocked(); err != nil {
		panic("failed to persist state: " + err.Error())
	}

	c.dialingRounds[v.Round] = &dialingRoundState{
		Round:        v.Round,
		Config:       newConfig.Inner.(*config.DialingConfig),
		ConfigParent: newConfig,
	}
}

func (c *Client) sendDialingOnion(conn typesocket.Conn, v coordinator.MixRound) {
	round := v.MixSettings.Round

	c.mu.Lock()
	st, ok := c.dialingRounds[round]
	c.mu.Unlock()
	if !ok {
		c.Handler.Error(errors.New("sendDialingOnion: round %d not configured", round))
		return
	}

	settingsMsg := v.MixSettings.SigningMessage()

	for i, mixer := range st.Config.MixServers {
		if !ed25519.Verify(mixer.Key, settingsMsg, v.MixSignatures[i]) {
			err := errors.New(
				"round %d: failed to verify mixnet settings for key %s",
				round, base32.EncodeToString(mixer.Key),
			)
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
	c.mu.Lock()
	st, ok := c.dialingRounds[v.Round]
	c.mu.Unlock()
	if !ok {
		return
	}

	mailboxID := usernameToMailbox(c.Username, v.NumMailboxes)
	mailbox, err := c.fetchMailbox(st.Config.CDNServer, v.URL, mailboxID)
	if err != nil {
		c.Handler.Error(errors.Wrap(err, "fetching mailbox"))
		return
	}

	filter := new(bloom.Filter)
	if err := filter.UnmarshalBinary(mailbox); err != nil {
		c.Handler.Error(errors.Wrap(err, "decoding bloom filter"))
	}

	allTokens := c.wheel.IncomingDialTokens(c.Username, v.Round, IntentMax)
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
