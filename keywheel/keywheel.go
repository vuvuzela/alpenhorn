// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package keywheel implements Alpenhorn's keywheel construction.
package keywheel

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
)

// Use github.com/davidlazar/easyjson:
//go:generate easyjson .

const version byte = 1

type Wheel struct {
	mu      sync.Mutex
	secrets map[string]*roundSecret
}

//easyjson:readable
type roundSecret struct {
	Round  uint32
	Secret *[32]byte
}

func (rs roundSecret) getSecret(round uint32) *[32]byte {
	if rs.Round == round {
		return rs.Secret
	}
	if rs.Round > round {
		return nil
	}

	secret := rs.Secret
	for r := rs.Round; r < round; r++ {
		secret = hash1(secret, r)
	}

	return secret
}

func (w *Wheel) Put(username string, round uint32, secret *[32]byte) {
	w.mu.Lock()
	if w.secrets == nil {
		w.secrets = make(map[string]*roundSecret)
	}
	w.secrets[username] = &roundSecret{
		Round:  round,
		Secret: secret,
	}
	w.mu.Unlock()
}

func (w *Wheel) get(username string) *roundSecret {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.secrets == nil {
		return nil
	}
	return w.secrets[username]
}

// Exists returns true if username is in the keywheel
// and false otherwise.
func (w *Wheel) Exists(username string) bool {
	return w.get(username) != nil
}

// UnsafeGet returns the internal keywheel state for a username.
// This is unsafe; use SessionKey, if possible.
func (w *Wheel) UnsafeGet(username string) (round uint32, secret *[32]byte) {
	rs := w.get(username)
	if rs != nil {
		round = rs.Round
		secret = rs.Secret
	}
	return
}

func (w *Wheel) Remove(username string) {
	w.mu.Lock()
	delete(w.secrets, username)
	w.mu.Unlock()
}

func (w *Wheel) SessionKey(username string, round uint32) *[32]byte {
	rs := w.get(username)
	if rs == nil || rs.Round > round {
		return nil
	}

	// TODO should we hash the intent also?
	key := hash3(rs.getSecret(round), round)
	return key
}

func (w *Wheel) OutgoingDialToken(username string, round uint32, intent int) *[32]byte {
	rs := w.get(username)
	if rs == nil || rs.Round > round {
		return nil
	}

	key := rs.getSecret(round)
	token := hash2(key, round, username, intent)
	return token
}

type UserDialTokens struct {
	FromUsername string
	Tokens       []*[32]byte
}

func (w *Wheel) IncomingDialTokens(myUsername string, round uint32, numIntents int) []*UserDialTokens {
	w.mu.Lock()
	defer w.mu.Unlock()

	all := make([]*UserDialTokens, 0, len(w.secrets))
	for friend, rs := range w.secrets {
		if rs.Round > round {
			continue
		}
		u := &UserDialTokens{
			FromUsername: friend,
			Tokens:       make([]*[32]byte, numIntents),
		}
		key := rs.getSecret(round)
		for i := range u.Tokens {
			u.Tokens[i] = hash2(key, round, myUsername, i)
		}
		all = append(all, u)
	}
	return all
}

func (w *Wheel) EraseKeys(round uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()

	newRound := round + 1
	for _, rs := range w.secrets {
		newSecret := rs.getSecret(newRound)
		if newSecret != nil {
			rs.Round = newRound
			rs.Secret = newSecret
		}
	}
}

func (w *Wheel) MarshalBinary() ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	buf := new(bytes.Buffer)
	if _, err := buf.Write([]byte{version}); err != nil {
		return nil, err
	}

	encoder := json.NewEncoder(buf)
	// use indented json for now for easier debugging
	encoder.SetIndent("", "  ")
	err := encoder.Encode(w.secrets)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (w *Wheel) UnmarshalBinary(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	ver := data[0]
	if ver != version {
		return fmt.Errorf("unknown serialization version: %d", ver)
	}

	secrets := make(map[string]*roundSecret)
	err := json.Unmarshal(data[1:], &secrets)
	if err != nil {
		return err
	}
	w.secrets = secrets

	return nil
}

var (
	hash1UniqueBytes = []byte{1, 1, 1, 1}
	hash2UniqueBytes = []byte{2, 2, 2, 2}
	hash3UniqueBytes = []byte{3, 3, 3, 3}
)

func hash1(key *[32]byte, round uint32) *[32]byte {
	var rb [4]byte
	binary.BigEndian.PutUint32(rb[:], round)

	h := hmac.New(sha256.New, key[:])
	h.Write(hash1UniqueBytes)
	h.Write(rb[:])

	r := new([32]byte)
	copy(r[:], h.Sum(nil))
	return r
}

func hash2(key *[32]byte, round uint32, username string, intent int) *[32]byte {
	var eb [8]byte
	binary.BigEndian.PutUint32(eb[0:4], round)
	binary.BigEndian.PutUint32(eb[4:8], uint32(intent))

	h := hmac.New(sha256.New, key[:])
	h.Write(hash2UniqueBytes)
	h.Write(eb[:])
	h.Write([]byte(username))

	r := new([32]byte)
	copy(r[:], h.Sum(nil))
	return r
}

func hash3(key *[32]byte, round uint32) *[32]byte {
	var rb [4]byte
	binary.BigEndian.PutUint32(rb[:], round)

	h := hmac.New(sha256.New, key[:])
	h.Write(hash3UniqueBytes)
	h.Write(rb[:])

	r := new([32]byte)
	copy(r[:], h.Sum(nil))
	return r
}
