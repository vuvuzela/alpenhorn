// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package alpenhorn

import (
	"time"

	"golang.org/x/crypto/ed25519"
)

// Friend is an entry in the client's address book.
type Friend struct {
	Username    string
	LongTermKey ed25519.PublicKey

	// extraData stores application-specific data.
	extraData []byte
	client    *Client
}

// GetFriends returns all the friends in the client's address book.
func (c *Client) GetFriends() []*Friend {
	c.mu.Lock()
	fs := make([]*Friend, 0, len(c.friends))
	for _, friend := range c.friends {
		fs = append(fs, friend)
	}
	c.mu.Unlock()
	return fs
}

// GetFriend returns the friend object for the given username,
// or nil if username is not in the client's address book.
func (c *Client) GetFriend(username string) *Friend {
	c.mu.Lock()
	friend := c.friends[username]
	c.mu.Unlock()
	return friend
}

// Remove removes the friend from the client's address book.
func (f *Friend) Remove() error {
	f.client.mu.Lock()
	defer f.client.mu.Unlock()

	delete(f.client.friends, f.Username)
	f.client.wheel.Remove(f.Username)

	// delete any outgoing calls for this friend
	calls := f.client.outgoingCalls[:0]
	for _, call := range f.client.outgoingCalls {
		if call.Username != f.Username {
			calls = append(calls, call)
		}
	}
	f.client.outgoingCalls = calls

	err := f.client.persistLocked()
	return err
}

// SetExtraData overwrites the friend's extra data field with the given
// data. The extra data field is useful for application-specific data
// about the friend, such as additional contact info, notes, or a photo.
//
// Applications should use the extra data field to store information
// about friends instead of maintaining a separate friend list because
// the Alpenhorn client will (eventually) ensure that the size of the
// persisted data on disk does not leak metadata.
func (f *Friend) SetExtraData(data []byte) error {
	f.client.mu.Lock()
	f.extraData = make([]byte, len(data))
	copy(f.extraData, data)
	err := f.client.persistLocked()
	f.client.mu.Unlock()
	return err
}

// ExtraData returns a copy of the extra data field for the friend.
func (f *Friend) ExtraData() []byte {
	f.client.mu.Lock()
	data := make([]byte, len(f.extraData))
	copy(data, f.extraData)
	f.client.mu.Unlock()
	return data
}

// UnsafeKeywheelState exposes the internal keywheel state for this friend.
// This should only be used for debugging.
func (f *Friend) UnsafeKeywheelState() (uint32, *[32]byte) {
	return f.client.wheel.UnsafeGet(f.Username)
}

// Intents are the dialing intents passed to Call.
const (
	IntentTalk = iota
	IntentPing
	IntentCallMeBack
	intentsMax
)

// Call is used to call a friend using Alpenhorn's dialing protocol.
// Call does not send the call right away but queues the call for an
// upcoming dialing round. The resulting OutgoingCall is the queued
// call object. Call does nothing and returns nil if the friend is
// not in the client's address book.
func (f *Friend) Call(intent int) *OutgoingCall {
	if !f.client.wheel.Exists(f.Username) {
		return nil
	}

	call := &OutgoingCall{
		Username: f.Username,
		Intent:   intent,
		Created:  time.Now(),
		client:   f.client,
	}
	f.client.mu.Lock()
	f.client.outgoingCalls = append(f.client.outgoingCalls, call)
	f.client.mu.Unlock()
	return call
}

type IncomingCall struct {
	Username   string
	Intent     int
	SessionKey *[32]byte
}

type OutgoingCall struct {
	Username string
	Intent   int
	Created  time.Time

	client     *Client
	sentRound  uint32
	dialToken  *[32]byte
	sessionKey *[32]byte
}

// Sent returns true if the call has been sent and false otherwise.
func (r *OutgoingCall) Sent() bool {
	r.client.mu.Lock()
	sent := r.sentRound != 0
	r.client.mu.Unlock()
	return sent
}

// SessionKey returns the session key established for this call,
// or nil if the call has not been sent yet.
func (r *OutgoingCall) SessionKey() (key *[32]byte) {
	r.client.mu.Lock()
	key = r.sessionKey
	r.client.mu.Unlock()
	return
}

// Cancel removes the call from the outgoing queue, returning
// ErrTooLate if the call is not found in the queue.
func (r *OutgoingCall) Cancel() error {
	r.client.mu.Lock()
	defer r.client.mu.Unlock()

	calls := r.client.outgoingCalls
	index := -1
	for i, c := range calls {
		if r == c {
			index = i
		}
	}

	if index == -1 {
		return ErrTooLate
	}

	r.client.outgoingCalls = append(calls[:index], calls[index+1:]...)
	return nil
}
