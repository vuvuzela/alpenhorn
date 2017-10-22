// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package alpenhorn

import (
	"errors"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/pkg"
)

// SendFriendRequest sends a friend request to the given username using
// Alpenhorn's add-friend protocol. The key is optional and specifies the
// username's long-term public key if it is known ahead of time.
//
// The friend request is not sent right away but queued for an upcoming
// add-friend round. The resulting OutgoingFriendRequest is the queued
// friend request.
func (c *Client) SendFriendRequest(username string, key ed25519.PublicKey) (*OutgoingFriendRequest, error) {
	req := &OutgoingFriendRequest{
		Username:    username,
		ExpectedKey: key,
		client:      c,
	}
	c.mu.Lock()
	c.outgoingFriendRequests = append(c.outgoingFriendRequests, req)
	err := c.persistLocked()
	c.mu.Unlock()
	return req, err
}

//easyjson:readable
type OutgoingFriendRequest struct {
	Username    string
	ExpectedKey ed25519.PublicKey

	// Confirmation indicates whether this request is in response to an
	// incoming friend request.
	Confirmation bool

	// DialRound is the round that the resulting shared key between friends
	// corresponds to. This field is only used when Confirmation is true.
	// Otherwise, the client uses the latest dialing round when the friend
	// request is sent.
	DialRound uint32

	client *Client
}

// sentFriendRequest is the result of sending an OutgoingFriendRequest.
//easyjson:readable
type sentFriendRequest struct {
	Username     string
	ExpectedKey  ed25519.PublicKey
	Confirmation bool
	DialRound    uint32

	SentRound    uint32
	DHPublicKey  *[32]byte
	DHPrivateKey *[32]byte

	client *Client
}

var ErrTooLate = errors.New("too late")

// Cancel cancels the friend request by removing it from the queue.
// It returns ErrTooLate if the request is not found in the queue.
func (r *OutgoingFriendRequest) Cancel() error {
	r.client.mu.Lock()
	defer r.client.mu.Unlock()

	reqs := r.client.outgoingFriendRequests
	index := -1
	for i, c := range reqs {
		if r == c {
			index = i
		}
	}
	if index == -1 {
		return ErrTooLate
	}

	r.client.outgoingFriendRequests = append(reqs[:index], reqs[index+1:]...)
	err := r.client.persistLocked()
	return err
}

func (c *Client) GetOutgoingFriendRequests() []*OutgoingFriendRequest {
	c.mu.Lock()
	defer c.mu.Unlock()

	r := make([]*OutgoingFriendRequest, len(c.outgoingFriendRequests))
	copy(r, c.outgoingFriendRequests)
	return r
}

func (c *Client) GetSentFriendRequests() []*OutgoingFriendRequest {
	c.mu.Lock()
	defer c.mu.Unlock()

	reqs := make([]*OutgoingFriendRequest, len(c.sentFriendRequests))
	for i, req := range c.sentFriendRequests {
		reqs[i] = &OutgoingFriendRequest{
			Username:     req.Username,
			ExpectedKey:  req.ExpectedKey,
			Confirmation: req.Confirmation,
			DialRound:    req.DialRound,

			client: c,
		}
	}
	return reqs
}

//easyjson:readable
type IncomingFriendRequest struct {
	Username    string
	LongTermKey ed25519.PublicKey
	DHPublicKey *[32]byte
	DialRound   uint32
	Verifiers   []pkg.PublicServerConfig

	client *Client
}

// Approve accepts the friend request and queues a confirmation friend
// request. The add-friend protocol is complete for this friend when the
// confirmation request is sent. Approve assumes that the friend request
// has not been previously rejected.
func (r *IncomingFriendRequest) Approve() (*OutgoingFriendRequest, error) {
	out := &OutgoingFriendRequest{
		Username:     r.Username,
		Confirmation: true,
		DialRound:    r.DialRound,
	}
	c := r.client
	c.mu.Lock()
	c.outgoingFriendRequests = append(c.outgoingFriendRequests, out)
	// The incoming request stays in its queue so it can be matched to the
	// outgoing request when it is sent.
	err := c.persistLocked()
	c.mu.Unlock()
	return out, err
}

// Reject rejects the friend request, returning ErrTooLate if the
// friend request is not found in the client's queue.
func (r *IncomingFriendRequest) Reject() error {
	r.client.mu.Lock()
	defer r.client.mu.Unlock()

	reqs := r.client.incomingFriendRequests
	index := -1
	for i, c := range reqs {
		if r == c {
			index = i
		}
	}
	if index == -1 {
		return ErrTooLate
	}

	r.client.incomingFriendRequests = append(reqs[:index], reqs[index+1:]...)
	err := r.client.persistLocked()
	return err
}

func (c *Client) GetIncomingFriendRequests() []*IncomingFriendRequest {
	c.mu.Lock()
	defer c.mu.Unlock()

	r := make([]*IncomingFriendRequest, len(c.incomingFriendRequests))
	copy(r, c.incomingFriendRequests)
	return r
}
