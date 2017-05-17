// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package alpenhorn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding"
	"encoding/hex"
	"sync/atomic"

	"github.com/davidlazar/go-crypto/encoding/base32"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"

	"vuvuzela.io/alpenhorn/addfriend"
	"vuvuzela.io/alpenhorn/coordinator"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/alpenhorn/typesocket"
	"vuvuzela.io/concurrency"
	"vuvuzela.io/crypto/bls"
	"vuvuzela.io/crypto/ibe"
	"vuvuzela.io/crypto/onionbox"
)

type addFriendRoundState struct {
	Round            uint32
	ServerMasterKeys []*ibe.MasterPublicKey
	PrivateKeys      []*ibe.IdentityPrivateKey
	ServerBLSKeys    []*bls.PublicKey
	IdentitySigs     []bls.Signature
}

func (c *Client) addFriendMux() typesocket.Mux {
	return typesocket.NewMux(map[string]interface{}{
		"pkg":     c.extractPKGKeys,
		"mix":     c.sendAddFriendOnion,
		"mailbox": c.scanMailbox,
		"error":   c.addFriendRoundError,
	})
}

func (c *Client) addFriendRoundError(conn typesocket.Conn, v coordinator.RoundError) {
	log.Printf("addfriend round error: %#v", v)
}

func (c *Client) extractPKGKeys(conn typesocket.Conn, v coordinator.PKGRound) {
	pkgKeys := make([]ed25519.PublicKey, len(c.pkgClients))
	for i := range pkgKeys {
		pkgKeys[i] = c.pkgClients[i].ServerKey
	}
	if !v.PKGSettings.Verify(v.Round, pkgKeys) {
		err := errors.New("failed to verify PKG settings: round %d", v.Round)
		c.Handler.Error(err)
		return
	}

	st := &addFriendRoundState{
		Round:            v.Round,
		ServerMasterKeys: make([]*ibe.MasterPublicKey, len(c.pkgClients)),
		PrivateKeys:      make([]*ibe.IdentityPrivateKey, len(c.pkgClients)),
		ServerBLSKeys:    make([]*bls.PublicKey, len(c.pkgClients)),
		IdentitySigs:     make([]bls.Signature, len(c.pkgClients)),
	}

	id := pkg.ValidUsernameToIdentity(c.Username)

	for i, pkgc := range c.pkgClients {
		extractResult, err := pkgc.Extract(v.Round)
		if err != nil {
			log.Printf("extract error: %s", err)
			return
		}
		hexkey := hex.EncodeToString(pkgc.ServerKey)
		st.ServerMasterKeys[i] = v.PKGSettings[hexkey].MasterPublicKey
		st.ServerBLSKeys[i] = v.PKGSettings[hexkey].BLSPublicKey
		st.PrivateKeys[i] = extractResult.PrivateKey

		attestation := &pkg.Attestation{
			AttestKey:       st.ServerBLSKeys[i],
			UserIdentity:    id,
			UserLongTermKey: c.LongTermPublicKey,
		}
		if !bls.Verify(st.ServerBLSKeys[i:i+1], [][]byte{attestation.Marshal()}, extractResult.IdentitySig) {
			log.Printf("pkg %s gave us an invalid identity signature", pkgc.ServerAddr)
			return
		}
		st.IdentitySigs[i] = extractResult.IdentitySig
	}

	c.mu.Lock()
	c.addFriendRounds[v.Round] = st
	c.mu.Unlock()
}

var zeroNonce = new([24]byte)

func (c *Client) sendAddFriendOnion(conn typesocket.Conn, v coordinator.MixRound) {
	for i, mixKey := range c.Mixers {
		if !v.MixSettings.Verify(mixKey, v.MixSignatures[i]) {
			err := errors.New(
				"failed to verify mixnet settings: round %d, key %s",
				v.MixSettings.Round, base32.EncodeToString(mixKey),
			)
			c.Handler.Error(err)
			return
		}
	}

	round := v.MixSettings.Round

	c.mu.Lock()
	st, ok := c.addFriendRounds[round]
	c.mu.Unlock()
	if !ok {
		//err := errors.New("sendOnion: round %d not found", round)
		//c.Handler.Error(err)
		return
	}

	outgoingReq := c.nextOutgoingFriendRequest()
	intro, sentReq := c.genIntro(st, outgoingReq)

	var isReal int // 1 if real, 0 if cover
	if sentReq.Username != "" {
		isReal = 1
	} else {
		isReal = 0
	}

	masterKey := new(ibe.MasterPublicKey).Aggregate(st.ServerMasterKeys...)
	// Unsafe because "" is not a valid username, but this reduces timing leak:
	id := pkg.ValidUsernameToIdentity(sentReq.Username)
	encIntro := ibe.Encrypt(rand.Reader, masterKey, id[:], mustMarshal(intro))
	encIntroBytes := mustMarshal(encIntro)

	mixMessage := new(addfriend.MixMessage)
	mixMessage.Mailbox = usernameToMailbox(sentReq.Username, v.MixSettings.NumMailboxes)
	subtle.ConstantTimeCopy(isReal, mixMessage.EncryptedIntro[:], encIntroBytes)

	onion, _ := onionbox.Seal(mustMarshal(mixMessage), zeroNonce, v.MixSettings.OnionKeys)

	omsg := coordinator.OnionMsg{
		Round: round,
		Onion: onion,
	}
	conn.Send("onion", omsg)

	if sentReq.Username != "" {
		c.Handler.SentFriendRequest(outgoingReq)
		inReq := c.matchToIncoming(sentReq)
		if inReq != nil {
			c.newFriend(inReq, sentReq)
		} else {
			c.mu.Lock()
			c.sentFriendRequests = append(c.sentFriendRequests, sentReq)
			c.mu.Unlock()
		}
	}
}

func (c *Client) nextOutgoingFriendRequest() *OutgoingFriendRequest {
	c.mu.Lock()
	defer c.mu.Unlock()

	var req *OutgoingFriendRequest
	if len(c.outgoingFriendRequests) > 0 {
		req = c.outgoingFriendRequests[0]
		c.outgoingFriendRequests = c.outgoingFriendRequests[1:]
	} else {
		req = &OutgoingFriendRequest{
			Username: "",
		}
	}

	return req
}

// genIntro generates an introduction from a friend request.
// The resulting introduction is the "public" part, and the
// sentFriendRequest is the private part.
func (c *Client) genIntro(st *addFriendRoundState, out *OutgoingFriendRequest) (*introduction, *sentFriendRequest) {
	dhPublic, dhPrivate, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic("box.GenerateKey: " + err.Error())
	}

	sent := &sentFriendRequest{
		Username:     out.Username,
		ExpectedKey:  out.ExpectedKey,
		Confirmation: out.Confirmation,
		DialRound:    out.DialRound,

		SentRound:    st.Round,
		DHPublicKey:  dhPublic,
		DHPrivateKey: dhPrivate,

		client: c,
	}
	if !sent.Confirmation {
		sent.DialRound = atomic.LoadUint32(&c.lastDialingRound)
	}

	intro := new(introduction)
	id := pkg.ValidUsernameToIdentity(c.Username)
	copy(intro.Username[:], id[:])

	copy(intro.DHPublicKey[:], dhPublic[:])
	copy(intro.LongTermKey[:], c.LongTermPublicKey[:])

	intro.DialingRound = sent.DialRound

	multisig := bls.Aggregate(st.IdentitySigs...).Compress()
	copy(intro.ServerMultisig[:], multisig[:])

	intro.Sign(c.LongTermPrivateKey)

	return intro, sent
}

func (c *Client) scanMailbox(conn typesocket.Conn, v coordinator.MailboxURL) {
	c.mu.Lock()
	st, ok := c.addFriendRounds[v.Round]
	c.mu.Unlock()
	if !ok {
		//err := errors.New("scanMailbox: round %d not found", v.Round)
		//c.Handler.Error(err)
		return
	}

	mailboxID := usernameToMailbox(c.Username, v.NumMailboxes)
	mailbox, err := c.fetchMailbox(v.URL, mailboxID)
	if err != nil {
		c.Handler.Error(errors.Wrap(err, "fetching mailbox"))
		return
	}

	intros := concurrency.Spans(len(mailbox), addfriend.SizeEncryptedIntro)
	privKey := new(ibe.IdentityPrivateKey).Aggregate(st.PrivateKeys...)

	//log.WithFields(log.Fields{"round": v.Round, "intros": len(intros), "mailbox": mailboxID}).Info("Scanning mailbox")
	concurrency.ParallelFor(len(intros), func(p *concurrency.P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			span := intros[i]
			var ctxt ibe.Ciphertext
			ctxtBytes := mailbox[span.Start : span.Start+span.Count]
			if err := ctxt.UnmarshalBinary(ctxtBytes); err != nil {
				log.Printf("Unmarshal failure: %s", err)
				continue
			}

			msg, ok := ibe.Decrypt(privKey, ctxt)
			if !ok {
				continue
			}

			c.decodeAddFriendMessage(msg, st.ServerBLSKeys)
		}
	})
}

func (c *Client) decodeAddFriendMessage(msg []byte, serverKeys []*bls.PublicKey) {
	intro := new(introduction)
	if err := intro.UnmarshalBinary(msg); err != nil {
		return
	}

	if !intro.Verify(serverKeys) {
		log.Printf("failed to verify intro: %s", intro.Username)
		return
	}

	username := pkg.IdentityToUsername(&intro.Username)
	req := &IncomingFriendRequest{
		Username:    username,
		LongTermKey: intro.LongTermKey[:],
		DHPublicKey: &intro.DHPublicKey,
		DialRound:   intro.DialingRound,
		client:      c,
	}

	sentReq := c.matchToSent(req)
	if sentReq != nil {
		c.newFriend(req, sentReq)
	} else {
		c.mu.Lock()
		c.incomingFriendRequests = append(c.incomingFriendRequests, req)
		c.mu.Unlock()
		c.Handler.ReceivedFriendRequest(req)
	}
}

func (c *Client) matchToIncoming(sentReq *sentFriendRequest) *IncomingFriendRequest {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, inReq := range c.incomingFriendRequests {
		if inReq.Username == sentReq.Username && inReq.DialRound == sentReq.DialRound {
			return inReq
		}
	}
	return nil
}

func (c *Client) matchToSent(inReq *IncomingFriendRequest) *sentFriendRequest {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, sentReq := range c.sentFriendRequests {
		if inReq.Username == sentReq.Username && inReq.DialRound == sentReq.DialRound {
			return sentReq
		}
	}
	return nil
}

func (c *Client) newFriend(in *IncomingFriendRequest, sent *sentFriendRequest) {
	sharedKey := new([32]byte)
	box.Precompute(sharedKey, in.DHPublicKey, sent.DHPrivateKey)
	c.wheel.Put(in.Username, in.DialRound, sharedKey)

	friend := &Friend{
		Username:    in.Username,
		LongTermKey: in.LongTermKey,

		client: c,
	}

	c.mu.Lock()
	c.friends[in.Username] = friend

	// delete the friend requests from the in/sent queues (slice tricks)
	newIn := c.incomingFriendRequests[:0]
	for _, req := range c.incomingFriendRequests {
		if req != in {
			newIn = append(newIn, req)
		}
	}
	c.incomingFriendRequests = newIn

	newSent := c.sentFriendRequests[:0]
	for _, req := range c.sentFriendRequests {
		if req != sent {
			newSent = append(newSent, req)
		}
	}
	c.sentFriendRequests = newSent

	if err := c.persistLocked(); err != nil {
		c.Handler.Error(errors.Wrap(err, "persist error"))
	}
	c.mu.Unlock()

	c.Handler.ConfirmedFriend(friend)
}

func mustMarshal(v encoding.BinaryMarshaler) []byte {
	bs, err := v.MarshalBinary()
	if err != nil {
		panic("marshalling error: " + err.Error())
	}
	return bs
}
