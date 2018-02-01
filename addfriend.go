// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package alpenhorn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding"
	"encoding/hex"
	"sync"
	"sync/atomic"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"

	"vuvuzela.io/alpenhorn/addfriend"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/coordinator"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/alpenhorn/typesocket"
	"vuvuzela.io/concurrency"
	"vuvuzela.io/crypto/bls"
	"vuvuzela.io/crypto/ibe"
	"vuvuzela.io/crypto/onionbox"
)

type addFriendRoundState struct {
	Round uint32

	// We keep a pointer to the inner config to avoid extra type assertions.
	Config       *config.AddFriendConfig
	ConfigParent *config.SignedConfig

	mu               sync.Mutex
	ServerMasterKeys []*ibe.MasterPublicKey
	PrivateKeys      []*ibe.IdentityPrivateKey
	ServerBLSKeys    []*bls.PublicKey
	IdentitySigs     []bls.Signature
	ExtractSuccess   bool
}

func (c *Client) addFriendMux() typesocket.Mux {
	return typesocket.NewMux(map[string]interface{}{
		"newround": c.newAddFriendRound,
		"pkg":      c.extractPKGKeys,
		"mix":      c.sendAddFriendOnion,
		"mailbox":  c.scanMailbox,
		"error":    c.addFriendRoundError,
	})
}

func (c *Client) addFriendRoundError(conn typesocket.Conn, v coordinator.RoundError) {
	log.WithFields(log.Fields{"round": v.Round}).Errorf("error from addfriend coordinator: %s", v.Err)
}

func (c *Client) newAddFriendRound(conn typesocket.Conn, v coordinator.NewRound) {
	c.mu.Lock()
	defer c.mu.Unlock()

	st, ok := c.addFriendRounds[v.Round]
	if ok {
		if st.ConfigParent.Hash() != v.ConfigHash {
			c.Handler.Error(errors.New("coordinator announced different configs round %d", v.Round))
		}
		return
	}

	// common case
	if v.ConfigHash == c.addFriendConfigHash {
		c.addFriendRounds[v.Round] = &addFriendRoundState{
			Round:        v.Round,
			Config:       c.addFriendConfig.Inner.(*config.AddFriendConfig),
			ConfigParent: c.addFriendConfig,
		}
		return
	}

	configs, err := c.ConfigClient.FetchAndVerifyChain(c.addFriendConfig, v.ConfigHash)
	if err != nil {
		c.Handler.Error(errors.Wrap(err, "fetching addfriend config"))
		return
	}

	// notify the application
	c.Handler.NewConfig(configs)

	newConfig := configs[0]
	addFriendConfig := c.loadAddFriendConfig(newConfig)

	c.addFriendRounds[v.Round] = &addFriendRoundState{
		Round:        v.Round,
		Config:       addFriendConfig,
		ConfigParent: newConfig,
	}

}

// assumes c.mu is locked
func (c *Client) loadAddFriendConfig(newConfig *config.SignedConfig) *config.AddFriendConfig {
	c.addFriendConfig = newConfig
	c.addFriendConfigHash = newConfig.Hash()

	// TODO do the right thing if the coordinator changes.

	innerConfig := newConfig.Inner.(*config.AddFriendConfig)

	pkgClient := &pkg.Client{
		Username:        c.Username,
		LoginKey:        c.PKGLoginKey,
		UserLongTermKey: c.LongTermPublicKey,
		HTTPClient:      c.edhttpClient,
	}

	for _, pkgServer := range innerConfig.PKGServers {
		err := pkgClient.CheckStatus(pkgServer)
		if err == nil {
			continue
		}

		pkgErr, ok := err.(pkg.Error)
		if ok && pkgErr.Code == pkg.ErrNotRegistered {
			log.Infof("Username %q not registered with PKG %s", c.Username, pkgServer.Address)
		} else {
			c.Handler.Error(errors.Wrap(err, "failed to check account status with PKG %s", pkgServer.Address))
		}
	}

	if err := c.persistLocked(); err != nil {
		panic("failed to persist state: " + err.Error())
	}

	return innerConfig
}

func (c *Client) extractPKGKeys(conn typesocket.Conn, v coordinator.PKGRound) {
	c.mu.Lock()
	st, ok := c.addFriendRounds[v.Round]
	c.mu.Unlock()
	if !ok {
		c.Handler.Error(errors.New("extractPKGKeys: round %d not configured", v.Round))
		return
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	if st.PrivateKeys != nil {
		return
	}

	numPKGs := len(st.Config.PKGServers)
	pkgKeys := make([]ed25519.PublicKey, numPKGs)
	for i := range pkgKeys {
		pkgKeys[i] = st.Config.PKGServers[i].Key
	}
	if !v.PKGSettings.Verify(v.Round, pkgKeys) {
		err := errors.New("round %d: failed to verify PKG settings", v.Round)
		c.Handler.Error(err)
		return
	}

	st.ServerMasterKeys = make([]*ibe.MasterPublicKey, numPKGs)
	st.PrivateKeys = make([]*ibe.IdentityPrivateKey, numPKGs)
	st.ServerBLSKeys = make([]*bls.PublicKey, numPKGs)
	st.IdentitySigs = make([]bls.Signature, numPKGs)

	id := pkg.ValidUsernameToIdentity(c.Username)

	pkgClient := &pkg.Client{
		Username:        c.Username,
		LoginKey:        c.PKGLoginKey,
		UserLongTermKey: c.LongTermPublicKey,
		HTTPClient:      c.edhttpClient,
	}

	for i, pkgServer := range st.Config.PKGServers {
		extractResult, err := pkgClient.Extract(pkgServer, v.Round)
		if err != nil {
			c.Handler.Error(errors.Wrap(err, "round %d: error extracting private key from %s", v.Round, pkgServer.Address))
			return
		}
		hexkey := hex.EncodeToString(pkgServer.Key)
		st.ServerMasterKeys[i] = v.PKGSettings[hexkey].MasterPublicKey
		st.ServerBLSKeys[i] = v.PKGSettings[hexkey].BLSPublicKey
		st.PrivateKeys[i] = extractResult.PrivateKey

		attestation := &pkg.Attestation{
			AttestKey:       st.ServerBLSKeys[i],
			UserIdentity:    id,
			UserLongTermKey: c.LongTermPublicKey,
		}
		if !bls.Verify(st.ServerBLSKeys[i:i+1], [][]byte{attestation.Marshal()}, extractResult.IdentitySig) {
			log.Errorf("pkg %s gave us an invalid identity signature", pkgServer.Address)
			return
		}
		st.IdentitySigs[i] = extractResult.IdentitySig
	}

	st.ExtractSuccess = true
}

var zeroNonce = new([24]byte)

func (c *Client) sendAddFriendOnion(conn typesocket.Conn, v coordinator.MixRound) {
	round := v.MixSettings.Round

	c.mu.Lock()
	st, ok := c.addFriendRounds[round]
	c.mu.Unlock()
	if !ok {
		c.Handler.Error(errors.New("sendAddFriendOnion: round %d not configured", round))
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

	st.mu.Lock()
	defer st.mu.Unlock()

	if !st.ExtractSuccess {
		c.Handler.Error(errors.New("sendAddFriendOnion: incomplete extraction for round %d", round))
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

	// Always persist client to avoid side-channels.
	if err := c.persistClient(); err != nil {
		panic(err)
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
	mailbox, err := c.fetchMailbox(st.Config.CDNServer, v.URL, mailboxID)
	if err != nil {
		c.Handler.Error(errors.Wrap(err, "fetching mailbox"))
		return
	}

	st.mu.Lock()
	if !st.ExtractSuccess {
		st.mu.Unlock()
		c.Handler.Error(errors.New("scanMailbox: incomplete extraction for round %d", v.Round))
		return
	}
	privKey := new(ibe.IdentityPrivateKey).Aggregate(st.PrivateKeys...)
	st.mu.Unlock()

	intros := concurrency.Spans(len(mailbox), addfriend.SizeEncryptedIntro)
	//log.WithFields(log.Fields{"round": v.Round, "intros": len(intros), "mailbox": mailboxID}).Info("Scanning mailbox")
	concurrency.ParallelFor(len(intros), func(p *concurrency.P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			span := intros[i]
			var ctxt ibe.Ciphertext
			ctxtBytes := mailbox[span.Start : span.Start+span.Count]
			if err := ctxt.UnmarshalBinary(ctxtBytes); err != nil {
				log.Warnf("Unmarshal failure: %s", err)
				continue
			}

			msg, ok := ibe.Decrypt(privKey, ctxt)
			if !ok {
				continue
			}

			c.decodeAddFriendMessage(msg, st.Config.PKGServers, st.ServerBLSKeys)
		}
	})

	// Always persist client to avoid side-channels.
	if err := c.persistClient(); err != nil {
		panic(err)
	}
}

func (c *Client) decodeAddFriendMessage(msg []byte, verifiers []pkg.PublicServerConfig, multisigKeys []*bls.PublicKey) {
	intro := new(introduction)
	if err := intro.UnmarshalBinary(msg); err != nil {
		return
	}

	if !intro.Verify(multisigKeys) {
		log.Warnf("failed to verify intro: %s", intro.Username)
		return
	}

	username := pkg.IdentityToUsername(&intro.Username)
	req := &IncomingFriendRequest{
		Username:    username,
		LongTermKey: intro.LongTermKey[:],
		DHPublicKey: &intro.DHPublicKey,
		DialRound:   intro.DialingRound,
		Verifiers:   verifiers,
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
