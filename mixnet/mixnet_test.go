// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package mixnet_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/ed25519"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"vuvuzela.io/alpenhorn/addfriend"
	"vuvuzela.io/alpenhorn/edhttp"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/internal/mock"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/alpenhorn/mixnet"
	"vuvuzela.io/concurrency"
	"vuvuzela.io/crypto/onionbox"
)

func TestMixnet(t *testing.T) {
	coordinatorPublic, coordinatorPrivate, _ := ed25519.GenerateKey(rand.Reader)

	testCDN := mock.LaunchCDN("", coordinatorPublic)

	mixchain := mock.LaunchMixchain(3, coordinatorPublic)

	coordinatorLoop(coordinatorPrivate, mixchain, testCDN)
}

func newBucket(coordinatorKey ed25519.PrivateKey, cdn *mock.CDN, lastServerKey ed25519.PublicKey, round uint32) {
	url := fmt.Sprintf("https://%s/newbucket?bucket=%s/%d&uploader=%s",
		cdn.Addr,
		"AddFriend",
		round,
		base32.EncodeToString(lastServerKey),
	)
	resp, err := (&edhttp.Client{
		Key: coordinatorKey,
	}).Post(cdn.PublicKey, url, "", nil)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := ioutil.ReadAll(resp.Body)
		log.Fatalf("creating cdn bucket failed: %s: %q", resp.Status, msg)
	}
}

func coordinatorLoop(coordinatorKey ed25519.PrivateKey, mixchain *mock.Mixchain, cdn *mock.CDN) {
	coordinatorClient := &mixnet.Client{
		Key: coordinatorKey,
	}

	for round := uint32(1); round < 10; round++ {
		newBucket(coordinatorKey, cdn, mixchain.Servers[len(mixchain.Servers)-1].Key, round)

		settings := &mixnet.RoundSettings{
			Service:      "AddFriend",
			Round:        round,
			NumMailboxes: 1,
		}
		sigs, err := coordinatorClient.NewRound(context.Background(), mixchain.Servers, cdn.Addr, cdn.PublicKey, settings)
		if err != nil {
			log.Fatalf("mixnet.NewRound: %s", err)
		}
		settingsMsg := settings.SigningMessage()
		for i, sig := range sigs {
			if !ed25519.Verify(mixchain.Servers[i].Key, settingsMsg, sig) {
				log.Fatalf("failed to verify round settings from mixer %d", i+1)
			}
		}

		msg, onion := makeAddFriendOnion(settings)
		url, err := coordinatorClient.RunRound(context.Background(), mixchain.Servers[0], "AddFriend", round, [][]byte{onion})
		if err != nil {
			log.Fatalf("mixnet.RunRound: %s", err)
		}

		msgs := fetchMailbox(cdn.PublicKey, url, 1, addfriend.SizeEncryptedIntro)
		msgIndex := -1
		for i, in := range msgs {
			if bytes.Equal(in, msg) {
				msgIndex = i
				break
			}

		}
		if msgIndex == -1 {
			log.Fatalf("did not find our message at %s", url)
		}
		log.Warnf("Found our message at position: %d", msgIndex)
	}
}

func fetchMailbox(cdnKey ed25519.PublicKey, baseURL string, mailbox uint32, msgSize int) (msgs [][]byte) {
	u, err := url.Parse(baseURL)
	if err != nil {
		log.Fatalf("parsing base url: %s", err)
	}
	vals := u.Query()
	vals.Set("key", fmt.Sprintf("%d", mailbox))
	u.RawQuery = vals.Encode()

	resp, err := (&edhttp.Client{}).Get(cdnKey, u.String())
	if err != nil {
		log.Fatalf("http.Get: %s", err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to fetch mailbox: %s", err)
	}

	spans := concurrency.Spans(len(data), msgSize)
	msgs = make([][]byte, len(spans))
	for i, span := range spans {
		msgs[i] = data[span.Start : span.Start+span.Count]
	}
	return
}

var zeroNonce = new([24]byte)

func makeAddFriendOnion(settings *mixnet.RoundSettings) (msg []byte, onion []byte) {
	msg = make([]byte, addfriend.SizeEncryptedIntro)
	rand.Read(msg)
	mixMessage := addfriend.MixMessage{
		Mailbox: 1,
	}
	copy(mixMessage.EncryptedIntro[:], msg)

	data, _ := mixMessage.MarshalBinary()
	onion, _ = onionbox.Seal(data, zeroNonce, settings.OnionKeys)
	return
}

func TestAuth(t *testing.T) {
	coordinatorPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	_, badPrivate, _ := ed25519.GenerateKey(rand.Reader)

	mixchain := mock.LaunchMixchain(3, coordinatorPublic)

	badClient := &mixnet.Client{
		Key: badPrivate,
	}

	_, err := badClient.NewRound(context.Background(), mixchain.Servers, "no-cdn", nil, &mixnet.RoundSettings{
		Service:      "AddFriend",
		Round:        42,
		NumMailboxes: 1,
	})
	err = errors.Cause(err)
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("unexpected error: %s", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("unexpected status: %s", st)
	}
}
