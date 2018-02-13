// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package keywheel

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestMarshal(t *testing.T) {
	var w1 Wheel
	w1.Put("alice", 100, new([32]byte))
	k1 := w1.SessionKey("alice", 100)
	w1Bytes, _ := w1.MarshalBinary()

	var w2 Wheel
	err := w2.UnmarshalBinary(w1Bytes)
	if err != nil {
		t.Fatal(err)
	}
	k2 := w2.SessionKey("alice", 100)

	if !bytes.Equal(k1[:], k2[:]) {
		t.Fatal("session keys differ after re-opening")
	}

	w2.EraseKeys(100)
	w2.EraseKeys(101)

	data, _ := w2.MarshalBinary()
	expected := `{
  "alice": {
    "Round": 102,
    "Secret": "bzc1exn1snjc7c43szqhmpd8h7c1hgep42ydwpy48ec6zt02ctx0"
  }
}
`
	// ignore version byte
	if !bytes.Equal(data[1:], []byte(expected)) {
		t.Fatalf("persisted state, got:\n%q\nwant:\n%q\n", data[1:], expected)
	}
}

func TestKeywheel(t *testing.T) {
	// Alice's keywheel
	alice := "alice@example.org"
	var aw Wheel

	// Bob's keywheel
	bob := "bob@example.org"
	var bw Wheel

	// shared key between Blice and Bob
	abKey := new([32]byte)
	rand.Read(abKey[:])

	aw.Put(bob, 100, abKey)
	bw.Put(alice, 100, abKey)

	keyA := aw.SessionKey(bob, 100)
	keyB := bw.SessionKey(alice, 100)
	if keyA == nil {
		t.Fatal("got nil session key")
	}
	if !bytes.Equal(keyA[:], keyB[:]) {
		t.Fatalf("%x != %x", keyA[:], keyB[:])
	}

	if key := aw.SessionKey(bob, 90); key != nil {
		t.Fatalf("expected nil session key for round 90")
	}

	aw.EraseKeys(99)
	if key := aw.SessionKey(bob, 100); !bytes.Equal(keyA[:], key[:]) {
		t.Fatalf("%x != %x", keyA[:], key[:])
	}
	aw.EraseKeys(100)
	if key := aw.SessionKey(bob, 100); key != nil {
		t.Fatalf("expected nil session key for round 100")
	}
	if xs := aw.IncomingDialTokens(bob, 100, 5); len(xs) != 0 {
		t.Fatalf("expected empty token list for round 100")
	}

	keyA = aw.SessionKey(bob, 120)
	keyB = bw.SessionKey(alice, 120)
	if keyA == nil {
		t.Fatal("got nil session key")
	}
	if !bytes.Equal(keyA[:], keyB[:]) {
		t.Fatalf("%x != %x", keyA[:], keyB[:])
	}

	chris := "chris@example.org"
	var cw Wheel

	acKey := new([32]byte)
	rand.Read(acKey[:])
	aw.Put(chris, 101, acKey)
	cw.Put(alice, 101, acKey)

	numIntents := 5
	alltokens := aw.IncomingDialTokens(alice, 101, numIntents)
	if len(alltokens) != 2 {
		t.Fatalf("expected single element in token list, got %d", len(alltokens))
	}
	for _, u := range alltokens {
		var w *Wheel
		if u.FromUsername == bob {
			w = &bw
		} else if u.FromUsername == chris {
			w = &cw
		} else {
			t.Fatalf("unexpected user in incoming dial tokens: %s", u.FromUsername)
		}
		for i := 0; i < numIntents; i++ {
			tok := w.OutgoingDialToken(alice, 101, i)
			if !bytes.Equal(tok[:], u.Tokens[i][:]) {
				t.Fatalf("dial token mismatch; user=%s intent=%d: expected %v, got %v", u.FromUsername, i, u.Tokens[i][:], tok[:])
			}
		}
	}
}

func BenchmarkGetSecret(b *testing.B) {
	rs := &roundSecret{
		Round:  0,
		Secret: new([32]byte),
	}
	for i := 0; i < b.N; i++ {
		_ = rs.getSecret(1)
	}
}
