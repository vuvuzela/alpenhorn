// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pkg

import (
	"crypto/rand"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"
)

func TestMarshalUserState(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)

	verifiedUser := userState{
		LoginKey: publicKey,
	}
	data := verifiedUser.Marshal()

	var verifiedUser2 userState
	if err := verifiedUser2.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(verifiedUser, verifiedUser2) {
		t.Fatalf("got %#v, want %#v", verifiedUser2, verifiedUser)
	}
}

func TestMarshalLastExtraction(t *testing.T) {
	e := lastExtraction{
		Round:    12345,
		UnixTime: time.Now().Unix(),
	}
	data := e.Marshal()
	var e2 lastExtraction
	if err := e2.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e, e2) {
		t.Fatalf("after unmarshal: got %#v, want %#v", e2, e)
	}
}
