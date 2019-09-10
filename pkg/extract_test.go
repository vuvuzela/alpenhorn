// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pkg

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"

	"vuvuzela.io/crypto/bls"
)

func TestMarshalExtractReply(t *testing.T) {
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	ctxt := make([]byte, 128)
	rand.Read(ctxt)

	_, blsPriv, _ := bls.GenerateKey(rand.Reader)
	sig := bls.Sign(blsPriv, []byte("test message"))

	reply := &extractReply{
		Round:               12345,
		Username:            "alice@example.org",
		EncryptedPrivateKey: ctxt,
		IdentitySig:         sig,
	}
	reply.Sign(serverPriv)
	data, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}

	ureply := new(extractReply)
	if err := json.Unmarshal(data, ureply); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(reply, ureply) {
		t.Fatalf("after unmarshal: got %#v, want %#v", ureply, reply)
	}
}
