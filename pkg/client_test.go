// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pkg

import (
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/internal/debug"
)

func TestMarshalClient(t *testing.T) {
	pkgPub, _, _ := ed25519.GenerateKey(rand.Reader)
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)

	client := &Client{
		PublicServerConfig: PublicServerConfig{
			Key:     pkgPub,
			Address: "localhost:8085",
		},

		Username:        "david",
		LoginKey:        userPriv,
		UserLongTermKey: userPub,
	}

	data, err := json.Marshal(client)
	if err != nil {
		t.Fatal(err)
	}

	client2 := new(Client)
	err = json.Unmarshal(data, client2)
	if err != nil {
		t.Fatal(err)
	}

	// UserLongTermKey is not marshaled.
	client2.UserLongTermKey = userPub

	if !reflect.DeepEqual(client, client2) {
		t.Fatalf("json round trip failed:\nwant: %s\n got: %s\n", debug.Pretty(client), debug.Pretty(client2))
	}
}
