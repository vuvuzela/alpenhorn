// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package config

import (
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/internal/debug"
	"vuvuzela.io/alpenhorn/mixnet"
	"vuvuzela.io/alpenhorn/pkg"
)

func TestMarshalConfig(t *testing.T) {
	guardianPub, guardianPriv, _ := ed25519.GenerateKey(rand.Reader)

	conf := &SignedConfig{
		// need to round otherwise the time includes a monotonic clock value
		Created: time.Now().Round(0),
		Expires: time.Now().Round(0),

		Guardians: []Guardian{
			{
				Username: "david",
				Key:      guardianPub,
			},
		},

		Service: "AddFriend",
		Inner: &AddFriendConfig{
			Coordinator: CoordinatorConfig{
				Key:     guardianPub,
				Address: "localhost:8080",
			},
			MixServers: []mixnet.PublicServerConfig{
				{
					Key:     guardianPub,
					Address: "localhost:1234",
				},
			},
			PKGServers: []pkg.PublicServerConfig{
				{
					Key:     guardianPub,
					Address: "localhost:5678",
				},
			},
			CDNServer: CDNServerConfig{
				Key:     guardianPub,
				Address: "localhost:8888",
			},
		},
	}
	sig := ed25519.Sign(guardianPriv, conf.SigningMessage())
	conf.Signatures = map[string][]byte{
		base32.EncodeToString(guardianPub): sig,
	}

	data, err := json.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}
	/*
		buf := new(bytes.Buffer)
		err = json.Indent(buf, data, "  ", "  ")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("Marshaled config:\n%s\n", buf.Bytes())
	*/

	conf2 := new(SignedConfig)
	err = json.Unmarshal(data, conf2)
	if err != nil {
		t.Fatal(err)
	}

	if conf.Hash() != conf2.Hash() {
		t.Fatalf("round-trip failed:\nbefore=%s\nafter=%s\n", debug.Pretty(conf), debug.Pretty(conf2))
	}
	if !reflect.DeepEqual(conf, conf2) {
		t.Fatalf("round-trip failed:\nbefore=%s\nafter=%s\n", debug.Pretty(conf), debug.Pretty(conf2))
	}
}

const exampleConfig = `
{
  "Service": "AddFriend",
  "Created": "2017-09-29T06:47:05.396965796-04:00",
  "Expires": "2017-09-29T06:47:05.396966008-04:00",
  "PrevConfigHash": "",
  "Inner": {
    "Coordinator": {
      "Key": "5t8c7emvexkwg02yhqwksj7shc93sh3cat3yxk57ghqdr4hp7zq0",
      "Address": "localhost:8080"
    },
    "PKGServers": [
      {
        "Key": "5t8c7emvexkwg02yhqwksj7shc93sh3cat3yxk57ghqdr4hp7zq0",
        "Address": "localhost:5678"
      }
    ],
    "MixServers": [
      {
        "Key": "5t8c7emvexkwg02yhqwksj7shc93sh3cat3yxk57ghqdr4hp7zq0",
        "Address": "localhost:1234"
      }
    ],
    "CDNServer": {
      "Key": "5t8c7emvexkwg02yhqwksj7shc93sh3cat3yxk57ghqdr4hp7zq0",
      "Address": "localhost:8888"
    }
  },
  "Guardians": [
    {
      "Username": "david",
      "Key": "5t8c7emvexkwg02yhqwksj7shc93sh3cat3yxk57ghqdr4hp7zq0"
    }
  ],
  "Signatures": {
    "5t8c7emvexkwg02yhqwksj7shc93sh3cat3yxk57ghqdr4hp7zq0": "6k9nkf4exwd1r1yhc00b0r8ky4y9006svj2n06w4bd3t226rxfrdn6mbt07rp5r6sw8mfy67y00z06k2tnd4sga4325pk3p5gzx862r"
  }
}
`

func TestUnmarshalConfig(t *testing.T) {
	conf := new(SignedConfig)
	err := json.Unmarshal([]byte(exampleConfig), conf)
	if err != nil {
		t.Fatal(err)
	}
	if conf.Hash() != "m1yvja2gyn95syw3g8f38k59e5c2d6cjgfn2em69nxrefbtyxx2g" {
		t.Fatalf("unexpected config: hash=%s\n%s", conf.Hash(), debug.Pretty(conf))
	}
}
