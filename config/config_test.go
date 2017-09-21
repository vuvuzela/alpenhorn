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
		err = json.Indent(buf, data, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("Marshaled config: %s\n", buf.Bytes())
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
	"Created": "2017-09-18T21:07:55-04:00",
	"Expires": "2017-09-18T21:07:55-04:00",
	"PrevConfigHash": "",
	"Service": "AddFriend",
	"Inner": {
	  "PKGServers": [
		{
		  "Key": "fw5f9rm3bsnnd2x67ha31nhdkja0b2renj1h8y98m3zvwtaw48jg",
		  "Address": "localhost:5678"
		}
	  ],
	  "MixServers": [
		{
		  "Key": "fw5f9rm3bsnnd2x67ha31nhdkja0b2renj1h8y98m3zvwtaw48jg",
		  "Address": "localhost:1234"
		}
	  ],
	  "CDNServer": {
		"Key": "fw5f9rm3bsnnd2x67ha31nhdkja0b2renj1h8y98m3zvwtaw48jg",
		"Address": "localhost:8888"
	  }
	},
	"Guardians": [
	  {
		"Username": "david",
		"Key": "fw5f9rm3bsnnd2x67ha31nhdkja0b2renj1h8y98m3zvwtaw48jg"
	  }
	],
	"Signatures": {
	  "fw5f9rm3bsnnd2x67ha31nhdkja0b2renj1h8y98m3zvwtaw48jg": "srtqxz33d1nm9w361ttrdecv0qs8ch1qw0h7k9416rbhmnkqsvvcf02kpwh0d6zxezwy5qy92n1c15snkqdkp79gtp9b3d2d80c903g"
	}
}
`

func TestUnmarshalConfig(t *testing.T) {
	conf := new(SignedConfig)
	err := json.Unmarshal([]byte(exampleConfig), conf)
	if err != nil {
		t.Fatal(err)
	}
	if conf.Hash() != "5zdffe6kjkrvc3psvwt6jqjzpmeywq3xczcetnxzaxmy9seyw730" {
		t.Fatalf("unexpected config: hash=%s\n%s", conf.Hash(), debug.Pretty(conf))
	}
}
