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

	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/internal/debug"
	"vuvuzela.io/vuvuzela/mixnet"
)

type trivialInner struct{}

func (x trivialInner) Validate() error { return nil }

func TestVerify(t *testing.T) {
	gA, gApriv := newGuardian("A")

	conf1 := &SignedConfig{
		Version:    SignedConfigVersion,
		Service:    "Trivial",
		Created:    time.Now(),
		Expires:    time.Now().Add(24 * time.Hour),
		Inner:      trivialInner{},
		Guardians:  []Guardian{gA},
		Signatures: make(map[string][]byte),
	}

	if err := conf1.Validate(); err != nil {
		t.Fatal(err)
	}
	err := conf1.Verify()
	if err == nil {
		t.Fatal("expecting Verify to fail")
	}

	conf1.Signatures[base32.EncodeToString(gA.Key)] = ed25519.Sign(gApriv, conf1.SigningMessage())

	err = conf1.Verify()
	if err != nil {
		t.Fatal(err)
	}

	gB, gBpriv := newGuardian("B")

	conf2 := &SignedConfig{
		Version:        SignedConfigVersion,
		Service:        "Trivial",
		Created:        time.Now(),
		Expires:        time.Now().Add(24 * time.Hour),
		PrevConfigHash: conf1.Hash(),
		Inner:          trivialInner{},
		Guardians:      []Guardian{gB},
		Signatures:     nil,
	}

	err = VerifyConfigChain(conf2, conf1)
	if err == nil {
		t.Fatal("expected VerifyConfigChain to fail")
	}

	conf2.Signatures = map[string][]byte{
		base32.EncodeToString(gA.Key): ed25519.Sign(gApriv, conf2.SigningMessage()),
	}
	err = VerifyConfigChain(conf2, conf1)
	if err == nil {
		t.Fatal("expected VerifyConfigChain to fail")
	}
	err = conf2.Verify()
	if err == nil {
		t.Fatal("expecting Verify to fail")
	}

	conf2.Signatures = map[string][]byte{
		base32.EncodeToString(gB.Key): ed25519.Sign(gBpriv, conf2.SigningMessage()),
	}
	err = VerifyConfigChain(conf2, conf1)
	if err == nil {
		t.Fatal("expected VerifyConfigChain to fail")
	}
	err = conf2.Verify()
	if err != nil {
		t.Fatal(err)
	}

	conf2.Signatures = map[string][]byte{
		base32.EncodeToString(gA.Key): ed25519.Sign(gApriv, conf2.SigningMessage()),
		base32.EncodeToString(gB.Key): ed25519.Sign(gBpriv, conf2.SigningMessage()),
	}
	err = VerifyConfigChain(conf2, conf1)
	if err != nil {
		t.Fatal(err)
	}
	err = conf2.Verify()
	if err != nil {
		t.Fatal(err)
	}
}

func newGuardian(username string) (Guardian, ed25519.PrivateKey) {
	guardianPub, guardianPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return Guardian{
		Username: username,
		Key:      guardianPub,
	}, guardianPriv
}

func TestMarshalAddFriendConfig(t *testing.T) {
	guardianPub, guardianPriv, _ := ed25519.GenerateKey(rand.Reader)

	conf := &SignedConfig{
		Version: SignedConfigVersion,

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
			Version: AddFriendConfigVersion,

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
			Registrar: RegistrarConfig{
				Key:     guardianPub,
				Address: "vuvuzela.io",
			},
		},
	}
	sig := ed25519.Sign(guardianPriv, conf.SigningMessage())
	conf.Signatures = map[string][]byte{
		base32.EncodeToString(guardianPub): sig,
	}
	if err := conf.Verify(); err != nil {
		t.Fatal(err)
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

func TestMarshalDialingConfig(t *testing.T) {
	guardianPub, guardianPriv, _ := ed25519.GenerateKey(rand.Reader)

	conf := &SignedConfig{
		Version: SignedConfigVersion,

		// need to round otherwise the time includes a monotonic clock value
		Created: time.Now().Round(0),
		Expires: time.Now().Round(0),

		Guardians: []Guardian{
			{
				Username: "david",
				Key:      guardianPub,
			},
		},

		Service: "Dialing",
		Inner: &DialingConfig{
			Version: DialingConfigVersion,

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
	if err := conf.Verify(); err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}

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
  "Version": 1,
  "Service": "AddFriend",
  "Created": "2017-09-29T06:47:05.396965796-04:00",
  "Expires": "2017-09-29T06:47:05.396966008-04:00",
  "PrevConfigHash": "",
  "Inner": {
    "Version": 1,
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
	},
	"RegistrarHost": "vuvuzela.io"
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
	addFriendConf := conf.Inner.(*AddFriendConfig)
	if addFriendConf.Registrar.Address != "vuvuzela.io" {
		t.Fatalf("invalid Registrar address: %q", addFriendConf.Registrar.Address)
	}
	if key := base32.EncodeToString(addFriendConf.PKGServers[0].Key); key != "5t8c7emvexkwg02yhqwksj7shc93sh3cat3yxk57ghqdr4hp7zq0" {
		t.Fatalf("invalid PKG key: %q", key)
	}
	if key := base32.EncodeToString(addFriendConf.MixServers[0].Key); key != "5t8c7emvexkwg02yhqwksj7shc93sh3cat3yxk57ghqdr4hp7zq0" {
		t.Fatalf("invalid mix server key: %q", key)
	}
	if conf.Hash() != "h0hfmekxv2p9n1bxa269whhadpmmynddbbes94e4zg9q4bsbjb90" {
		t.Fatalf("unexpected config: hash=%s\n%s", conf.Hash(), debug.Pretty(conf))
	}
}
