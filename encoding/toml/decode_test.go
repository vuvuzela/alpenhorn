// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toml

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"
)

type config struct {
	Entry      string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	ExtraData  []byte
	Count      int
	Servers    map[string]serverInfo
	Clients    []clientInfo `mapstructure:"client"`
}

type serverInfo struct {
	IP       string
	Mu       int
	B        float64
	Wait     time.Duration
	Optional []byte
}

type clientInfo struct {
	Username string
	Friends  map[string]ed25519.PublicKey
}

const tomlConfig = `
entry = "192.168.0.1"
publicKey = "gg3rwp4ye8j1xbmkf2y5ae55cne1y3m9ew8g3156g8n5c572j2d0"
privateKey = "dmrrz794yevgkb0gk0qqagzsym4d294eckbj2dq1khcpksnj654881web2f7490ynt9qhf2n72jpaq0z1t4qe481gjk84ajp2kh916g"
extraData = "928vmmzbwh746grq3n1xp497m9m2jn4t2948njqf4bd841ykv6xg"
count = 42

[servers]

[servers.alpha]
ip = "10.0.0.1"
mu = 3000
b = 72.5
wait = "30s"

[servers.beta]
ip = "10.0.0.2"
mu = 9000
b = 4000.714
wait = 1000000000
optional = [3, 0, 1, 2]

[[client]]
username = "alice"

[client.friends]
bob = "m3vzyq6r1m27m1se385qhdprzbab6xhyy6ftv5w3mhttej3qmdp0"
eve = "2myv6p59nb9a7g2n27etd4cv3mhcznp4hc2z0dm18cksasajs10g"

[[client]]
username = "sam"

[client.friends]
eve = "d3311ab5xyzmw6r5tmffama53xct661ky0yb9hrm1xfmvzh9gnk0"
`

func TestDecode(t *testing.T) {
	c := new(config)
	err := Unmarshal([]byte(tomlConfig), c)
	if err != nil {
		t.Fatal(err)
	}

	pub := ed25519.PublicKey{0x84, 0x7, 0x8e, 0x58, 0x9e, 0x72, 0x24, 0x1e, 0xae, 0x93, 0x78, 0xbc, 0x55, 0x38, 0xa5, 0x65, 0x5c, 0x1f, 0xe, 0x89, 0x77, 0x11, 0x1, 0x84, 0xa6, 0x82, 0x2a, 0x56, 0x14, 0xe2, 0x90, 0x9a}
	priv := ed25519.PrivateKey{0x6d, 0x31, 0x8f, 0x9d, 0x24, 0xf3, 0xb7, 0x9, 0xac, 0x10, 0x98, 0x2f, 0x75, 0x43, 0xf9, 0xf5, 0x8, 0xd1, 0x24, 0x8e, 0x64, 0xd7, 0x21, 0x36, 0xe1, 0x9c, 0x59, 0x69, 0xe6, 0xb2, 0x31, 0x48, 0x84, 0x7, 0x8e, 0x58, 0x9e, 0x72, 0x24, 0x1e, 0xae, 0x93, 0x78, 0xbc, 0x55, 0x38, 0xa5, 0x65, 0x5c, 0x1f, 0xe, 0x89, 0x77, 0x11, 0x1, 0x84, 0xa6, 0x82, 0x2a, 0x56, 0x14, 0xe2, 0x90, 0x9a}
	extraData := []byte{0x48, 0x91, 0xba, 0x53, 0xeb, 0xe4, 0x4e, 0x43, 0x43, 0x17, 0x1d, 0x43, 0xdb, 0x11, 0x27, 0xa2, 0x68, 0x29, 0x54, 0x9a, 0x12, 0x48, 0x8a, 0xca, 0xef, 0x22, 0xda, 0x82, 0x7, 0xd3, 0xd9, 0xbb}

	if !bytes.Equal(c.ExtraData, extraData) {
		t.Fatalf("unexpected extra data in config: %#v", c.ExtraData)
	}
	if !bytes.Equal(c.PrivateKey, priv) {
		t.Fatalf("unexpected private key in config: %#v", c.PrivateKey)
	}
	if !bytes.Equal(c.PublicKey, pub) {
		t.Fatalf("unexpected public key in config: %#v", c.PublicKey)
	}

	if c.Servers["alpha"].IP != "10.0.0.1" {
		t.Fatalf("unexpected IP for server alpha: %s", c.Servers["alpha"].IP)
	}
	if c.Servers["beta"].IP != "10.0.0.2" {
		t.Fatalf("unexpected IP for server beta: %s", c.Servers["beta"].IP)
	}

	if c.Servers["alpha"].B != float64(72.5) {
		t.Fatalf("unexpected b value for server alpha: %v", c.Servers["alpha"].B)
	}
	if c.Servers["beta"].B != float64(4000.714) {
		t.Fatalf("unexpected b value for server beta: %v", c.Servers["beta"].B)
	}

	if c.Servers["alpha"].Wait != time.Duration(30*time.Second) {
		t.Fatalf("unexpected wait value for server alpha: %#v", c.Servers["alpha"].Wait)
	}
	if c.Servers["beta"].Wait != time.Duration(1*time.Second) {
		t.Fatalf("unexpected wait value for server beta: %#v", c.Servers["beta"].Wait)
	}

	if !bytes.Equal(c.Servers["beta"].Optional, []byte{3, 0, 1, 2}) {
		t.Fatalf("unexpected optional value for server beta: %#v", c.Servers["beta"].Optional)
	}

	if len(c.Clients) != 2 {
		t.Fatalf("unexpected number of clients, got %d want %d", len(c.Clients), 2)
	}
	if c.Clients[0].Username != "alice" {
		t.Fatalf("wrong username for first client, got %q want %q", c.Clients[0].Username, "alice")
	}
	if len(c.Clients[0].Friends) != 2 {
		t.Fatalf("unexpected number of friends for first client, got %d want %d", len(c.Clients[0].Friends), 2)
	}
	if !bytes.Equal(c.Clients[0].Friends["bob"], decodeBytes("m3vzyq6r1m27m1se385qhdprzbab6xhyy6ftv5w3mhttej3qmdp0")) {
		t.Fatalf("bad key for bob in client 1, got %s", EncodeBytes(c.Clients[0].Friends["bob"]))
	}
	if !bytes.Equal(c.Clients[0].Friends["eve"], decodeBytes("2myv6p59nb9a7g2n27etd4cv3mhcznp4hc2z0dm18cksasajs10g")) {
		t.Fatalf("bad key for eve in client 1, got %s", EncodeBytes(c.Clients[0].Friends["eve"]))
	}
	if c.Clients[1].Username != "sam" {
		t.Fatalf("wrong username for first client, got %q want %q", c.Clients[1].Username, "sam")
	}
	if !bytes.Equal(c.Clients[1].Friends["eve"], decodeBytes("d3311ab5xyzmw6r5tmffama53xct661ky0yb9hrm1xfmvzh9gnk0")) {
		t.Fatalf("bad key for eve in client 2, got %s", EncodeBytes(c.Clients[1].Friends["eve"]))
	}
}

func decodeBytes(str string) []byte {
	data, err := DecodeBytes(str)
	if err != nil {
		panic(err)
	}
	return data
}
