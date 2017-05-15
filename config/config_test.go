package config

import (
	"bytes"
	"testing"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/ed25519"
)

var config = `
[alpenhorn.coordinator]
key = "csail1"
clientAddress = ":8080"

[[alpenhorn.pkg]]
key = "csail1"
clientAddress = ":1000"
coordinatorAddress = ":1001"

[[alpenhorn.pkg]]
key = "csail2"
clientAddress = ":1002"
coordinatorAddress = ":1003"

[[alpenhorn.mixer]]
key = "csail1"
address = ":2000"

[[alpenhorn.mixer]]
key = "csail2"
address = ":2001"

[vuvuzela.coordinator]
key = "csail3"
clientAddress = ":8081"

[[vuvuzela.mixer]]
key = "csail1"
address = ":3000"

[[vuvuzela.mixer]]
key = "csail2"
address = ":3001"

[[vuvuzela.mixer]]
key = "csail3"
address = ":3002"

[keys]
csail1 = "vnvf94mthygtxcfpmw6r0zgbzf2v87xf1qr3gy8931743j71cdsg"
csail2 = "h3q6dqt8s2a0chn384st31fv2txbfmegg6rtzas9v13kk4j898n0"
csail3 = "0pcj6hte3vg6c7cz6sc8ekz77v4c4cr39h6cvpk3taegrk7665ag"
`

func TestConfig(t *testing.T) {
	var keys = map[string]ed25519.PublicKey{
		"csail1": decodeBase32("vnvf94mthygtxcfpmw6r0zgbzf2v87xf1qr3gy8931743j71cdsg"),
		"csail2": decodeBase32("h3q6dqt8s2a0chn384st31fv2txbfmegg6rtzas9v13kk4j898n0"),
		"csail3": decodeBase32("0pcj6hte3vg6c7cz6sc8ekz77v4c4cr39h6cvpk3taegrk7665ag"),
	}

	globalConf, err := decodeGlobalConfig([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	alpConf, err := globalConf.AlpenhornConfig()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(alpConf.Coordinator.Key, keys["csail1"]) {
		t.Fatal("bad key for alpenhorn coordinator")
	}
	if alpConf.Coordinator.ClientAddress != ":8080" {
		t.Fatal("bad client address for alpenhorn coordinator")
	}
	if len(alpConf.Mixers) != 2 {
		t.Fatal("wrong number of alpenhorn mixers")
	}
	if !bytes.Equal(alpConf.Mixers[1].Key, keys["csail2"]) {
		t.Fatal("bad key for alpenhorn mixer 2")
	}
	if alpConf.Mixers[1].Address != ":2001" {
		t.Fatal("bad address for alpenhorn mixer 2")
	}

	vzConf, err := globalConf.VuvuzelaConfig()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(vzConf.Coordinator.Key, keys["csail3"]) {
		t.Fatal("bad key for vuvuzela coordinator")
	}
	if vzConf.Coordinator.ClientAddress != ":8081" {
		t.Fatal("bad client address for vuvuzela coordinator")
	}

	if len(vzConf.Mixers) != 3 {
		t.Fatal("wrong number of vuvuzela mixers")
	}
}

func decodeBase32(str string) []byte {
	data, err := base32.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return data
}
