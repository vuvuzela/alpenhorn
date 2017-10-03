// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/cmd/guardian"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/log"
	// Register the convo inner config.
	_ "vuvuzela.io/vuvuzela/convo"
)

var configPath = flag.String("config", "", "path to new signed config")

func main() {
	flag.Parse()

	if *configPath == "" {
		fmt.Println("Specify config file with -config.")
		os.Exit(1)
	}

	configBytes, err := ioutil.ReadFile(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	config := new(config.SignedConfig)

	if err := json.Unmarshal(configBytes, config); err != nil {
		log.Fatalf("error decoding json: %s", err)
	}
	if err := config.Validate(); err != nil {
		log.Fatalf("invalid config: %s", err)
	}

	appDir := guardian.Appdir()
	privatePath := filepath.Join(appDir, "guardian.privatekey")

	privateKey := guardian.ReadPrivateKey(privatePath)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	myPos := -1
	for i, g := range config.Guardians {
		if bytes.Equal(g.Key, publicKey) {
			myPos = i
		}
	}
	if myPos == -1 {
		fmt.Printf("! Warning: your key is not in the supplied config's Guardian list!\n")
	}

	msg := config.SigningMessage()
	sig := ed25519.Sign(privateKey, msg)

	fmt.Printf("%q: %q\n", base32.EncodeToString(publicKey), base32.EncodeToString(sig))
}
