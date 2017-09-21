// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/edhttp"
)

var configPath = flag.String("config", "", "path to new signed config")
var coordinatorAddr = flag.String("addr", "", "coordinator address")
var coordinatorKeyStr = flag.String("key", "", "coordinator key")

func main() {
	flag.Parse()

	if *configPath == "" {
		fmt.Println("Specify config file with -config.")
		os.Exit(1)
	}
	if *coordinatorAddr == "" {
		fmt.Println("Specify coordinator address with -addr.")
		os.Exit(1)
	}
	if *coordinatorKeyStr == "" {
		fmt.Println("Specify coordinator key with -key.")
		os.Exit(1)
	}

	coordinatorKey, err := base32.DecodeString(*coordinatorKeyStr)
	if err != nil {
		log.Fatalf("error base32-decoding coordinator key: %s", err)
	}
	if len(coordinatorKey) != ed25519.PublicKeySize {
		log.Fatalf("invalid coordinator key")
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

	service := strings.ToLower(config.Service)
	url := fmt.Sprintf("https://%s/%s/config/new", *coordinatorAddr, service)
	resp, err := (&edhttp.Client{}).PostJSON(coordinatorKey, url, config)
	if err != nil {
		log.Fatalf("POST to %q failed: %s", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := ioutil.ReadAll(resp.Body)
		log.Fatalf("bad http response: %s: %q", resp.Status, msg)
	}
	resp.Body.Close()

	fmt.Printf("Success: uploaded config with hash %s\n", config.Hash())
}
