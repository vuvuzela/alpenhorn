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
	"os"

	"vuvuzela.io/alpenhorn/config"
	// Register the convo inner config.
	_ "vuvuzela.io/vuvuzela/convo"
)

var configPath = flag.String("config", "", "path to new signed config")
var configServerURL = flag.String("url", "", "url of config server")

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
	conf := new(config.SignedConfig)

	if err := json.Unmarshal(configBytes, conf); err != nil {
		log.Fatalf("error decoding json: %s", err)
	}
	if err := conf.Validate(); err != nil {
		log.Fatalf("invalid config: %s", err)
	}

	var client *config.Client
	if *configServerURL == "" {
		client = config.StdClient
	} else {
		client = &config.Client{
			ConfigServerURL: *configServerURL,
		}
	}
	err = client.SetCurrentConfig(conf)
	if err != nil {
		log.Fatalf("failed to set config: %s", err)
	}

	fmt.Printf("Success: uploaded config with hash %s\n", conf.Hash())
}
