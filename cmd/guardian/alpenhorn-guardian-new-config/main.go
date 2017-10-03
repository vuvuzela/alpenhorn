// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"vuvuzela.io/alpenhorn/config"
)

var service = flag.String("service", "", "service name")
var printCurrent = flag.Bool("current", false, "print current config")
var configServerURL = flag.String("url", "", "url of config server")

func main() {
	flag.Parse()

	if *service == "" {
		fmt.Println("Specify a service name with -service.")
		os.Exit(1)
	}

	var client *config.Client
	if *configServerURL == "" {
		client = config.StdClient
	} else {
		client = &config.Client{
			ConfigServerURL: *configServerURL,
		}
	}

	conf, err := client.CurrentConfig(*service)
	if err != nil {
		log.Fatalf("failed to fetch current config: %s", err)
	}
	confHash := conf.Hash()

	if !*printCurrent {
		valid := conf.Expires.Sub(conf.Created)
		conf.Created = time.Now()
		conf.Expires = conf.Created.Add(valid)
		conf.PrevConfigHash = confHash
		conf.Signatures = make(map[string][]byte)
	}

	data, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", data)
}
