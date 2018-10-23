// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"vuvuzela.io/alpenhorn/config"
	// Register the convo inner config.
	_ "vuvuzela.io/vuvuzela/convo"
)

var (
	hostname      = flag.String("hostname", "", "hostname of config server")
	setConfigPath = flag.String("setConfig", "", "path to signed config to make current")
	persistPath   = flag.String("persist", "persist_config_server", "persistent data directory")
)

func main() {
	flag.Parse()

	if err := os.MkdirAll(*persistPath, 0700); err != nil {
		log.Fatal(err)
	}
	serverPath := filepath.Join(*persistPath, "config-server-state")

	if *setConfigPath != "" {
		setConfig(serverPath)
		return
	}

	server, err := config.LoadServer(serverPath)
	if os.IsNotExist(err) {
		fmt.Println("No server state found. Please initialize server with -setConfig.")
		os.Exit(1)
	} else if err != nil {
		log.Fatalf("error loading server state: %s", err)
	}

	if *hostname == "" {
		fmt.Println("Please set -hostname.")
		os.Exit(1)
	}

	certManager := autocert.Manager{
		Cache:      autocert.DirCache(filepath.Join(*persistPath, "ssl")),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(*hostname),
	}
	// Listen on :80 for http-01 ACME challenge.
	go http.ListenAndServe(":http", certManager.HTTPHandler(nil))

	httpServer := &http.Server{
		Addr:      ":https",
		Handler:   server,
		TLSConfig: &tls.Config{GetCertificate: certManager.GetCertificate},

		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	log.Printf("Listening on https://%s", *hostname)
	log.Fatal(httpServer.ListenAndServeTLS("", ""))
}

func setConfig(serverPath string) {
	data, err := ioutil.ReadFile(*setConfigPath)
	if err != nil {
		log.Fatal(err)
	}

	conf := new(config.SignedConfig)
	err = json.Unmarshal(data, conf)
	if err != nil {
		log.Fatalf("error decoding config: %s", err)
	}

	server, err := config.LoadServer(serverPath)
	if err == nil {
		err = server.SetCurrentConfig(conf)
		if err != nil {
			log.Fatalf("error setting config: %s", err)
		}
		fmt.Printf("Set current %q config in existing server state.\n", conf.Service)
	} else if os.IsNotExist(err) {
		server, err := config.CreateServer(serverPath)
		if err != nil {
			log.Fatalf("error creating server state: %s", err)
		}
		fmt.Printf("Created new config server state: %s\n", serverPath)

		err = server.SetCurrentConfig(conf)
		if err != nil {
			log.Fatalf("error setting config: %s", err)
		}
		fmt.Printf("Set current %q config in new state.\n", conf.Service)
	} else {
		log.Fatalf("unexpected error loading server state: %s", err)
	}
}
