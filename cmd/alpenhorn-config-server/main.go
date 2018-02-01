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
	"os/user"
	"path/filepath"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"vuvuzela.io/alpenhorn/config"
	// Register the convo inner config.
	_ "vuvuzela.io/vuvuzela/convo"
)

var hostname = flag.String("hostname", "", "hostname of config server")
var setConfigPath = flag.String("setConfig", "", "path to signed config to make current")

func main() {
	flag.Parse()

	u, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	confHome := filepath.Join(u.HomeDir, ".alpenhorn")
	serverPath := filepath.Join(confHome, "config-server-state")

	if *setConfigPath != "" {
		setConfig(confHome, serverPath)
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
		Cache:      autocert.DirCache(filepath.Join(confHome, "config-server-keys")),
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

func setConfig(confHome, serverPath string) {
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
		err := os.Mkdir(confHome, 0700)
		if err == nil {
			fmt.Printf("Created directory %s\n", confHome)
		} else if !os.IsExist(err) {
			log.Fatal(err)
		}

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
