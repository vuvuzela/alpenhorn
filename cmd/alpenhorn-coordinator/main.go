// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/cmd/cmdutil"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/coordinator"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/alpenhorn/internal/alplog"
	"vuvuzela.io/alpenhorn/log"
)

var (
	doInit      = flag.Bool("init", false, "initialize the coordinator for the first time")
	persistPath = flag.String("persist", "persist", "persistent data directory")
)

type Config struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey

	ListenAddr string

	AddFriendDelay time.Duration
	DialingDelay   time.Duration
	MixWait        time.Duration
	PKGWait        time.Duration

	AddFriendMailboxes uint32
	DialingMailboxes   uint32
}

var funcMap = template.FuncMap{
	"base32": toml.EncodeBytes,
}

const confTemplate = `# Alpenhorn coordinator (entry) server config

publicKey  = {{.PublicKey | base32 | printf "%q"}}
privateKey = {{.PrivateKey | base32 | printf "%q"}}

listenAddr = {{.ListenAddr | printf "%q"}}

addFriendDelay = {{.AddFriendDelay | printf "%q"}}
dialingDelay   = {{.DialingDelay | printf "%q"}}

# mixWait is how long to wait after announcing the mixnet round
# settings and before closing the round.
mixWait = {{.MixWait | printf "%q"}}

# pkgWait is how long to wait after announcing the PKG round
# settings and before announcing the mixnet settings.
pkgWait = {{.PKGWait | printf "%q"}}

addFriendMailboxes = {{.AddFriendMailboxes}}
dialingMailboxes   = {{.DialingMailboxes}}
`

func initService(service string) {
	fmt.Printf("--> Initializing %q service.\n", service)
	servicePersistPath := filepath.Join(*persistPath, strings.ToLower(service)+"-coordinator-state")

	doCoordinator := cmdutil.Overwrite(servicePersistPath)

	if !doCoordinator {
		fmt.Println("Nothing to do.")
		return
	}

	server := &coordinator.Server{
		Service:     service,
		PersistPath: servicePersistPath,
	}
	err := server.Persist()
	if err != nil {
		log.Fatalf("failed to create coordinator server state for service %q: %s", service, err)
	}

	fmt.Printf("! Wrote coordinator server state: %s\n", servicePersistPath)
}

func initCoordinator(confPath string) {
	fmt.Printf("--> Generating coordinator key pair and config.\n")
	if cmdutil.Overwrite(confPath) {
		writeNewConfig(confPath)
		fmt.Printf("--> Please edit the config file before running the server.\n")
	}

	initService("AddFriend")
	initService("Dialing")

}

func writeNewConfig(path string) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	conf := &Config{
		PublicKey:  publicKey,
		PrivateKey: privateKey,

		ListenAddr: "0.0.0.0:8000",

		AddFriendDelay: 10 * time.Second,
		DialingDelay:   5 * time.Second,
		MixWait:        2 * time.Second,
		PKGWait:        5 * time.Second,

		AddFriendMailboxes: 1,
		DialingMailboxes:   1,
	}

	tmpl := template.Must(template.New("config").Funcs(funcMap).Parse(confTemplate))

	buf := new(bytes.Buffer)
	err = tmpl.Execute(buf, conf)
	if err != nil {
		log.Fatalf("template error: %s", err)
	}

	err = ioutil.WriteFile(path, buf.Bytes(), 0600)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("! Wrote new config file: %s\n", path)
}

func main() {
	flag.Parse()

	if err := os.MkdirAll(*persistPath, 0700); err != nil {
		log.Fatal(err)
	}
	confPath := filepath.Join(*persistPath, "coordinator.conf")

	if *doInit {
		initCoordinator(confPath)
		return
	}

	data, err := ioutil.ReadFile(confPath)
	if err != nil {
		log.Fatal(err)
	}
	conf := new(Config)
	err = toml.Unmarshal(data, conf)
	if err != nil {
		log.Fatalf("error parsing config %s: %s", confPath, err)
	}

	logsDir := filepath.Join(*persistPath, "logs")
	logHandler, err := alplog.NewProductionOutput(logsDir)
	if err != nil {
		log.Fatal(err)
	}
	logger := &log.Logger{
		Level:        log.InfoLevel,
		EntryHandler: logHandler,
	}

	var addFriendServer *coordinator.Server
	if conf.AddFriendMailboxes > 0 {
		addFriendServer = &coordinator.Server{
			Service:    "AddFriend",
			PrivateKey: conf.PrivateKey,
			Log:        logger.WithFields(log.Fields{"service": "AddFriend"}),

			ConfigClient: config.StdClient,

			PKGWait:   conf.PKGWait,
			MixWait:   conf.MixWait,
			RoundWait: conf.AddFriendDelay,

			NumMailboxes: conf.AddFriendMailboxes,

			PersistPath: filepath.Join(*persistPath, "addfriend-coordinator-state"),
		}

		err = addFriendServer.LoadPersistedState()
		if err != nil {
			log.Fatalf("error loading addfriend state: %s", err)
		}
		http.Handle("/addfriend/", http.StripPrefix("/addfriend", addFriendServer))
	}

	var dialingServer *coordinator.Server
	if conf.DialingMailboxes > 0 {
		dialingServer = &coordinator.Server{
			Service:    "Dialing",
			PrivateKey: conf.PrivateKey,
			Log:        logger.WithFields(log.Fields{"service": "Dialing"}),

			ConfigClient: config.StdClient,

			MixWait:   conf.MixWait,
			RoundWait: conf.DialingDelay,

			NumMailboxes: conf.DialingMailboxes,

			PersistPath: filepath.Join(*persistPath, "dialing-coordinator-state"),
		}

		err = dialingServer.LoadPersistedState()
		if err != nil {
			log.Fatalf("error loading dialing state: %s", err)
		}
		http.Handle("/dialing/", http.StripPrefix("/dialing", dialingServer))
	}

	if addFriendServer != nil {
		err := addFriendServer.Run()
		if err != nil {
			log.Fatalf("error starting addfriend loop: %s", err)
		}
	}

	if dialingServer != nil {
		err := dialingServer.Run()
		if err != nil {
			log.Fatalf("error starting dialing loop: %s", err)
		}
	}

	listener, err := edtls.Listen("tcp", conf.ListenAddr, conf.PrivateKey)
	if err != nil {
		log.Fatalf("edtls listen: %s", err)
	}

	log.Infof("Listening on %q; logging to %s", conf.ListenAddr, logHandler.Name())
	logger.Infof("Listening on %q", conf.ListenAddr)

	err = http.Serve(listener, nil)
	if err != nil {
		logger.Fatalf("Shutdown: %s", err)
	}
}
