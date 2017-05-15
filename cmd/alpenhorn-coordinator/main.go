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
	"runtime"
	"text/template"
	"time"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/coordinator"
	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/alpenhorn/vrpc"
)

var (
	globalConfPath = flag.String("global", "", "global config file")
	confPath       = flag.String("conf", "", "config file")
	doinit         = flag.Bool("init", false, "create config file")
)

type Config struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	ListenAddr string
	PersistDir string

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
persistDir = {{.PersistDir | printf "%q" }}

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

func writeNewConfig() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	conf := &Config{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		ListenAddr: "0.0.0.0:8000",
		PersistDir: "/var/run/alpenhorn",

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
	data := buf.Bytes()

	path := "coordinator-init.conf"
	err = ioutil.WriteFile(path, data, 0600)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s\n", path)
}

func init() {
	//log.SetFormatter(&log.JSONFormatter{})
}

func main() {
	flag.Parse()

	if *doinit {
		writeNewConfig()
		return
	}

	if *globalConfPath == "" {
		fmt.Println("specify global config file with -global")
		os.Exit(1)
	}

	if *confPath == "" {
		fmt.Println("specify config file with -conf")
		os.Exit(1)
	}

	globalConf, err := config.ReadGlobalConfigFile(*globalConfPath)
	if err != nil {
		log.Fatal(err)
	}
	alpConf, err := globalConf.AlpenhornConfig()
	if err != nil {
		log.Fatalf("error reading alpenhorn config from %q: %s", *globalConfPath, err)
	}
	if len(alpConf.Mixers) == 0 {
		log.Fatalf("no mix servers defined in global config: %s", *globalConfPath)
	}
	if len(alpConf.PKGs) == 0 {
		log.Fatalf("no PKG servers defined in global config: %s", *globalConfPath)
	}

	data, err := ioutil.ReadFile(*confPath)
	if err != nil {
		log.Fatal(err)
	}
	conf := new(Config)
	err = toml.Unmarshal(data, conf)
	if err != nil {
		log.Fatalf("error parsing config %q: %s", *confPath, err)
	}

	mixConns := make([]*vrpc.Client, len(alpConf.Mixers))
	for i, mixer := range alpConf.Mixers {
		if mixer.Key == nil || mixer.Address == "" {
			log.Fatalf("mixer %d is missing a key or address", i+1)
		}
		numConns := 1
		if i == 0 {
			numConns = runtime.NumCPU()
		}

		log.Printf("connecting to mixer: %s", mixer.Address)
		client, err := vrpc.Dial("tcp", mixer.Address, mixer.Key, conf.PrivateKey, numConns)
		if err != nil {
			log.Fatalf("vrpc.Dial: %s", err)
		}
		mixConns[i] = client
	}

	pkgConns := make([]*vrpc.Client, len(alpConf.PKGs))
	for i, pkg := range alpConf.PKGs {
		if pkg.Key == nil || pkg.CoordinatorAddress == "" {
			log.Fatalf("PKG %d is missing a key or address", i+1)
		}

		client, err := vrpc.Dial("tcp", pkg.CoordinatorAddress, pkg.Key, conf.PrivateKey, 1)
		log.Printf("connecting to PKG: %s", pkg.CoordinatorAddress)
		if err != nil {
			log.Fatalf("vrpc.Dial: %s", err)
		}
		pkgConns[i] = client
	}

	if conf.AddFriendMailboxes > 0 {
		addFriendServer := &coordinator.Server{
			Service:     "AddFriend",
			PersistPath: filepath.Join(conf.PersistDir, "addfriend-coordinator-state"),

			MixServers:   mixConns,
			MixWait:      conf.MixWait,
			NumMailboxes: conf.AddFriendMailboxes,

			PKGServers: pkgConns,
			PKGWait:    conf.PKGWait,

			RoundWait: conf.AddFriendDelay,
		}
		err := addFriendServer.Run()
		if err != nil {
			log.Fatalf("error starting add-friend loop: %s", err)
		}
		http.Handle("/afws", addFriendServer)
	}

	if conf.DialingMailboxes > 0 {
		dialingServer := &coordinator.Server{
			Service:     "Dialing",
			PersistPath: filepath.Join(conf.PersistDir, "dialing-coordinator-state"),

			MixServers:   mixConns,
			MixWait:      conf.MixWait,
			NumMailboxes: conf.DialingMailboxes,

			RoundWait: conf.DialingDelay,
		}
		err := dialingServer.Run()
		if err != nil {
			log.Fatalf("error starting dialing loop: %s", err)
		}
		http.Handle("/dws", dialingServer)
	}

	log.Printf("listening on: %s", conf.ListenAddr)
	err = http.ListenAndServe(conf.ListenAddr, nil)
	if err != nil {
		log.Fatal(err)
	}
}
