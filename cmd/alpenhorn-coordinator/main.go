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
	"os/user"
	"path/filepath"
	"text/template"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/coordinator"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/encoding/toml"
)

var (
	bootstrapPath = flag.String("bootstrap", "", "path to bootstrap config")
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

type BootstrapConfig struct {
	AddFriendStartingConfig *coordinator.AlpenhornConfig `mapstructure:"AddFriend"`
	DialingStartingConfig   *coordinator.AlpenhornConfig `mapstructure:"Dialing"`
}

func doBootstrap() {
	u, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	confHome := filepath.Join(u.HomeDir, ".alpenhorn")

	confPath := filepath.Join(confHome, "coordinator.conf")
	addFriendStatePath := filepath.Join(confHome, "coordinator-addfriend-state")
	dialingStatePath := filepath.Join(confHome, "coordinator-dialing-state")

	doConf := overwrite(confPath)
	doAddFriend := overwrite(addFriendStatePath)
	doDialing := overwrite(dialingStatePath)

	if !doConf && !doAddFriend && !doDialing {
		fmt.Println("Nothing to do.")
		os.Exit(0)
	}

	var bootstrap *BootstrapConfig
	if doAddFriend || doDialing {
		if *bootstrapPath == "" {
			fmt.Println("Please specify a bootstrap config with -bootstrap.")
			os.Exit(1)
		}

		data, err := ioutil.ReadFile(*bootstrapPath)
		if err != nil {
			log.Fatal(err)
		}

		bootstrap = new(BootstrapConfig)
		err = toml.Unmarshal(data, bootstrap)
		if err != nil {
			log.Fatalf("error decoding toml from %s: %s", *bootstrapPath, err)
		}
	}

	err = os.Mkdir(confHome, 0700)
	if err == nil {
		fmt.Printf("Created directory %s\n", confHome)
	} else if !os.IsExist(err) {
		log.Fatal(err)
	}

	if doConf {
		writeNewConfig(confPath)
	}

	if doAddFriend {
		if bootstrap.AddFriendStartingConfig == nil {
			log.Fatalf("no addfriend config defined in %s", *bootstrapPath)
		}
		addFriendServer := &coordinator.Server{
			Service:     "AddFriend",
			PersistPath: addFriendStatePath,
		}
		err := addFriendServer.Bootstrap(bootstrap.AddFriendStartingConfig)
		if err != nil {
			log.Fatalf("error bootstrapping addfriend server: %s", err)
		}
		fmt.Printf("Wrote initial addfriend state: %s\n", addFriendStatePath)
	}

	if doDialing {
		if bootstrap.DialingStartingConfig == nil {
			log.Fatalf("no dialing config defined in %s", *bootstrapPath)
		}
		dialingServer := &coordinator.Server{
			Service:     "Dialing",
			PersistPath: dialingStatePath,
		}
		err := dialingServer.Bootstrap(bootstrap.DialingStartingConfig)
		if err != nil {
			log.Fatalf("error bootstrapping dialing server: %s", err)
		}
		fmt.Printf("Wrote initial dialing state: %s\n", dialingStatePath)
	}

	if doConf {
		fmt.Printf("Please edit the config file before running the server.\n")
	}
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
	fmt.Printf("Wrote new config file: %s\n", path)
}

func init() {
	//log.SetFormatter(&log.JSONFormatter{})
}

func main() {
	flag.Parse()

	if *bootstrapPath != "" {
		doBootstrap()
		return
	}

	u, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	confHome := filepath.Join(u.HomeDir, ".alpenhorn")

	confPath := filepath.Join(confHome, "coordinator.conf")
	data, err := ioutil.ReadFile(confPath)
	if err != nil {
		log.Fatal(err)
	}
	conf := new(Config)
	err = toml.Unmarshal(data, conf)
	if err != nil {
		log.Fatalf("error parsing config %s: %s", confPath, err)
	}

	var addFriendServer *coordinator.Server
	if conf.AddFriendMailboxes > 0 {
		addFriendStatePath := filepath.Join(confHome, "coordinator-addfriend-state")
		addFriendServer = &coordinator.Server{
			Service:    "AddFriend",
			PrivateKey: conf.PrivateKey,

			PKGWait:   conf.PKGWait,
			MixWait:   conf.MixWait,
			RoundWait: conf.AddFriendDelay,

			NumMailboxes: conf.AddFriendMailboxes,

			PersistPath: addFriendStatePath,
		}

		err = addFriendServer.LoadPersistedState()
		if err != nil {
			log.Fatalf("error reading addfriend state from %s: %s", addFriendStatePath, err)
		}
		http.Handle("/addfriend/", http.StripPrefix("/addfriend", addFriendServer))
	}

	var dialingServer *coordinator.Server
	if conf.DialingMailboxes > 0 {
		dialingStatePath := filepath.Join(confHome, "coordinator-dialing-state")
		dialingServer = &coordinator.Server{
			Service:    "Dialing",
			PrivateKey: conf.PrivateKey,

			MixWait:   conf.MixWait,
			RoundWait: conf.DialingDelay,

			NumMailboxes: conf.DialingMailboxes,

			PersistPath: dialingStatePath,
		}

		err = dialingServer.LoadPersistedState()
		if err != nil {
			log.Fatalf("error reading dialing state from %s: %s", dialingStatePath, err)
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

	log.Printf("Listening on: %s", conf.ListenAddr)
	err = http.Serve(listener, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func overwrite(path string) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return true
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s already exists.\n", path)
	fmt.Printf("Overwrite (y/N)? ")
	var yesno [3]byte
	n, err := os.Stdin.Read(yesno[:])
	if err != nil {
		log.Fatal(err)
	}
	if n == 0 {
		return false
	}
	if yesno[0] != 'y' && yesno[0] != 'Y' {
		return false
	}
	return true
}
