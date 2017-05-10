// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"text/template"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/addfriend"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/dialing"
	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/alpenhorn/mixnet"
	"vuvuzela.io/alpenhorn/vrpc"
	"vuvuzela.io/crypto/rand"
)

var (
	globalConfPath = flag.String("global", "", "global config file")
	confPath       = flag.String("conf", "", "config file")
	doinit         = flag.Bool("init", false, "create config file")
)

type Config struct {
	ServerName string
	ListenAddr string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey

	AddFriendNoise rand.Laplace
	DialingNoise   rand.Laplace
}

var funcMap = template.FuncMap{
	"base32": toml.EncodeBytes,
}

const confTemplate = `# Alpenhorn mixnet server config

serverName = {{.ServerName | printf "%q"}}
listenAddr = {{.ListenAddr | printf "%q"}}

publicKey  = {{.PublicKey | base32 | printf "%q"}}
privateKey = {{.PrivateKey | base32 | printf "%q"}}

[addFriendNoise]
mu = {{.AddFriendNoise.Mu | printf "%0.1f"}}
b = {{.AddFriendNoise.B | printf "%0.1f"}}

[dialingNoise]
mu = {{.DialingNoise.Mu | printf "%0.1f"}}
b = {{.DialingNoise.B | printf "%0.1f"}}
`

func writeNewConfig() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	conf := &Config{
		ServerName: "server1",
		ListenAddr: "0.0.0.0:28000",
		PublicKey:  publicKey,
		PrivateKey: privateKey,

		AddFriendNoise: rand.Laplace{
			Mu: 100,
			B:  3.0,
		},

		DialingNoise: rand.Laplace{
			Mu: 100,
			B:  3.0,
		},
	}

	tmpl := template.Must(template.New("config").Funcs(funcMap).Parse(confTemplate))

	buf := new(bytes.Buffer)
	err = tmpl.Execute(buf, conf)
	if err != nil {
		log.Fatalf("template error: %s", err)
	}
	data := buf.Bytes()

	path := "mixer-init.conf"
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

	globalConf, err := config.ReadFile(*globalConfPath)
	if err != nil {
		log.Fatal(err)
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

	serverPos := globalConf.MixerPosition(conf.ServerName)
	if serverPos < 0 {
		log.Fatalf("server %s not found in global mixer list", conf.ServerName)
	}

	var nextServer *vrpc.Client
	nextInfo := globalConf.NextMixer(conf.ServerName)
	if nextInfo != nil {
		nextServer, err = vrpc.Dial("tcp", nextInfo.Address, nextInfo.PublicKey, conf.PrivateKey, runtime.NumCPU())
		if err != nil {
			log.Fatalf("vrpc.Dial: %s", err)
		}
	}

	cdn := globalConf.GetServer(globalConf.CDN)

	addFriendMixnet := &mixnet.Server{
		SigningKey:     conf.PrivateKey,
		ServerPosition: serverPos,
		NumServers:     len(globalConf.Mixers),
		NextServer:     nextServer,
		CDNAddr:        cdn.Address,
		CDNPublicKey:   cdn.PublicKey,

		Mixer:   &addfriend.Mixer{},
		Laplace: conf.AddFriendNoise,
	}

	dialingMixnet := &mixnet.Server{
		SigningKey:     conf.PrivateKey,
		ServerPosition: serverPos,
		NumServers:     len(globalConf.Mixers),
		NextServer:     nextServer,
		CDNAddr:        cdn.Address,
		CDNPublicKey:   cdn.PublicKey,

		Mixer:   &dialing.Mixer{},
		Laplace: conf.DialingNoise,
	}

	entryServer := globalConf.GetServer(globalConf.EntryServer)
	if entryServer == nil {
		log.Fatalf("no entry server defined in global config")
	}

	srv := new(vrpc.Server)
	if err := srv.Register(entryServer.PublicKey, "DialingCoordinator", &mixnet.CoordinatorService{dialingMixnet}); err != nil {
		log.Fatalf("vrpc.Register: %s", err)
	}
	if err := srv.Register(entryServer.PublicKey, "AddFriendCoordinator", &mixnet.CoordinatorService{addFriendMixnet}); err != nil {
		log.Fatalf("vrpc.Register: %s", err)
	}

	prevServer := globalConf.PrevMixer(conf.ServerName)
	if err := srv.Register(prevServer.PublicKey, "DialingChain", &mixnet.ChainService{dialingMixnet}); err != nil {
		log.Fatalf("vrpc.Register: %s", err)
	}
	if err := srv.Register(prevServer.PublicKey, "AddFriendChain", &mixnet.ChainService{addFriendMixnet}); err != nil {
		log.Fatalf("vrpc.Register: %s", err)
	}

	err = srv.ListenAndServe(conf.ListenAddr, conf.PrivateKey)
	if err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}
