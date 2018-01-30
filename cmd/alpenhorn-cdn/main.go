// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"text/template"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/cdn"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/alpenhorn/internal/alplog"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/crypto/rand"
)

var (
	confPath = flag.String("conf", "", "config file")
	doinit   = flag.Bool("init", false, "create config file")
)

type Config struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	DBPath     string
	ListenAddr string
	LogsDir    string
}

var funcMap = template.FuncMap{
	"base32": toml.EncodeBytes,
}

const confTemplate = `# Alpenhorn CDN config

publicKey  = {{.PublicKey | base32 | printf "%q"}}
privateKey = {{.PrivateKey | base32 | printf "%q"}}

dbPath = {{.DBPath | printf "%q" }}
listenAddr = {{.ListenAddr | printf "%q" }}
logsDir = {{.LogsDir | printf "%q" }}
`

func writeNewConfig() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	conf := &Config{
		PublicKey:  publicKey,
		PrivateKey: privateKey,

		DBPath:     "cdn_data",
		ListenAddr: "0.0.0.0:8080",
		LogsDir:    alplog.DefaultLogsDir("alpenhorn-cdn", publicKey),
	}

	tmpl := template.Must(template.New("config").Funcs(funcMap).Parse(confTemplate))

	buf := new(bytes.Buffer)
	err = tmpl.Execute(buf, conf)
	if err != nil {
		log.Fatalf("template error: %s", err)
	}
	data := buf.Bytes()

	path := "cdn-init.conf"
	err = ioutil.WriteFile(path, data, 0600)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s\n", path)
}

func main() {
	flag.Parse()

	if *doinit {
		writeNewConfig()
		return
	}

	if *confPath == "" {
		fmt.Println("specify config file with -conf")
		os.Exit(1)
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

	if conf.ListenAddr == "" {
		log.Fatal("empty listen address in config")
	}

	logHandler, err := alplog.NewProductionOutput(conf.LogsDir)
	if err != nil {
		log.Fatal(err)
	}

	signedConfig, err := config.StdClient.CurrentConfig("AddFriend")
	if err != nil {
		log.Fatal(err)
	}
	addFriendConfig := signedConfig.Inner.(*config.AddFriendConfig)

	server, err := cdn.New(conf.DBPath, addFriendConfig.Coordinator.Key)
	if err != nil {
		log.Fatal(err)
	}

	listener, err := edtls.Listen("tcp", conf.ListenAddr, conf.PrivateKey)
	if err != nil {
		log.Fatalf("edtls listen: %s", err)
	}

	log.Infof("Listening on %q; logging to %s", conf.ListenAddr, logHandler.Name())
	log.StdLogger.EntryHandler = logHandler
	log.Infof("Listening on %q", conf.ListenAddr)

	err = http.Serve(listener, server)
	log.Fatalf("Shutdown: %s", err)
}
