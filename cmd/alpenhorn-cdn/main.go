// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/ed25519"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"text/template"

	"vuvuzela.io/alpenhorn/cdn"
	"vuvuzela.io/alpenhorn/cmd/cmdutil"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/alpenhorn/internal/alplog"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/crypto/rand"
)

var (
	doinit      = flag.Bool("init", false, "create config file")
	persistPath = flag.String("persist", "persist_cdn", "persistent data directory")
)

type Config struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey

	ListenAddr string
}

var funcMap = template.FuncMap{
	"base32": toml.EncodeBytes,
}

const confTemplate = `# Alpenhorn CDN config

publicKey  = {{.PublicKey | base32 | printf "%q"}}
privateKey = {{.PrivateKey | base32 | printf "%q"}}

listenAddr = {{.ListenAddr | printf "%q" }}
`

func writeNewConfig(path string) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	conf := &Config{
		PublicKey:  publicKey,
		PrivateKey: privateKey,

		ListenAddr: "0.0.0.0:8080",
	}

	tmpl := template.Must(template.New("config").Funcs(funcMap).Parse(confTemplate))

	buf := new(bytes.Buffer)
	err = tmpl.Execute(buf, conf)
	if err != nil {
		log.Fatalf("template error: %s", err)
	}
	data := buf.Bytes()

	err = ioutil.WriteFile(path, data, 0600)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s\n", path)
}

func main() {
	flag.Parse()

	if err := os.MkdirAll(*persistPath, 0700); err != nil {
		log.Fatal(err)
	}
	confPath := filepath.Join(*persistPath, "cdn.conf")

	if *doinit {
		if cmdutil.Overwrite(confPath) {
			writeNewConfig(confPath)
		}
		return
	}

	data, err := ioutil.ReadFile(confPath)
	if err != nil {
		log.Fatal(err)
	}
	conf := new(Config)
	err = toml.Unmarshal(data, conf)
	if err != nil {
		log.Fatalf("error parsing config %q: %s", confPath, err)
	}

	if conf.ListenAddr == "" {
		log.Fatal("empty listen address in config")
	}

	logsDir := filepath.Join(*persistPath, "logs")
	logHandler, err := alplog.NewProductionOutput(logsDir)
	if err != nil {
		log.Fatal(err)
	}

	signedConfig, err := config.StdClient.CurrentConfig("AddFriend")
	if err != nil {
		log.Fatal(err)
	}
	addFriendConfig := signedConfig.Inner.(*config.AddFriendConfig)

	dbPath := filepath.Join(*persistPath, "bolt_db")
	server, err := cdn.New(dbPath, addFriendConfig.Coordinator.Key)
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
