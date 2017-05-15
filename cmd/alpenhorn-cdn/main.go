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

	log "github.com/Sirupsen/logrus"

	"vuvuzela.io/alpenhorn/cdn"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/crypto/rand"
)

var (
	confPath       = flag.String("conf", "", "config file")
	globalConfPath = flag.String("global", "", "global config file")
	doinit         = flag.Bool("init", false, "create config file")
)

type Config struct {
	DBPath     string
	ListenAddr string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

var funcMap = template.FuncMap{
	"base32": toml.EncodeBytes,
}

const confTemplate = `# Alpenhorn CDN config

dbPath = {{.DBPath | printf "%q" }}
listenAddr = {{.ListenAddr | printf "%q" }}

publicKey  = {{.PublicKey | base32 | printf "%q"}}
privateKey = {{.PrivateKey | base32 | printf "%q"}}
`

func writeNewConfig() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	conf := &Config{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
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
	mixers := alpConf.Mixers
	if len(mixers) == 0 {
		log.Fatal("no alpenhorn mixers defined in global config")
	}
	lastMixerKey := mixers[len(mixers)-1].Key
	if lastMixerKey == nil {
		log.Fatal("last alpenhorn mixer has no key")
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

	server, err := cdn.New(conf.DBPath, lastMixerKey)
	if err != nil {
		log.Fatal(err)
	}

	listener, err := edtls.Listen("tcp", conf.ListenAddr, conf.PrivateKey)
	if err != nil {
		log.Fatalf("edtls listen: %s", err)
	}

	err = http.Serve(listener, server)
	log.Fatal(err)
}
