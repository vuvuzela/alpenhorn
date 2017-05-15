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
	"time"

	log "github.com/Sirupsen/logrus"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/alpenhorn/vrpc"
	"vuvuzela.io/crypto/rand"
)

var (
	globalConfPath = flag.String("global", "", "global config file")
	confPath       = flag.String("conf", "", "config file")
	doinit         = flag.Bool("init", false, "create config file")
)

type Config struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey

	DBName           string
	ClientListenAddr string
	EntryListenAddr  string
}

var funcMap = template.FuncMap{
	"base32": toml.EncodeBytes,
}

const confTemplate = `# Alpenhorn PKG server config

publicKey  = {{.PublicKey | base32 | printf "%q"}}
privateKey = {{.PrivateKey | base32 | printf "%q"}}

dbName = {{.DBName | printf "%q"}}
clientListenAddr = {{.ClientListenAddr | printf "%q"}}
entryListenAddr = {{.EntryListenAddr | printf "%q"}}
`

func writeNewConfig() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	conf := &Config{
		PublicKey:  publicKey,
		PrivateKey: privateKey,

		DBName:           "pkg",
		ClientListenAddr: "0.0.0.0:80",
		EntryListenAddr:  "0.0.0.0:27270",
	}

	tmpl := template.Must(template.New("config").Funcs(funcMap).Parse(confTemplate))

	buf := new(bytes.Buffer)
	err = tmpl.Execute(buf, conf)
	if err != nil {
		log.Fatalf("template error: %s", err)
	}
	data := buf.Bytes()

	path := "pkg-init.conf"
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
	coordinatorKey := alpConf.Coordinator.Key
	if coordinatorKey == nil {
		log.Fatalf("no alpenhorn coordinator key specified in global config")
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

	pkgConfig := &pkg.Config{
		SigningKey: conf.PrivateKey,
		DBName:     conf.DBName,
	}
	pkgServer, err := pkg.NewServer(pkgConfig)
	if err != nil {
		log.Fatalf("pkg.NewServer: %s", err)
	}

	clientListener, err := edtls.Listen("tcp", conf.ClientListenAddr, conf.PrivateKey)
	if err != nil {
		log.Fatalf("edtls.Listen: %s", err)
	}
	httpServer := &http.Server{
		Handler:      pkgServer,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	httpServer.SetKeepAlivesEnabled(false)
	go func() {
		err := httpServer.Serve(clientListener)
		if err != nil {
			log.Fatalf("http listen: %s", err)
		}
	}()

	rpcServer := new(vrpc.Server)
	if err := rpcServer.Register(coordinatorKey, "PKG", (*pkg.CoordinatorService)(pkgServer)); err != nil {
		log.Fatalf("vrpc.Register: %s", err)
	}
	err = rpcServer.ListenAndServe(conf.EntryListenAddr, conf.PrivateKey)
	log.Fatal(err)
}
