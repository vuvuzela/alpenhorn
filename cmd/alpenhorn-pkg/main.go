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

	_ "github.com/lib/pq"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/internal/alplog"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/crypto/rand"
)

var (
	confPath = flag.String("conf", "", "config file")
	doinit   = flag.Bool("init", false, "create config file")
)

type Config struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey

	CoordinatorKey ed25519.PublicKey

	DBName     string
	ListenAddr string
}

var funcMap = template.FuncMap{
	"base32": toml.EncodeBytes,
}

const confTemplate = `# Alpenhorn PKG server config

publicKey  = {{.PublicKey | base32 | printf "%q"}}
privateKey = {{.PrivateKey | base32 | printf "%q"}}

coordinatorKey = "change me"

dbName = {{.DBName | printf "%q"}}
listenAddr = {{.ListenAddr | printf "%q"}}
`

func writeNewConfig() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	conf := &Config{
		PublicKey:  publicKey,
		PrivateKey: privateKey,

		DBName:     "pkg",
		ListenAddr: "0.0.0.0:80",
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

func init() {
	log.LogDates(log.Stderr)
	log.StdLogger.EntryHandler = alplog.OutputText(log.Stderr)
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
	err = checkConfig(conf)
	if err != nil {
		log.Fatalf("invalid config: %s", err)
	}

	pkgConfig := &pkg.Config{
		SigningKey:     conf.PrivateKey,
		DBName:         conf.DBName,
		CoordinatorKey: conf.CoordinatorKey,
	}
	pkgServer, err := pkg.NewServer(pkgConfig)
	if err != nil {
		log.Fatalf("pkg.NewServer: %s", err)
	}

	listener, err := edtls.Listen("tcp", conf.ListenAddr, conf.PrivateKey)
	if err != nil {
		log.Fatalf("edtls.Listen: %s", err)
	}
	httpServer := &http.Server{
		Handler:      pkgServer,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	log.Infof("Listening on %q", conf.ListenAddr)
	err = httpServer.Serve(listener)
	if err != nil {
		log.Fatalf("http listen: %s", err)
	}
}

func checkConfig(conf *Config) error {
	if conf.ListenAddr == "" {
		return errors.New("no listen address specified")
	}
	if conf.DBName == "" {
		return errors.New("no database name specified")
	}
	if len(conf.CoordinatorKey) != ed25519.PublicKeySize {
		return errors.New("invalid coordinator key")
	}
	if len(conf.PrivateKey) != ed25519.PrivateKeySize {
		return errors.New("invalid private key")
	}
	expectedPub := conf.PrivateKey.Public().(ed25519.PublicKey)
	if !bytes.Equal(expectedPub, conf.PublicKey) {
		return errors.New("public key does not correspond to private key")
	}
	return nil
}
