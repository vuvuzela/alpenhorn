// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"text/template"
	"time"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/internal/alplog"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/crypto/rand"
)

var (
	doinit      = flag.Bool("init", false, "create config file")
	persistPath = flag.String("persist", "persist_pkg", "persistent data directory")
)

type Config struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey

	ListenAddr string
}

var funcMap = template.FuncMap{
	"base32": toml.EncodeBytes,
}

const confTemplate = `# Alpenhorn PKG server config

publicKey  = {{.PublicKey | base32 | printf "%q"}}
privateKey = {{.PrivateKey | base32 | printf "%q"}}

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

		ListenAddr: "0.0.0.0:80",
	}

	tmpl := template.Must(template.New("config").Funcs(funcMap).Parse(confTemplate))

	buf := new(bytes.Buffer)
	err = tmpl.Execute(buf, conf)
	if err != nil {
		log.Fatalf("template error: %s", err)
	}
	data := buf.Bytes()

	path := filepath.Join(*persistPath, "pkg.conf")
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
		return
	}

	if *doinit {
		writeNewConfig()
		return
	}

	confPath := filepath.Join(*persistPath, "pkg.conf")
	data, err := ioutil.ReadFile(confPath)
	if err != nil {
		log.Fatal(err)
	}
	conf := new(Config)
	err = toml.Unmarshal(data, conf)
	if err != nil {
		log.Fatalf("error parsing config %q: %s", confPath, err)
	}
	err = checkConfig(conf)
	if err != nil {
		log.Fatalf("invalid config: %s", err)
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
	if addFriendConfig.Registrar.Address == "" {
		log.Fatal("no Registrar Address defined in current addfriend config!")
	}

	dbPath := filepath.Join(*persistPath, "db")
	if err := os.MkdirAll(dbPath, 0700); err != nil {
		log.Fatal(err)
	}

	pkgConfig := &pkg.Config{
		DBPath:     dbPath,
		SigningKey: conf.PrivateKey,

		CoordinatorKey: addFriendConfig.Coordinator.Key,
		RegistrarKey:   addFriendConfig.Registrar.Key,

		Logger: &log.Logger{
			Level:        log.InfoLevel,
			EntryHandler: logHandler,
		},

		RegTokenHandler: pkg.ExternalVerifier(fmt.Sprintf("https://%s/verify", addFriendConfig.Registrar.Address)),
	}
	pkgServer, err := pkg.NewServer(pkgConfig)
	if err != nil {
		log.Fatalf("pkg.NewServer: %s", err)
	}
	defer func() {
		err := pkgServer.Close()
		if err != nil {
			log.Infof("PKG closed with error: %s", err)
		}
	}()

	httpServer := &http.Server{
		Handler:      pkgServer,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	shutdownDone := make(chan struct{})
	go func() {
		<-sigChan
		log.Infof("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		err := httpServer.Shutdown(ctx)
		if err != nil {
			log.Infof("HTTP server shutdown with error: %s", err)
		}
		close(shutdownDone)
	}()

	listener, err := edtls.Listen("tcp", conf.ListenAddr, conf.PrivateKey)
	if err != nil {
		log.Fatalf("edtls.Listen: %s", err)
	}

	// Let the user know what's happening before switching the logger.
	log.Infof("Listening on %q; logging to %s", conf.ListenAddr, logHandler.Name())
	// Record the start time in the logs directory.
	pkgConfig.Logger.Infof("Listening on %q", conf.ListenAddr)

	err = httpServer.Serve(listener)
	if err != http.ErrServerClosed {
		log.Errorf("http listen: %s", err)
	}

	<-shutdownDone
}

func checkConfig(conf *Config) error {
	if conf.ListenAddr == "" {
		return errors.New("no listen address specified")
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
