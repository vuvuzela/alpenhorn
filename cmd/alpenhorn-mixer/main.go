// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"text/template"

	"golang.org/x/crypto/ed25519"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"vuvuzela.io/alpenhorn/addfriend"
	"vuvuzela.io/alpenhorn/cmd/cmdutil"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/dialing"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/crypto/rand"
	"vuvuzela.io/vuvuzela/mixnet"
	pb "vuvuzela.io/vuvuzela/mixnet/convopb"
)

var (
	doinit      = flag.Bool("init", false, "create config file")
	persistPath = flag.String("persist", "persist_alpmix", "persistent data directory")
)

type Config struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey

	ListenAddr string

	AddFriendNoise rand.Laplace
	DialingNoise   rand.Laplace
}

var funcMap = template.FuncMap{
	"base32": toml.EncodeBytes,
}

const confTemplate = `# Alpenhorn mixnet server config

publicKey  = {{.PublicKey | base32 | printf "%q"}}
privateKey = {{.PrivateKey | base32 | printf "%q"}}

listenAddr = {{.ListenAddr | printf "%q"}}

[addFriendNoise]
mu = {{.AddFriendNoise.Mu | printf "%0.1f"}}
b = {{.AddFriendNoise.B | printf "%0.1f"}}

[dialingNoise]
mu = {{.DialingNoise.Mu | printf "%0.1f"}}
b = {{.DialingNoise.B | printf "%0.1f"}}
`

func writeNewConfig(path string) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	conf := &Config{
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
	confPath := filepath.Join(*persistPath, "mixer.conf")

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

	signedConfig, err := config.StdClient.CurrentConfig("AddFriend")
	if err != nil {
		log.Fatal(err)
	}
	addFriendConfig := signedConfig.Inner.(*config.AddFriendConfig)

	mixServer := &mixnet.Server{
		SigningKey: conf.PrivateKey,
		// Assumes that AddFriend and Dialing use the same coordinator.
		CoordinatorKey: addFriendConfig.Coordinator.Key,

		Services: map[string]mixnet.MixService{
			"AddFriend": &addfriend.Mixer{
				SigningKey: conf.PrivateKey,
				Laplace:    conf.AddFriendNoise,
			},

			"Dialing": &dialing.Mixer{
				SigningKey: conf.PrivateKey,
				Laplace:    conf.DialingNoise,
			},
		},
	}

	creds := credentials.NewTLS(edtls.NewTLSServerConfig(conf.PrivateKey))
	grpcServer := grpc.NewServer(grpc.Creds(creds))

	pb.RegisterMixnetServer(grpcServer, mixServer)

	log.Infof("Listening on %q", conf.ListenAddr)

	listener, err := net.Listen("tcp", conf.ListenAddr)
	if err != nil {
		log.Fatalf("net.Listen: %s", err)
	}

	err = grpcServer.Serve(listener)
	log.Fatalf("Shutdown: %s", err)
}
