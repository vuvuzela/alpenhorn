// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package mock

import (
	"log"
	"net"

	"golang.org/x/crypto/ed25519"
	"vuvuzela.io/alpenhorn/addfriend"
	"vuvuzela.io/alpenhorn/dialing"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/mixnet"
	"vuvuzela.io/alpenhorn/vrpc"
	"vuvuzela.io/crypto/rand"
)

type Mixchain struct {
	Keys  []ed25519.PublicKey
	Addrs []string

	rpcServers []*vrpc.Server
}

func (m *Mixchain) Close() error {
	var err error
	for _, srv := range m.rpcServers {
		e := srv.Close()
		if e != nil && err == nil {
			err = e
		}
	}
	return err
}

func LaunchMixchain(length int, cdnAddr string, entryKey, cdnKey ed25519.PublicKey) *Mixchain {
	publicKeys := make([]ed25519.PublicKey, length)
	privateKeys := make([]ed25519.PrivateKey, length)
	listeners := make([]net.Listener, length)
	addrs := make([]string, length)
	for i := 0; i < length; i++ {
		publicKeys[i], privateKeys[i], _ = ed25519.GenerateKey(rand.Reader)
		l, err := edtls.Listen("tcp", "localhost:0", privateKeys[i])
		if err != nil {
			log.Panicf("edtls.Listen: %s", err)
		}
		listeners[i] = l
		addrs[i] = l.Addr().String()
	}

	rpcServers := make([]*vrpc.Server, length)
	for pos := length - 1; pos >= 0; pos-- {
		var nextServer *vrpc.Client
		// if not the last server
		if pos < length-1 {
			var err error
			nextServer, err = vrpc.Dial("tcp", listeners[pos+1].Addr().String(), publicKeys[pos+1], privateKeys[pos], 2)
			if err != nil {
				log.Panicf("vrpc.Dial: %s", err)
			}
		}

		addFriendMixnet := &mixnet.Server{
			SigningKey:     privateKeys[pos],
			ServerPosition: pos,
			NumServers:     length,
			NextServer:     nextServer,
			CDNAddr:        cdnAddr,
			CDNPublicKey:   cdnKey,

			Mixer: &addfriend.Mixer{},
			Laplace: rand.Laplace{
				Mu: 100,
				B:  3.0,
			},
		}

		dialingMixnet := &mixnet.Server{
			SigningKey:     privateKeys[pos],
			ServerPosition: pos,
			NumServers:     length,
			NextServer:     nextServer,
			CDNAddr:        cdnAddr,
			CDNPublicKey:   cdnKey,

			Mixer: &dialing.Mixer{},
			Laplace: rand.Laplace{
				Mu: 100,
				B:  3.0,
			},
		}

		srv := new(vrpc.Server)
		rpcServers[pos] = srv

		if err := srv.Register(entryKey, "DialingCoordinator", &mixnet.CoordinatorService{dialingMixnet}); err != nil {
			log.Fatalf("vrpc.Register: %s", err)
		}
		if err := srv.Register(entryKey, "AddFriendCoordinator", &mixnet.CoordinatorService{addFriendMixnet}); err != nil {
			log.Fatalf("vrpc.Register: %s", err)
		}

		var prevKey ed25519.PublicKey
		if pos == 0 {
			prevKey = entryKey
		} else {
			prevKey = publicKeys[pos-1]
		}
		if err := srv.Register(prevKey, "DialingChain", &mixnet.ChainService{dialingMixnet}); err != nil {
			log.Fatalf("vrpc.Register: %s", err)
		}
		if err := srv.Register(prevKey, "AddFriendChain", &mixnet.ChainService{addFriendMixnet}); err != nil {
			log.Fatalf("vrpc.Register: %s", err)
		}

		go func(pos int) {
			err := srv.Serve(listeners[pos], privateKeys[pos])
			if err != vrpc.ErrServerClosed {
				log.Fatal("vrpc.Serve:", err)
			}
		}(pos)
	}

	return &Mixchain{
		Keys:  publicKeys,
		Addrs: addrs,

		rpcServers: rpcServers,
	}
}
