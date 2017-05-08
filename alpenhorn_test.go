// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package alpenhorn

import (
	"bytes"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/cdn"
	"vuvuzela.io/alpenhorn/coordinator"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/internal/mock"
	"vuvuzela.io/alpenhorn/vrpc"
	"vuvuzela.io/crypto/rand"
)

type chanHandler struct {
	confirmedFriend       chan *Friend
	sentFriendRequest     chan *OutgoingFriendRequest
	receivedFriendRequest chan *IncomingFriendRequest
	sentCall              chan *OutgoingCall
	receivedCall          chan *IncomingCall
}

func newChanHandler() *chanHandler {
	return &chanHandler{
		confirmedFriend:       make(chan *Friend, 1),
		sentFriendRequest:     make(chan *OutgoingFriendRequest, 1),
		receivedFriendRequest: make(chan *IncomingFriendRequest, 1),
		sentCall:              make(chan *OutgoingCall, 1),
		receivedCall:          make(chan *IncomingCall, 1),
	}
}

func (h *chanHandler) Error(err error) {
	log.Fatalf("error: %s", err)
}
func (h *chanHandler) ConfirmedFriend(f *Friend) {
	h.confirmedFriend <- f
}
func (h *chanHandler) SentFriendRequest(r *OutgoingFriendRequest) {
	h.sentFriendRequest <- r
}
func (h *chanHandler) ReceivedFriendRequest(r *IncomingFriendRequest) {
	h.receivedFriendRequest <- r
}
func (h *chanHandler) SentCall(call *OutgoingCall) {
	h.sentCall <- call
}
func (h *chanHandler) ReceivedCall(call *IncomingCall) {
	h.receivedCall <- call
}
func (h *chanHandler) UnexpectedSigningKey(in *IncomingFriendRequest, out *OutgoingFriendRequest) {
	log.Fatalf("unexpected signing key for %s", in.Username)
}

func (u *universe) newUser(username string) *Client {
	pkgKeys := make([]ed25519.PublicKey, len(u.PKGs))
	pkgAddrs := make([]string, len(u.PKGs))
	for i, pkgServer := range u.PKGs {
		pkgKeys[i] = pkgServer.Key
		pkgAddrs[i] = pkgServer.ClientAddr
	}

	h := newChanHandler()

	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	client := &Client{
		Username:           username,
		LongTermPublicKey:  userPub,
		LongTermPrivateKey: userPriv,

		ConnectionSettings: ConnectionSettings{
			EntryAddr: u.EntryAddr,
			PKGAddrs:  pkgAddrs,
			PKGKeys:   pkgKeys,
			Mixers:    u.Mixchain.Keys,
			CDNKey:    u.CDNKey,
		},

		Handler: h,
	}

	for _, pkgServer := range u.PKGs {
		err := client.Register(client.Username, pkgServer.ClientAddr, pkgServer.Key)
		if err != nil {
			log.Fatalf("client.Register: %s", err)
		}
	}

	return client
}

func TestAliceFriendsThenCallsBob(t *testing.T) {
	u := createAlpenhornUniverse()
	defer u.Destroy()

	alice := u.newUser("alice@example.org")
	bob := u.newUser("bob@example.org")

	if err := alice.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := bob.Connect(); err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Second)

	_, err := alice.SendFriendRequest(bob.Username, nil)
	if err != nil {
		t.Fatal(err)
	}
	<-alice.Handler.(*chanHandler).sentFriendRequest
	log.Printf("Alice: sent friend request")

	friendRequest := <-bob.Handler.(*chanHandler).receivedFriendRequest
	_, err = friendRequest.Approve()
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("Bob: approved friend request")

	aliceConfirmedFriend := <-alice.Handler.(*chanHandler).confirmedFriend
	if aliceConfirmedFriend.Username != bob.Username {
		t.Fatalf("made friends with unexpected username: %s", aliceConfirmedFriend.Username)
	}
	log.Printf("Alice: confirmed friend")

	bobConfirmedFriend := <-bob.Handler.(*chanHandler).confirmedFriend
	if bobConfirmedFriend.Username != alice.Username {
		t.Fatalf("made friends with unexpected username: %s", bobConfirmedFriend.Username)
	}
	log.Printf("Bob: confirmed friend")

	friend := alice.GetFriend(bob.Username)
	if friend == nil {
		t.Fatal("friend not found")
	}

	friend.Call(0)
	outCall := <-alice.Handler.(*chanHandler).sentCall
	log.Printf("Alice: called Bob")

	inCall := <-bob.Handler.(*chanHandler).receivedCall
	if inCall.Username != alice.Username {
		t.Fatalf("received call from unexpected username: %s", inCall.Username)
	}
	log.Printf("Bob: received call from Alice")

	if !bytes.Equal(outCall.SessionKey()[:], inCall.SessionKey[:]) {
		t.Fatal("Alice and Bob agreed on different keys!")
	}
}

type universe struct {
	Dir string

	Mixchain *mock.Mixchain
	PKGs     []*mock.PKG

	CDNKey        ed25519.PublicKey
	cdnServer     *cdn.Server
	cdnHTTPServer *http.Server

	EntryAddr       string
	entryServer     *coordinator.Server
	entryHTTPServer *http.Server

	entryPKGConns []*vrpc.Client
	entryMixConns []*vrpc.Client
}

func (u *universe) Destroy() error {
	// TODO close everything else
	return os.RemoveAll(u.Dir)
}

func createAlpenhornUniverse() *universe {
	var err error

	u := new(universe)

	u.Dir, err = ioutil.TempDir("", "alpenhorn_universe_")
	if err != nil {
		log.Panicf("ioutil.TempDir: %s", err)
	}

	entryPublic, entryPrivate, _ := ed25519.GenerateKey(rand.Reader)
	cdnPublic, cdnPrivate, _ := ed25519.GenerateKey(rand.Reader)

	u.CDNKey = cdnPublic
	cdnListener, err := edtls.Listen("tcp", "localhost:0", cdnPrivate)
	if err != nil {
		log.Panicf("edtls.Listen: %s", err)
	}
	cdnAddr := cdnListener.Addr().String()

	u.Mixchain = mock.LaunchMixchain(3, cdnAddr, entryPublic, cdnPublic)
	lastMixerKey := u.Mixchain.Keys[len(u.Mixchain.Keys)-1]

	cdnPath := filepath.Join(u.Dir, "cdn")
	u.cdnServer, err = cdn.New(cdnPath, lastMixerKey)
	if err != nil {
		log.Panicf("cdn.New: %s", err)
	}
	u.cdnHTTPServer = &http.Server{
		Handler: u.cdnServer,
	}
	go func() {
		err := u.cdnHTTPServer.Serve(cdnListener)
		if err != http.ErrServerClosed {
			log.Fatalf("http.Serve: %s", err)
		}
	}()

	u.entryPKGConns = make([]*vrpc.Client, 3)
	for i := range u.entryPKGConns {
		srv, err := mock.LaunchPKG(entryPublic, nil)
		if err != nil {
			log.Panicf("launching PKG: %s", err)
		}
		u.PKGs = append(u.PKGs, srv)

		conn, err := vrpc.Dial("tcp", srv.EntryAddr, srv.Key, entryPrivate, 1)
		if err != nil {
			log.Panicf("vrpc.Dial: %s", err)
		}
		u.entryPKGConns[i] = conn
	}

	u.entryMixConns = make([]*vrpc.Client, len(u.Mixchain.Addrs))
	for i := range u.entryMixConns {
		numConns := 1
		if i == 0 {
			numConns = runtime.NumCPU()
		}
		conn, err := vrpc.Dial("tcp", u.Mixchain.Addrs[i], u.Mixchain.Keys[i], entryPrivate, numConns)
		if err != nil {
			log.Panicf("vrpc.Dial: %s", err)
		}
		u.entryMixConns[i] = conn
	}

	addFriendServer := &coordinator.Server{
		Service: "AddFriend",

		PKGServers: u.entryPKGConns,
		PKGWait:    1 * time.Second,

		MixServers:   u.entryMixConns,
		MixWait:      1 * time.Second,
		NumMailboxes: 1,

		RoundWait: 2 * time.Second,

		PersistPath: filepath.Join(u.Dir, "addfriend-coordinator-state"),
	}
	if err := addFriendServer.Run(); err != nil {
		log.Panicf("starting addfriend loop: %s", err)
	}

	dialingServer := &coordinator.Server{
		Service:      "Dialing",
		MixServers:   u.entryMixConns,
		MixWait:      1 * time.Second,
		NumMailboxes: 1,

		RoundWait: 2 * time.Second,

		PersistPath: filepath.Join(u.Dir, "dialing-coordinator-state"),
	}
	if err := dialingServer.Run(); err != nil {
		log.Panicf("starting dialing loop: %s", err)
	}

	entryListener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Panicf("net.Listen: %s", err)
	}
	u.EntryAddr = entryListener.Addr().String()

	mux := http.NewServeMux()
	mux.Handle("/afws", addFriendServer)
	mux.Handle("/dws", dialingServer)
	u.entryHTTPServer = &http.Server{
		Handler: mux,
	}
	go func() {
		err := u.entryHTTPServer.Serve(entryListener)
		if err != http.ErrServerClosed {
			log.Fatalf("http.Serve: %s", err)
		}
	}()

	return u
}
