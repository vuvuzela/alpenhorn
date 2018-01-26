// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package alpenhorn

import (
	"bytes"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/cdn"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/coordinator"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/internal/alplog"
	"vuvuzela.io/alpenhorn/internal/debug"
	"vuvuzela.io/alpenhorn/internal/mock"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/crypto/rand"
)

type chanHandler struct {
	errPrefix string

	confirmedFriend       chan *Friend
	sentFriendRequest     chan *OutgoingFriendRequest
	receivedFriendRequest chan *IncomingFriendRequest
	sentCall              chan *OutgoingCall
	receivedCall          chan *IncomingCall
	newConfig             chan []*config.SignedConfig
}

func newChanHandler(errPrefix string) *chanHandler {
	return &chanHandler{
		errPrefix:             errPrefix,
		confirmedFriend:       make(chan *Friend, 1),
		sentFriendRequest:     make(chan *OutgoingFriendRequest, 1),
		receivedFriendRequest: make(chan *IncomingFriendRequest, 1),
		sentCall:              make(chan *OutgoingCall, 1),
		receivedCall:          make(chan *IncomingCall, 1),
		newConfig:             make(chan []*config.SignedConfig, 1),
	}
}

func (h *chanHandler) Error(err error) {
	log.Errorf(h.errPrefix+": client error: %s", err)
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
func (h *chanHandler) SendingCall(call *OutgoingCall) {
	h.sentCall <- call
}
func (h *chanHandler) ReceivedCall(call *IncomingCall) {
	h.receivedCall <- call
}
func (h *chanHandler) NewConfig(configs []*config.SignedConfig) {
	h.newConfig <- configs
}
func (h *chanHandler) UnexpectedSigningKey(in *IncomingFriendRequest, out *OutgoingFriendRequest) {
	log.Fatalf("unexpected signing key for %s", in.Username)
}

func (u *universe) newUser(username string) *Client {
	pkgKeys := make([]ed25519.PublicKey, len(u.PKGs))
	pkgAddrs := make([]string, len(u.PKGs))
	for i, pkgServer := range u.PKGs {
		pkgKeys[i] = pkgServer.Key
		pkgAddrs[i] = pkgServer.Address
	}

	h := newChanHandler(username)

	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	client := &Client{
		Username:           username,
		LongTermPublicKey:  userPub,
		LongTermPrivateKey: userPriv,
		PKGLoginKey:        userPriv,

		ConfigClient: u.ConfigClient,

		Handler: h,
	}
	err := client.Bootstrap(
		u.CurrentConfig("AddFriend"),
		u.CurrentConfig("Dialing"),
	)
	if err != nil {
		log.Fatalf("client.Bootstrap: %s", err)
	}

	for _, pkgServer := range u.PKGs {
		err := client.Register(pkgServer.PublicServerConfig, "token")
		if err != nil {
			log.Fatalf("client.Register: %s", err)
		}
	}

	return client
}

func TestAliceFriendsThenCallsBob(t *testing.T) {
	u := createAlpenhornUniverse()
	defer func() {
		// Give time for goroutines to finish before pulling the rug from under them.
		time.Sleep(1 * time.Second)
		u.Destroy()
	}()

	alice := u.newUser("alice")
	bob := u.newUser("bob")
	bob.ClientPersistPath = filepath.Join(u.Dir, "bob-client")
	bob.KeywheelPersistPath = filepath.Join(u.Dir, "bob-keywheel")

	_, err := alice.ConnectAddFriend()
	if err != nil {
		t.Fatal(err)
	}
	defer alice.CloseAddFriend()
	_, err = alice.ConnectDialing()
	if err != nil {
		t.Fatal(err)
	}
	defer alice.CloseDialing()

	disconnectBobAddFriend, err := bob.ConnectAddFriend()
	if err != nil {
		t.Fatal(err)
	}
	defer bob.CloseAddFriend()
	disconnectBobDialing, err := bob.ConnectDialing()
	if err != nil {
		t.Fatal(err)
	}
	defer bob.CloseDialing()

	time.Sleep(2 * time.Second)

	_, err = alice.SendFriendRequest(bob.Username, nil)
	if err != nil {
		t.Fatal(err)
	}
	<-alice.Handler.(*chanHandler).sentFriendRequest
	log.Infof("Alice: sent friend request")

	friendRequest := <-bob.Handler.(*chanHandler).receivedFriendRequest
	currentConfig := u.CurrentConfig("AddFriend").Inner.(*config.AddFriendConfig)
	if !reflect.DeepEqual(currentConfig.PKGServers, friendRequest.Verifiers) {
		t.Fatalf("unexpected verifiers list in friend request:\ngot:  %s\nwant: %s",
			debug.Pretty(friendRequest.Verifiers), debug.Pretty(currentConfig.PKGServers))
	}
	_, err = friendRequest.Approve()
	if err != nil {
		t.Fatal(err)
	}
	<-bob.Handler.(*chanHandler).sentFriendRequest
	log.Infof("Bob: approved friend request")

	aliceConfirmedFriend := <-alice.Handler.(*chanHandler).confirmedFriend
	if aliceConfirmedFriend.Username != bob.Username {
		t.Fatalf("made friends with unexpected username: %s", aliceConfirmedFriend.Username)
	}
	log.Infof("Alice: confirmed friend")

	bobConfirmedFriend := <-bob.Handler.(*chanHandler).confirmedFriend
	if bobConfirmedFriend.Username != alice.Username {
		t.Fatalf("made friends with unexpected username: %s", bobConfirmedFriend.Username)
	}
	log.Infof("Bob: confirmed friend")

	friend := alice.GetFriend(bob.Username)
	if friend == nil {
		t.Fatal("friend not found")
	}

	friend.Call(0)
	outCall := <-alice.Handler.(*chanHandler).sentCall
	log.Infof("Alice: called Bob")

	inCall := <-bob.Handler.(*chanHandler).receivedCall
	if inCall.Username != alice.Username {
		t.Fatalf("received call from unexpected username: %s", inCall.Username)
	}
	log.Infof("Bob: received call from Alice")

	if !bytes.Equal(outCall.SessionKey()[:], inCall.SessionKey[:]) {
		t.Fatal("Alice and Bob agreed on different keys!")
	}

	// Test persistence.
	if err := bob.CloseAddFriend(); err != nil {
		t.Fatal(err)
	}
	if err := bob.CloseDialing(); err != nil {
		t.Fatal(err)
	}
	<-disconnectBobAddFriend
	<-disconnectBobDialing

	bob2, err := LoadClient(bob.ClientPersistPath, bob.KeywheelPersistPath)
	if err != nil {
		t.Fatal(err)
	}
	bob2.ConfigClient = u.ConfigClient
	bob2.Handler = newChanHandler("bob2")

	_, err = bob2.ConnectAddFriend()
	if err != nil {
		t.Fatal(err)
	}
	defer bob2.CloseAddFriend()
	_, err = bob2.ConnectDialing()
	if err != nil {
		t.Fatal(err)
	}
	defer bob2.CloseDialing()

	friend = bob2.GetFriend(alice.Username)
	friend.Call(0)
	outCall = <-bob2.Handler.(*chanHandler).sentCall
	if outCall.Username != alice.Username {
		t.Fatalf("bad username in call: got %q, want %q", outCall.Username, alice.Username)
	}

	inCall = <-alice.Handler.(*chanHandler).receivedCall
	if inCall.Username != bob2.Username {
		t.Fatalf("received call from unexpected username: %s", inCall.Username)
	}
	log.Infof("Alice: received call from Bob")

	// Test adding a new PKG.
	newPKG, err := mock.LaunchPKG(u.CoordinatorKey, func(username string, token string) error {
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	log.Infof("Created new PKG server: %s", newPKG.Address)

	prevAddFriendConfig := u.CurrentConfig("AddFriend")
	prevAddFriendInner := prevAddFriendConfig.Inner.(*config.AddFriendConfig)
	newAddFriendConfig := &config.SignedConfig{
		Version:        config.SignedConfigVersion,
		Created:        time.Now(),
		Expires:        time.Now().Add(24 * time.Hour),
		PrevConfigHash: prevAddFriendConfig.Hash(),

		Service: "AddFriend",
		Inner: &config.AddFriendConfig{
			Version:     config.AddFriendConfigVersion,
			Coordinator: prevAddFriendInner.Coordinator,
			MixServers:  prevAddFriendInner.MixServers,
			PKGServers:  append(prevAddFriendInner.PKGServers, newPKG.PublicServerConfig),
			CDNServer:   prevAddFriendInner.CDNServer,
		},
	}
	err = u.ConfigClient.SetCurrentConfig(newAddFriendConfig)
	if err != nil {
		t.Fatal(err)
	}
	log.Infof("Uploaded new addfriend config")

	confs := <-bob2.Handler.(*chanHandler).newConfig
	if confs[0].Hash() != newAddFriendConfig.Hash() {
		t.Fatalf("received unexpected config: %s", debug.Pretty(confs))
	}
	confs = <-alice.Handler.(*chanHandler).newConfig
	if confs[0].Hash() != newAddFriendConfig.Hash() {
		t.Fatalf("received unexpected config: %s", debug.Pretty(confs))
	}
	// Register with the new PKG. Previously, the Alpenhorn client did this automatically.
	if err := bob2.Register(newPKG.PublicServerConfig, ""); err != nil {
		t.Fatal(err)
	}
	if err := alice.Register(newPKG.PublicServerConfig, ""); err != nil {
		t.Fatal(err)
	}

	_, err = bob2.SendFriendRequest(alice.Username, nil)
	if err != nil {
		t.Fatal(err)
	}
	<-bob2.Handler.(*chanHandler).sentFriendRequest

	friendRequest = <-alice.Handler.(*chanHandler).receivedFriendRequest
	// No guarantee that Verifiers will be in the same order but it works for now:
	if !reflect.DeepEqual(friendRequest.Verifiers, newAddFriendConfig.Inner.(*config.AddFriendConfig).PKGServers) {
		t.Fatalf("unexpected verifiers:\ngot:  %s\nwant: %s", debug.Pretty(friendRequest.Verifiers), debug.Pretty(newAddFriendConfig.Inner.(*config.AddFriendConfig).PKGServers))
	}
	log.Infof("Alice: received friend request from Bob")

	_, err = friendRequest.Approve()
	if err != nil {
		t.Fatal(err)
	}
	<-alice.Handler.(*chanHandler).sentFriendRequest
	<-alice.Handler.(*chanHandler).confirmedFriend

	friend = <-bob2.Handler.(*chanHandler).confirmedFriend
	friend.Call(1)
	outCall = <-bob2.Handler.(*chanHandler).sentCall
	if outCall.Intent() != 1 {
		t.Fatalf("wrong intent: got %d, want %d", outCall.Intent(), 1)
	}
	log.Infof("Bob: confirmed friend; calling with intent 1")

	inCall = <-alice.Handler.(*chanHandler).receivedCall
	if inCall.Intent != 1 {
		t.Fatalf("wrong intent: got %d, want %d", inCall.Intent, 1)
	}
	log.Infof("Alice: received call with intent 1")

	// Add more servers to the end of the addfriend mixchain.
	newChain := mock.LaunchMixchain(2, u.CoordinatorKey)

	prevAddFriendConfig = u.CurrentConfig("AddFriend")
	prevAddFriendInner = prevAddFriendConfig.Inner.(*config.AddFriendConfig)
	newAddFriendConfig = &config.SignedConfig{
		Version:        config.SignedConfigVersion,
		Created:        time.Now(),
		Expires:        time.Now().Add(24 * time.Hour),
		PrevConfigHash: prevAddFriendConfig.Hash(),

		Service: "AddFriend",
		Inner: &config.AddFriendConfig{
			Version:     config.AddFriendConfigVersion,
			Coordinator: prevAddFriendInner.Coordinator,
			MixServers:  append(prevAddFriendInner.MixServers, newChain.Servers...),
			PKGServers:  prevAddFriendInner.PKGServers,
			CDNServer:   prevAddFriendInner.CDNServer,
		},
	}
	err = u.ConfigClient.SetCurrentConfig(newAddFriendConfig)
	if err != nil {
		t.Fatal(err)
	}
	log.Infof("Uploaded new addfriend config")

	confs = <-bob2.Handler.(*chanHandler).newConfig
	if confs[0].Hash() != newAddFriendConfig.Hash() {
		t.Fatalf("received unexpected config: %s", debug.Pretty(confs))
	}
	confs = <-alice.Handler.(*chanHandler).newConfig
	if confs[0].Hash() != newAddFriendConfig.Hash() {
		t.Fatalf("received unexpected config: %s", debug.Pretty(confs))
	}

	_, err = bob2.SendFriendRequest(alice.Username, nil)
	if err != nil {
		t.Fatal(err)
	}
	<-bob2.Handler.(*chanHandler).sentFriendRequest
	log.Infof("Bob: sent friend request to Alice")

	friendRequest = <-alice.Handler.(*chanHandler).receivedFriendRequest
	log.Infof("Alice: got friend request from %s", friendRequest.Username)

	_, err = friendRequest.Approve()
	if err != nil {
		t.Fatal(err)
	}
	<-alice.Handler.(*chanHandler).sentFriendRequest
	<-alice.Handler.(*chanHandler).confirmedFriend

	friend = <-bob2.Handler.(*chanHandler).confirmedFriend
	log.Infof("Bob: confirmed friend")

	// Add more servers to the dialing mixchain.
	prevDialingConfig := u.CurrentConfig("Dialing")
	newDialingConfig := &config.SignedConfig{
		Version:        config.SignedConfigVersion,
		Created:        time.Now(),
		Expires:        time.Now().Add(24 * time.Hour),
		PrevConfigHash: prevDialingConfig.Hash(),

		Service: "Dialing",
		Inner: &config.DialingConfig{
			Version:     config.DialingConfigVersion,
			Coordinator: prevDialingConfig.Inner.(*config.DialingConfig).Coordinator,
			MixServers:  append(prevDialingConfig.Inner.(*config.DialingConfig).MixServers, newChain.Servers...),
			CDNServer:   prevDialingConfig.Inner.(*config.DialingConfig).CDNServer,
		},
	}
	err = u.ConfigClient.SetCurrentConfig(newDialingConfig)
	if err != nil {
		t.Fatal(err)
	}
	log.Infof("Uploaded new dialing config")

	confs = <-bob2.Handler.(*chanHandler).newConfig
	if confs[0].Hash() != newDialingConfig.Hash() {
		t.Fatalf("received unexpected config: %s", debug.Pretty(confs))
	}
	confs = <-alice.Handler.(*chanHandler).newConfig
	if confs[0].Hash() != newDialingConfig.Hash() {
		t.Fatalf("received unexpected config: %s", debug.Pretty(confs))
	}

	friend = alice.GetFriend(bob2.Username)
	friend.Call(2)
	outCall = <-alice.Handler.(*chanHandler).sentCall
	if outCall.Intent() != 2 {
		t.Fatalf("wrong intent: got %d, want %d", outCall.Intent(), 2)
	}
	log.Infof("Alice: calling Bob with intent 2")

	inCall = <-bob2.Handler.(*chanHandler).receivedCall
	if inCall.Intent != 2 {
		t.Fatalf("wrong intent: got %d, want %d", inCall.Intent, 2)
	}
	log.Infof("Bob: received call with intent 2")

	if !bytes.Equal(outCall.SessionKey()[:], inCall.SessionKey[:]) {
		t.Fatal("Alice and Bob agreed on different keys!")
	}
}

var logger = &log.Logger{
	Level:        log.InfoLevel,
	EntryHandler: alplog.OutputText(log.Stderr),
}

type universe struct {
	Dir string

	ConfigServer     *config.Server
	ConfigClient     *config.Client
	configHTTPServer *http.Server

	CDN      *mock.CDN
	Mixchain *mock.Mixchain
	PKGs     []*mock.PKG

	CDNKey        ed25519.PublicKey
	cdnServer     *cdn.Server
	cdnHTTPServer *http.Server

	CoordinatorAddress    string
	CoordinatorKey        ed25519.PublicKey
	dialingServer         *coordinator.Server
	addFriendServer       *coordinator.Server
	coordinatorHTTPServer *http.Server
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

	u.ConfigServer, err = config.CreateServer(filepath.Join(u.Dir, "config-server-state"))
	if err != nil {
		log.Panicf("config.CreateServer: %s", err)
	}
	configListener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Panic(err)
	}
	u.configHTTPServer = &http.Server{
		Handler: u.ConfigServer,
	}
	go func() {
		err := u.configHTTPServer.Serve(configListener)
		if err != http.ErrServerClosed {
			log.Fatalf("http.Serve: %s", err)
		}
	}()
	u.ConfigClient = &config.Client{
		ConfigServerURL: "http://" + configListener.Addr().String(),
	}

	coordinatorPublic, coordinatorPrivate, _ := ed25519.GenerateKey(rand.Reader)
	u.CoordinatorKey = coordinatorPublic
	coordinatorListener, err := edtls.Listen("tcp", "localhost:0", coordinatorPrivate)
	if err != nil {
		log.Panicf("edtls.Listen: %s", err)
	}
	u.CoordinatorAddress = coordinatorListener.Addr().String()

	u.CDN = mock.LaunchCDN(u.Dir, coordinatorPublic)

	u.Mixchain = mock.LaunchMixchain(3, coordinatorPublic)

	u.PKGs = make([]*mock.PKG, 3)
	for i := range u.PKGs {
		srv, err := mock.LaunchPKG(coordinatorPublic, func(username string, token string) error {
			return nil
		})
		if err != nil {
			log.Panicf("launching PKG: %s", err)
		}
		u.PKGs[i] = srv
	}

	addFriendConfig := &config.SignedConfig{
		Version: config.SignedConfigVersion,
		Created: time.Now(),
		Expires: time.Now().Add(24 * time.Hour),

		Service: "AddFriend",
		Inner: &config.AddFriendConfig{
			Version: config.AddFriendConfigVersion,
			Coordinator: config.CoordinatorConfig{
				Key:     u.CoordinatorKey,
				Address: u.CoordinatorAddress,
			},
			PKGServers: make([]pkg.PublicServerConfig, len(u.PKGs)),
			MixServers: u.Mixchain.Servers,
			CDNServer: config.CDNServerConfig{
				Key:     u.CDN.PublicKey,
				Address: u.CDN.Addr,
			},
		},
	}
	for i, pkgServer := range u.PKGs {
		addFriendConfig.Inner.(*config.AddFriendConfig).PKGServers[i] = pkgServer.PublicServerConfig
	}
	err = u.ConfigServer.SetCurrentConfig(addFriendConfig)
	if err != nil {
		log.Panicf("error setting current addfriend config: %s", err)
	}

	u.addFriendServer = &coordinator.Server{
		Service:    "AddFriend",
		PrivateKey: coordinatorPrivate,
		Log: logger.WithFields(log.Fields{
			"tag":     "coordinator",
			"service": "AddFriend",
		}),

		ConfigClient: u.ConfigClient,

		PKGWait:      1 * time.Second,
		MixWait:      1 * time.Second,
		RoundWait:    2 * time.Second,
		NumMailboxes: 1,

		PersistPath: filepath.Join(u.Dir, "addfriend-coordinator-state"),
	}
	if err := u.addFriendServer.Persist(); err != nil {
		log.Panicf("error persisting addfriend server: %s", err)
	}
	if err := u.addFriendServer.LoadPersistedState(); err != nil {
		log.Panicf("error loading persisted state: %s", err)
	}
	if err := u.addFriendServer.Run(); err != nil {
		log.Panicf("starting addfriend loop: %s", err)
	}

	dialingConfig := &config.SignedConfig{
		Version: config.SignedConfigVersion,
		Created: time.Now(),
		Expires: time.Now().Add(24 * time.Hour),

		Service: "Dialing",
		Inner: &config.DialingConfig{
			Version: config.DialingConfigVersion,
			Coordinator: config.CoordinatorConfig{
				Key:     u.CoordinatorKey,
				Address: u.CoordinatorAddress,
			},
			MixServers: u.Mixchain.Servers,
			CDNServer: config.CDNServerConfig{
				Key:     u.CDN.PublicKey,
				Address: u.CDN.Addr,
			},
		},
	}
	err = u.ConfigServer.SetCurrentConfig(dialingConfig)
	if err != nil {
		log.Panicf("error setting current dialing config: %s", err)
	}

	u.dialingServer = &coordinator.Server{
		Service:    "Dialing",
		PrivateKey: coordinatorPrivate,
		Log: logger.WithFields(log.Fields{
			"tag":     "coordinator",
			"service": "Dialing",
		}),

		ConfigClient: u.ConfigClient,

		MixWait:      1 * time.Second,
		RoundWait:    2 * time.Second,
		NumMailboxes: 1,

		PersistPath: filepath.Join(u.Dir, "dialing-coordinator-state"),
	}
	if err := u.dialingServer.Persist(); err != nil {
		log.Panicf("error persisting dialing server: %s", err)
	}
	if err := u.dialingServer.LoadPersistedState(); err != nil {
		log.Panicf("error loading persisted state: %s", err)
	}
	if err := u.dialingServer.Run(); err != nil {
		log.Panicf("starting dialing loop: %s", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/addfriend/", http.StripPrefix("/addfriend", u.addFriendServer))
	mux.Handle("/dialing/", http.StripPrefix("/dialing", u.dialingServer))
	u.coordinatorHTTPServer = &http.Server{
		Handler: mux,
	}
	go func() {
		err := u.coordinatorHTTPServer.Serve(coordinatorListener)
		if err != http.ErrServerClosed {
			log.Fatalf("http.Serve: %s", err)
		}
	}()

	return u
}

func (u *universe) CurrentConfig(service string) *config.SignedConfig {
	conf, err := u.ConfigClient.CurrentConfig(service)
	if err != nil {
		log.Panic(err)
	}
	return conf
}
