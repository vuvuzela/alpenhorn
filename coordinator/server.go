// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package coordinator implements the entry/coordinator server.
package coordinator

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/net/context"

	"vuvuzela.io/alpenhorn/edhttp"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/mixnet"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/alpenhorn/typesocket"
)

// Server is the coordinator (entry) server for the add-friend or dialing
// protocols. Currently, clients connect to the server using websockets, but
// this might change if we find that websockets don't work well with long
// add-friend rounds.
type Server struct {
	Service    string // "AddFriend" or "Dialing"
	PrivateKey ed25519.PrivateKey

	PKGWait      time.Duration
	MixWait      time.Duration
	RoundWait    time.Duration
	NumMailboxes uint32

	PersistPath string

	mu                sync.Mutex
	round             uint32
	onions            [][]byte
	closed            bool
	shutdown          chan struct{}
	latestMixRound    *MixRound
	latestPKGRound    *PKGRound
	allConfigs        map[string]*AlpenhornConfig // use sync.Map in 1.9
	currentConfigHash string

	hub *typesocket.Hub

	mixnetClient *mixnet.Client
	pkgClient    *pkg.CoordinatorClient
	cdnClient    *edhttp.Client

	// TODO we should keep old PKGSettings and old mailbox URLS around
	// in case clients request them.
}

var ErrServerClosed = errors.New("coordinator: server closed")

func (srv *Server) Run() error {
	if srv.Service != "AddFriend" && srv.Service != "Dialing" {
		return errors.New("unexpected service type: %q", srv.Service)
	}
	if srv.PersistPath == "" {
		return errors.New("no persist path specified")
	}
	if srv.currentConfigHash == "" {
		return errors.New("current config hash is empty")
	}

	mux := typesocket.NewMux(map[string]interface{}{
		"onion": srv.incomingOnion,
	})
	srv.hub = &typesocket.Hub{
		Mux: mux,
	}

	if srv.Service == "AddFriend" {
		srv.pkgClient = &pkg.CoordinatorClient{
			CoordinatorKey: srv.PrivateKey,
		}
	}

	srv.mixnetClient = &mixnet.Client{
		Key: srv.PrivateKey,
	}

	srv.cdnClient = &edhttp.Client{
		Key: srv.PrivateKey,
	}

	srv.mu.Lock()
	srv.onions = make([][]byte, 0, 128)
	srv.closed = false
	srv.shutdown = make(chan struct{})
	srv.mu.Unlock()

	go srv.loop()
	return nil
}

func (srv *Server) Close() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	// This could be better if we had Contexts everywhere,
	// but only tests should need to close the server.
	if !srv.closed {
		close(srv.shutdown)
		srv.closed = true
		return nil
	} else {
		return ErrServerClosed
	}
}

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/ws":
		srv.hub.ServeHTTP(w, r)
	case "/config":
		srv.getConfigsHandler(w, r)
	case "/newconfig":
		srv.newConfigHandler(w, r)
	}
}

type OnionMsg struct {
	Round uint32
	Onion []byte
}

type NewRound struct {
	Round      uint32
	ConfigHash string
}

type PKGRound struct {
	Round       uint32
	PKGSettings pkg.RoundSettings
}

type MixRound struct {
	MixSettings   mixnet.RoundSettings
	MixSignatures [][]byte
	EndTime       time.Time
}

type RoundError struct {
	Round uint32
	Err   string
}

type MailboxURL struct {
	Round        uint32
	URL          string
	NumMailboxes uint32
}

func (srv *Server) onConnect(c typesocket.Conn) error {
	srv.mu.Lock()
	mixRound := srv.latestMixRound
	pkgRound := srv.latestPKGRound
	srv.mu.Unlock()

	if mixRound != nil {
		err := c.Send("mix", mixRound)
		if err != nil {
			return err
		}
	}

	if pkgRound != nil {
		return c.Send("pkg", pkgRound)
	}

	return nil
}

func (srv *Server) incomingOnion(c typesocket.Conn, o OnionMsg) {
	srv.mu.Lock()
	round := srv.round
	if o.Round == round {
		srv.onions = append(srv.onions, o.Onion)
	}
	srv.mu.Unlock()
	if o.Round != round {
		log.Errorf("got onion for wrong round (want %d, got %d)", round, o.Round)
		c.Send("error", RoundError{
			Round: o.Round,
			Err:   fmt.Sprintf("wrong round (want %d)", round),
		})
	}
}

func (srv *Server) prepCDN(config *AlpenhornConfig, round uint32) error {
	lastMixer := config.MixServers[len(config.MixServers)-1]
	url := fmt.Sprintf("https://%s/newbucket?bucket=%s/%d&uploader=%s",
		config.CDNServer.Address,
		config.Service,
		round,
		base32.EncodeToString(lastMixer.Key),
	)
	resp, err := srv.cdnClient.Post(config.CDNServer.Key, url, "", nil)
	if err != nil {
		return errors.Wrap(err, "POST error")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := ioutil.ReadAll(resp.Body)
		return errors.New("unsuccessful status code: %s: %q", resp.Status, msg)
	}
	return nil
}

func (srv *Server) loop() {
	for {
		srv.mu.Lock()
		srv.round++
		round := srv.round
		logger := log.WithFields(log.Fields{"service": srv.Service, "round": round})

		configHash := srv.currentConfigHash
		config := srv.allConfigs[configHash]

		if err := srv.persistLocked(); err != nil {
			logger.Errorf("error persisting state: %s", err)
			srv.mu.Unlock()
			break
		}
		srv.mu.Unlock()

		logger.Info("starting new round")

		srv.hub.Broadcast("newround", NewRound{
			Round:      round,
			ConfigHash: configHash,
		})

		// TODO perhaps pkg.NewRound, mixnet.NewRound, hub.Broadcast, etc
		// should take a Context for better cancelation.

		if srv.Service == "AddFriend" {
			logger.Info("requesting PKG keys")
			pkgSettings, err := srv.pkgClient.NewRound(config.PKGServers, round)
			if err != nil {
				logger.WithFields(log.Fields{"call": "pkg.NewRound"}).Error(err)
				if !srv.sleep(10 * time.Second) {
					break
				}
				continue
			}

			pkgRound := &PKGRound{
				Round:       round,
				PKGSettings: pkgSettings,
			}
			srv.mu.Lock()
			srv.latestPKGRound = pkgRound
			srv.mu.Unlock()

			srv.hub.Broadcast("pkg", pkgRound)

			if !srv.sleep(srv.PKGWait) {
				break
			}
		}

		err := srv.prepCDN(config, round)
		if err != nil {
			log.Errorf("error preparing CDN for round: %s", err)
			break
		}

		mixSettings := mixnet.RoundSettings{
			Service:      srv.Service,
			Round:        round,
			NumMailboxes: srv.NumMailboxes,
		}
		mixSigs, err := srv.mixnetClient.NewRound(context.Background(), config.MixServers, &mixSettings)
		if err != nil {
			logger.WithFields(log.Fields{"call": "mixnet.NewRound"}).Error(err)
			if !srv.sleep(10 * time.Second) {
				break
			}
			continue
		}

		roundEnd := time.Now().Add(srv.MixWait)
		mixRound := &MixRound{
			MixSettings:   mixSettings,
			MixSignatures: mixSigs,
			EndTime:       roundEnd,
		}
		srv.mu.Lock()
		srv.latestMixRound = mixRound
		srv.mu.Unlock()

		logger.Info("announcing mixnet settings")
		srv.hub.Broadcast("mix", mixRound)

		if !srv.sleep(srv.MixWait) {
			break
		}

		logger.Info("running round")
		srv.mu.Lock()
		go srv.runRound(context.Background(), config.MixServers[0], round, srv.onions)
		srv.onions = make([][]byte, 0, len(srv.onions))
		srv.mu.Unlock()

		logger.Info("waiting for next round")
		if !srv.sleep(srv.RoundWait) {
			break
		}
	}

	log.WithFields(log.Fields{"service": srv.Service}).Info("shutting down")
}

func (srv *Server) sleep(d time.Duration) bool {
	timer := time.NewTimer(d)
	select {
	case <-srv.shutdown:
		timer.Stop()
		return false
	case <-timer.C:
		return true
	}
}

func (srv *Server) runRound(ctx context.Context, firstServer mixnet.PublicServerConfig, round uint32, onions [][]byte) {
	logger := log.WithFields(log.Fields{"service": srv.Service, "round": round})

	logger.WithFields(log.Fields{"onions": len(onions)}).Info("start RunRound")
	start := time.Now()
	url, err := srv.mixnetClient.RunRound(ctx, firstServer, srv.Service, round, onions)
	if err != nil {
		logger.WithFields(log.Fields{"call": "RunRound"}).Error(err)
		srv.hub.Broadcast("error", RoundError{Round: round, Err: "server error"})
		return
	}
	end := time.Now()
	logger.WithFields(log.Fields{"duration": end.Sub(start)}).Info("end RunRound")

	srv.hub.Broadcast("mailbox", MailboxURL{
		Round:        round,
		URL:          url,
		NumMailboxes: srv.NumMailboxes,
	})
}
