// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package coordinator implements the entry/coordinator server.
package coordinator

import (
	"crypto/ed25519"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/net/context"

	"vuvuzela.io/alpenhorn/addfriend"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/dialing"
	"vuvuzela.io/alpenhorn/edhttp"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/alpenhorn/typesocket"
	"vuvuzela.io/vuvuzela/mixnet"
)

// Server is the coordinator (entry) server for the add-friend or dialing
// protocols. Currently, clients connect to the server using websockets, but
// this might change if we find that websockets don't work well with long
// add-friend rounds.
type Server struct {
	Service    string // "AddFriend" or "Dialing"
	PrivateKey ed25519.PrivateKey
	Log        *log.Logger

	ConfigClient *config.Client

	PKGWait      time.Duration
	MixWait      time.Duration
	RoundWait    time.Duration
	NumMailboxes uint32

	PersistPath string

	mu             sync.Mutex
	round          uint32
	onions         [][]byte
	closed         bool
	shutdown       chan struct{}
	latestMixRound *MixRound
	latestPKGRound *PKGRound

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
	switch {
	case strings.HasPrefix(r.URL.Path, "/ws"):
		srv.hub.ServeHTTP(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
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

func (srv *Server) prepCDN(cdnServer config.CDNServerConfig, lastMixer mixnet.PublicServerConfig, service string, round uint32) error {
	url := fmt.Sprintf("https://%s/newbucket?bucket=%s/%d&uploader=%s",
		cdnServer.Address,
		service,
		round,
		base32.EncodeToString(lastMixer.Key),
	)
	resp, err := srv.cdnClient.Post(cdnServer.Key, url, "", nil)
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
		currentConfig, err := srv.ConfigClient.CurrentConfig(srv.Service)
		if err != nil {
			log.Errorf("failed to fetch current config: %s", err)
			if !srv.sleep(10 * time.Second) {
				break
			}
			continue
		}
		configHash := currentConfig.Hash()

		var rawServiceData []byte
		var mixServers []mixnet.PublicServerConfig
		var cdnServer config.CDNServerConfig
		var pkgServers []pkg.PublicServerConfig
		switch srv.Service {
		case "AddFriend":
			conf := currentConfig.Inner.(*config.AddFriendConfig)
			mixServers = conf.MixServers
			cdnServer = conf.CDNServer
			pkgServers = conf.PKGServers
			rawServiceData = addfriend.ServiceData{
				CDNKey:       cdnServer.Key,
				CDNAddress:   cdnServer.Address,
				NumMailboxes: srv.NumMailboxes,
			}.Marshal()
		case "Dialing":
			conf := currentConfig.Inner.(*config.DialingConfig)
			mixServers = conf.MixServers
			cdnServer = conf.CDNServer
			rawServiceData = dialing.ServiceData{
				CDNKey:       cdnServer.Key,
				CDNAddress:   cdnServer.Address,
				NumMailboxes: srv.NumMailboxes,
			}.Marshal()
		default:
			log.Panicf("invalid service type: %q", srv.Service)
		}

		srv.mu.Lock()
		srv.round++
		round := srv.round

		logger := srv.Log.WithFields(log.Fields{"round": round, "config": configHash})

		if err := srv.persistLocked(); err != nil {
			logger.Errorf("error persisting state: %s", err)
			srv.mu.Unlock()
			break
		}
		srv.mu.Unlock()

		logger.Info("Starting new round")

		srv.hub.Broadcast("newround", NewRound{
			Round:      round,
			ConfigHash: configHash,
		})

		time.Sleep(500 * time.Millisecond)

		// TODO perhaps pkg.NewRound, mixnet.NewRound, hub.Broadcast, etc
		// should take a Context for better cancelation.

		if srv.Service == "AddFriend" {
			logger.WithFields(log.Fields{"numPKG": len(pkgServers)}).Info("Requesting PKG keys")
			pkgSettings, err := srv.pkgClient.NewRound(pkgServers, round)
			if err != nil {
				logger.WithFields(log.Fields{"call": "pkg.NewRound"}).Errorf("pkg.NewRound failed: %s", err)
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

		err = srv.prepCDN(cdnServer, mixServers[len(mixServers)-1], srv.Service, round)
		if err != nil {
			logger.Errorf("error preparing CDN for round: %s", err)
			break
		}

		mixSettings := mixnet.RoundSettings{
			Service:        srv.Service,
			Round:          round,
			RawServiceData: rawServiceData,
		}
		mixSigs, err := srv.mixnetClient.NewRound(context.Background(), mixServers, &mixSettings)
		if err != nil {
			logger.WithFields(log.Fields{"call": "mixnet.NewRound"}).Errorf("mixnet.NewRound failed: %s", err)
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

		logger.WithFields(log.Fields{"wait": srv.MixWait}).Info("Announcing mixnet settings")
		srv.hub.Broadcast("mix", mixRound)

		if !srv.sleep(srv.MixWait) {
			break
		}

		srv.mu.Lock()
		go srv.runRound(context.Background(), mixServers[0], round, srv.onions)
		srv.onions = make([][]byte, 0, len(srv.onions))
		srv.mu.Unlock()

		if !srv.sleep(srv.RoundWait) {
			break
		}
	}

	srv.Log.Error("Shutting down")
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
	srv.Log.WithFields(log.Fields{
		"round":  round,
		"onions": len(onions),
	}).Info("Start mixing")
	start := time.Now()

	url, err := srv.mixnetClient.RunRoundUnidirectional(ctx, firstServer, srv.Service, round, onions)
	if err != nil {
		srv.Log.WithFields(log.Fields{
			"round": round,
			"call":  "mixnet.RunRound",
		}).Error(err)
		srv.hub.Broadcast("error", RoundError{Round: round, Err: "server error"})
		return
	}

	end := time.Now()
	srv.Log.WithFields(log.Fields{
		"round":    round,
		"onions":   len(onions),
		"duration": end.Sub(start),
	}).Info("End mixing")

	srv.hub.Broadcast("mailbox", MailboxURL{
		Round:        round,
		URL:          url,
		NumMailboxes: srv.NumMailboxes,
	})
}
