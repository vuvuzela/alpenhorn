// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package coordinator implements the entry/coordinator server.
package coordinator

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"

	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/internal/ioutil2"
	"vuvuzela.io/alpenhorn/mixnet"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/alpenhorn/typesocket"
	"vuvuzela.io/alpenhorn/vrpc"
)

// Server is the coordinator (entry) server for the add-friend or dialing
// protocols. Currently, clients connect to the server using websockets, but
// this might change if we find that websockets don't work well with long
// add-friend rounds.
type Server struct {
	Service string // "AddFriend" or "Dialing"

	MixServers   []*vrpc.Client
	MixWait      time.Duration
	NumMailboxes uint32

	RoundWait time.Duration

	PKGServers []*vrpc.Client
	PKGWait    time.Duration

	PersistPath string

	mu             sync.Mutex
	round          uint32
	onions         [][]byte
	closed         bool
	shutdown       chan struct{}
	latestMixRound *MixRound
	latestPKGRound *PKGRound

	hub *typesocket.Hub

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

	round, err := loadPersistedState(srv.PersistPath)
	if err != nil {
		return err
	}
	srv.round = round + 1
	srv.onions = make([][]byte, 0, 128)
	srv.closed = false
	srv.shutdown = make(chan struct{})

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

// version is the current version number of the persisted state format.
const version byte = 0

func loadPersistedState(path string) (round uint32, err error) {
	data, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, persistState(path, 0)
	} else if err != nil {
		return 0, err
	}

	if len(data) < 5 {
		return 0, fmt.Errorf("short data: want %d bytes, got %d", 5, len(data))
	}

	ver := data[0]
	if ver != version {
		return 0, fmt.Errorf("unexpected version: want version %d, got %d", version, ver)
	}

	round = binary.BigEndian.Uint32(data[1:])
	return round, nil
}

func persistState(path string, round uint32) error {
	var data [5]byte
	data[0] = version
	binary.BigEndian.PutUint32(data[1:], round)
	return ioutil2.WriteFileAtomic(path, data[:], 0600)
}

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srv.hub.ServeHTTP(w, r)
}

type OnionMsg struct {
	Round uint32
	Onion []byte
}

type PKGRound struct {
	Round       uint32
	PKGSettings pkg.PKGSettings
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

func (srv *Server) loop() {
	round := srv.round

	for {
		logger := log.WithFields(log.Fields{"service": srv.Service, "round": round})

		if err := persistState(srv.PersistPath, round); err != nil {
			logger.Errorf("error persisting state: %s", err)
			break
		}

		logger.Info("starting new round")

		// TODO perhaps pkg.NewRound, mixnet.NewRound, hub.Broadcast, etc
		// should take a Context for better cancelation.

		if srv.Service == "AddFriend" {
			logger.Info("requesting PKG keys")
			pkgSettings, err := pkg.NewRound(srv.PKGServers, round)
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

		mixSettings := mixnet.RoundSettings{
			Round:        round,
			NumMailboxes: srv.NumMailboxes,
		}
		mixSigs, err := mixnet.NewRound(srv.Service, srv.MixServers, &mixSettings)
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
		go srv.runRound(round, srv.onions)

		round++
		srv.round = round
		srv.onions = make([][]byte, len(srv.onions))
		srv.mu.Unlock()

		logger.Info("waiting for next round")
		if !srv.sleep(srv.RoundWait) {
			break
		}
	}

	log.WithFields(log.Fields{"service": srv.Service, "round": round}).Info("shutting down")
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

func (srv *Server) runRound(round uint32, onions [][]byte) {
	logger := log.WithFields(log.Fields{"service": srv.Service, "round": round})

	logger.WithFields(log.Fields{"onions": len(onions)}).Info("start RunRound")
	start := time.Now()
	url, err := mixnet.RunRound(srv.Service, srv.MixServers[0], round, onions)
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
