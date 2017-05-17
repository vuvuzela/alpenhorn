// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package vrpc

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/rpc"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/edtls"
)

type Server struct {
	servers  map[[ed25519.PublicKeySize]byte]*rpc.Server
	listener net.Listener

	mu   sync.Mutex
	done chan struct{}
}

func (s *Server) ListenAndServe(addr string, myKey ed25519.PrivateKey) error {
	listener, err := edtls.Listen("tcp", addr, myKey)
	if err != nil {
		return err
	}
	return s.Serve(listener, myKey)
}

// Serve accepts incoming RPCs on the listener, which must be an edtls listener.
func (s *Server) Serve(listener net.Listener, myKey ed25519.PrivateKey) error {
	defer listener.Close()
	s.listener = listener

	for {
		rawConn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.getDoneChan():
				return ErrServerClosed
			default:
			}
			log.Errorf("vrpc.Serve: accept: %s", err.Error())
			return err
		}
		conn := rawConn.(*tls.Conn)

		if err := conn.Handshake(); err != nil {
			conn.Close()
			continue
		}
		state := conn.ConnectionState()
		if !state.HandshakeComplete {
			log.Errorf("vrpc.Serve: TLS handshake did not complete")
			continue
		}

		if len(state.PeerCertificates) == 0 {
			log.Errorf("vrpc.Serve: no TLS peer certificates")
			continue
		}
		clientCert := state.PeerCertificates[0]
		clientKey := edtls.GetSigningKey(clientCert)

		ok := edtls.Verify(clientKey, clientCert, time.Now())
		if !ok {
			log.Errorf("vrpc.Serve: edtls verification failed with key %q", base64.RawURLEncoding.EncodeToString(clientKey))
			continue
		}

		if s.servers == nil {
			continue
		}

		var key [ed25519.PublicKeySize]byte
		copy(key[:], clientKey)
		srv := s.servers[key]
		if srv != nil {
			go srv.ServeConn(conn)
		}
	}
}

func (s *Server) Register(allowedKey ed25519.PublicKey, name string, rcvr interface{}) error {
	if s.servers == nil {
		s.servers = make(map[[ed25519.PublicKeySize]byte]*rpc.Server)
	}
	var key [ed25519.PublicKeySize]byte
	copy(key[:], allowedKey)
	srv := s.servers[key]
	if srv == nil {
		srv = rpc.NewServer()
		s.servers[key] = srv
	}
	return srv.RegisterName(name, rcvr)
}

var ErrServerClosed = errors.New("vrpc: Server closed")

func (s *Server) getDoneChan() chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done == nil {
		s.done = make(chan struct{})
	}
	return s.done
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// This logic is based on net/http.(*Server).Close()
	if s.done == nil {
		s.done = make(chan struct{})
	}
	select {
	case <-s.done:
		// Already closed. Don't close again.
	default:
		close(s.done)
	}

	return s.listener.Close()
}
