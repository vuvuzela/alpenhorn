// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package mock

import (
	"io/ioutil"
	"net/http"
	"os"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/crypto/rand"
)

type PKG struct {
	PKGServer *pkg.Server
	pkg.PublicServerConfig

	dbPath     string
	httpServer *http.Server
}

func (p *PKG) Close() error {
	err1 := p.httpServer.Close()
	err2 := p.PKGServer.Close()
	err3 := os.RemoveAll(p.dbPath)
	return firstError(err1, err2, err3)
}

func firstError(errors ...error) error {
	for _, err := range errors {
		if err != nil {
			return err
		}
	}
	return nil
}

func LaunchPKG(coordinatorKey ed25519.PublicKey, regTokenHandler pkg.RegTokenHandler) (*PKG, error) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	listener, err := edtls.Listen("tcp", "localhost:0", privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "edtls.Listen")
	}
	addr := listener.Addr().String()

	dbPath, err := ioutil.TempDir("", "alpenhorn_mock_pkg_")
	if err != nil {
		return nil, err
	}

	config := &pkg.Config{
		SigningKey: privateKey,
		DBPath:     dbPath,
		Logger: &log.Logger{
			Level:        log.ErrorLevel,
			EntryHandler: &log.OutputText{Out: log.Stderr},
		},
		CoordinatorKey:  coordinatorKey,
		RegTokenHandler: regTokenHandler,
	}
	pkgServer, err := pkg.NewServer(config)
	if err != nil {
		return nil, errors.Wrap(err, "pkg.NewServer")
	}
	httpServer := &http.Server{
		Handler: pkgServer,
	}
	httpServer.SetKeepAlivesEnabled(false)
	go func() {
		err := httpServer.Serve(listener)
		if err != http.ErrServerClosed {
			log.Fatalf("http.Serve: %s", err)
		}
	}()

	return &PKG{
		PKGServer: pkgServer,

		PublicServerConfig: pkg.PublicServerConfig{
			Key:     publicKey,
			Address: addr,
		},

		dbPath:     config.DBPath,
		httpServer: httpServer,
	}, nil
}
