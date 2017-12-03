// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package mock

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/internal/pg"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/crypto/rand"
)

type PKG struct {
	pkg.PublicServerConfig

	dbName     string
	pkgServer  *pkg.Server
	httpServer *http.Server

	badgerDBPath string
}

func (p *PKG) Close() error {
	err1 := p.httpServer.Close()
	err2 := p.pkgServer.Close()
	err3 := os.RemoveAll(p.badgerDBPath)
	pg.Dropdb(p.dbName)
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

func LaunchPKG(coordinatorKey ed25519.PublicKey, sendMail pkg.SendMailHandler) (*PKG, error) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	listener, err := edtls.Listen("tcp", "localhost:0", privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "edtls.Listen")
	}
	addr := listener.Addr().String()

	id := make([]byte, 8)
	rand.Read(id)
	dbName := fmt.Sprintf("alpenhorn_mock_pkg_%x", id)
	pg.Createdb(dbName)

	badgerDir, err := ioutil.TempDir("", "alpenhorn_pkg_badger_")
	if err != nil {
		return nil, err
	}

	config := &pkg.Config{
		SigningKey:   privateKey,
		DBName:       dbName,
		BadgerDBPath: badgerDir,
		Logger: &log.Logger{
			Level:        log.ErrorLevel,
			EntryHandler: log.OutputText(log.Stderr),
		},
		CoordinatorKey: coordinatorKey,

		SendVerificationEmail: sendMail,
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
		PublicServerConfig: pkg.PublicServerConfig{
			Key:     publicKey,
			Address: addr,
		},

		dbName:     dbName,
		pkgServer:  pkgServer,
		httpServer: httpServer,

		badgerDBPath: badgerDir,
	}, nil
}
