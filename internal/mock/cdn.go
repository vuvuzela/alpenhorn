// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package mock

import (
	"crypto/rand"
	"io/ioutil"
	"log"
	"net/http"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/cdn"
	"vuvuzela.io/alpenhorn/edtls"
)

type CDN struct {
	PublicKey  ed25519.PublicKey
	Addr       string
	Path       string
	CDNServer  *cdn.Server
	HTTPServer *http.Server
}

func LaunchCDN(dir string, coordinatorKey ed25519.PublicKey) *CDN {
	cdnPublic, cdnPrivate, _ := ed25519.GenerateKey(rand.Reader)

	cdnListener, err := edtls.Listen("tcp", "localhost:0", cdnPrivate)
	if err != nil {
		log.Panicf("edtls.Listen: %s", err)
	}
	cdnAddr := cdnListener.Addr().String()

	file, err := ioutil.TempFile(dir, "alpenhorn_mock_cdn_")
	if err != nil {
		log.Fatal(err)
	}
	file.Close()
	cdnPath := file.Name()

	cdnServer, err := cdn.New(cdnPath, coordinatorKey)
	if err != nil {
		log.Panicf("cdn.New: %s", err)
	}

	cdnHTTPServer := &http.Server{
		Handler: cdnServer,
	}
	go func() {
		err := cdnHTTPServer.Serve(cdnListener)
		if err != http.ErrServerClosed {
			log.Fatalf("http.Serve: %s", err)
		}
	}()

	return &CDN{
		PublicKey:  cdnPublic,
		Addr:       cdnAddr,
		Path:       cdnPath,
		CDNServer:  cdnServer,
		HTTPServer: cdnHTTPServer,
	}
}
