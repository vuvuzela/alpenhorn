// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pkg

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/dgraph-io/badger"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/log"
)

func BenchmarkRegister(b *testing.B) {
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	dbPath, err := ioutil.TempDir("", "alpenhorn_pkg_db_")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(dbPath)

	conf := &Config{
		DBPath: dbPath,
		Logger: &log.Logger{
			Level:        log.ErrorLevel,
			EntryHandler: &log.OutputText{Out: log.Stderr},
		},
		SigningKey: serverPriv,

		RegTokenHandler: func(username string, token string, tx *badger.Txn) error {
			return nil
		},
	}

	srv, err := NewServer(conf)
	if err != nil {
		b.Fatal(err)
	}
	defer srv.Close()

	userPub, _, _ := ed25519.GenerateKey(rand.Reader)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		args := &registerArgs{
			Username: fmt.Sprintf("%dbenchmark@example.com", i),
			LoginKey: userPub,
		}
		err = srv.register(args)
		if err != nil {
			b.Fatal(err)
		}
	}
}
