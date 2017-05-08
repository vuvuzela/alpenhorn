// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package cdn simulates a basic CDN server.
package cdn

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/edtls"
)

type Server struct {
	db        *bolt.DB
	uploadKey ed25519.PublicKey
}

// how long a key is stored before it is deleted
var defaultTTL = 24 * time.Hour

func New(dbPath string, uploadKey ed25519.PublicKey) (*Server, error) {
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("Expires"))
		return err
	})
	if err != nil {
		return nil, err
	}

	srv := &Server{
		db:        db,
		uploadKey: uploadKey,
	}
	go srv.deleteExpiredLoop()

	return srv, nil
}

func (srv *Server) Close() error {
	return srv.db.Close()
}

func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/get") {
		srv.get(w, r)
	} else if strings.HasPrefix(r.URL.Path, "/put") {
		srv.put(w, r)
	} else {
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func parseURL(u *url.URL) (bucket []byte, prefix []byte, ok bool) {
	bucket = []byte(u.Query().Get("bucket"))
	prefix = []byte(u.Query().Get("prefix"))
	ok = len(bucket) > 0 && len(prefix) > 0
	ok = ok && !bytes.ContainsAny(bucket, ":") && !bytes.ContainsAny(prefix, ":")
	return
}

func join(prefix, key []byte) []byte {
	r := make([]byte, 0, len(prefix)+1+len(key))
	r = append(append(append(r, prefix...), ':'), key...)
	return r
}

func (srv *Server) put(w http.ResponseWriter, req *http.Request) {
	if len(req.TLS.PeerCertificates) == 0 {
		http.Error(w, "expecting peer tls certificate", http.StatusBadRequest)
		return
	}
	ok := edtls.Verify(srv.uploadKey, req.TLS.PeerCertificates[0], time.Now())
	if !ok {
		http.Error(w, "no permission to upload", http.StatusUnauthorized)
		return
	}

	bucket, prefix, ok := parseURL(req.URL)
	if !ok {
		http.Error(w, "invalid bucket or prefix", http.StatusBadRequest)
		return
	}

	vals := make(map[string][]byte)
	err := gob.NewDecoder(req.Body).Decode(&vals)
	if err != nil {
		http.Error(w, fmt.Sprintf("gob decoding error: %s", err), http.StatusBadRequest)
		return
	}

	err = srv.db.Update(func(tx *bolt.Tx) error {
		eb := tx.Bucket([]byte("Expires"))

		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}

		expires := time.Now().Add(defaultTTL).Format(time.RFC3339)
		err = eb.Put([]byte(expires), join(bucket, prefix))
		if err != nil {
			return err
		}

		for k, v := range vals {
			err := b.Put(join(prefix, []byte(k)), v)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("internal DB error: %s", err), http.StatusInternalServerError)
		return
	}
	w.Write([]byte("OK"))
}

func (srv *Server) get(w http.ResponseWriter, req *http.Request) {
	bucket, prefix, ok := parseURL(req.URL)
	if !ok {
		http.Error(w, "invalid bucket or prefix", http.StatusBadRequest)
		return
	}
	key := req.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "unspecified key", http.StatusBadRequest)
		return
	}

	var val []byte
	srv.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}

		v := b.Get(join(prefix, []byte(key)))
		if v != nil {
			val = make([]byte, len(v))
			copy(val, v)
		}
		return nil
	})

	if val == nil {
		http.Error(w, fmt.Sprintf("key not found: %s:%s:%s", bucket, prefix, key), http.StatusNotFound)
		return
	}
	w.Write(val)
}

var deleteExpiredTickRate = 6 * time.Hour

func (srv *Server) deleteExpiredLoop() {
	c := time.Tick(deleteExpiredTickRate)
	for _ = range c {
		err := srv.deleteExpired()
		if err != nil {
			log.Printf("failed to delete expired keys: %s", err)
		}
	}
}

func (srv *Server) deleteExpired() error {
	err := srv.db.Update(func(tx *bolt.Tx) error {
		buckets := make(map[string][][]byte)

		ec := tx.Bucket([]byte("Expires")).Cursor()
		max := []byte(time.Now().Format(time.RFC3339))
		for k, v := ec.First(); k != nil && bytes.Compare(k, max) <= 0; k, v = ec.Next() {
			i := bytes.IndexByte(v, ':')
			b := string(v[:i])
			prefix := v[i+1:]
			buckets[b] = append(buckets[b], prefix)
		}

		for bucket, prefixes := range buckets {
			b := tx.Bucket([]byte(bucket))
			if b == nil {
				continue
			}
			c := b.Cursor()
			for _, prefix := range prefixes {
				for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
					err := b.Delete(k)
					if err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
	return err
}
