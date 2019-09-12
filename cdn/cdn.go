// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package cdn simulates a basic CDN server.
package cdn

import (
	"bytes"
	"crypto/ed25519"
	"encoding/gob"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/boltdb/bolt"
	"github.com/davidlazar/go-crypto/encoding/base32"
)

type Server struct {
	db *bolt.DB

	mu             sync.Mutex
	coordinatorKey ed25519.PublicKey
	// Map from CDN bucket ("addfriend/1234") to key allowed to upload.
	uploaders map[string]ed25519.PublicKey
}

// how long a key is stored before it is deleted
var defaultTTL = 24 * time.Hour

func New(dbPath string, coordinatorKey ed25519.PublicKey) (*Server, error) {
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
		db:             db,
		coordinatorKey: coordinatorKey,
		uploaders:      make(map[string]ed25519.PublicKey),
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
	} else if strings.HasPrefix(r.URL.Path, "/newbucket") {
		srv.newBucket(w, r)
	} else {
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func parseURL(u *url.URL) (cdnBucket, boltBucket, prefix string, err error) {
	b := u.Query().Get("bucket")
	parts := strings.Split(b, "/")
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		boltBucket, prefix = parts[0], parts[1]
		cdnBucket = boltBucket + "/" + prefix
	} else {
		err = fmt.Errorf("bad bucket name: %q", b)
	}
	return
}

func join(prefix, key []byte) []byte {
	r := make([]byte, 0, len(prefix)+1+len(key))
	r = append(append(append(r, prefix...), ':'), key...)
	return r
}

func (srv *Server) NewBucket(bucket string, uploader ed25519.PublicKey) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	_, ok := srv.uploaders[bucket]
	if ok {
		return fmt.Errorf("bucket already exists: %q", bucket)
	}
	srv.uploaders[bucket] = uploader
	return nil
}

func (srv *Server) newBucket(w http.ResponseWriter, req *http.Request) {
	if len(req.TLS.PeerCertificates) == 0 {
		http.Error(w, "expecting peer tls certificate", http.StatusBadRequest)
		return
	}
	cert := req.TLS.PeerCertificates[0]
	peerKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		http.Error(w, "expecting ed25519 certificate", http.StatusUnauthorized)
		return
	}
	if !bytes.Equal(peerKey, srv.coordinatorKey) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	cdnBucket, _, _, err := parseURL(req.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	encodedKey := req.URL.Query().Get("uploader")
	keyBytes, err := base32.DecodeString(encodedKey)
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		http.Error(w, fmt.Sprintf("bad uploader key: %q", encodedKey), http.StatusBadRequest)
		return
	}
	uploaderKey := ed25519.PublicKey(keyBytes)

	srv.mu.Lock()
	if _, ok := srv.uploaders[cdnBucket]; ok {
		srv.mu.Unlock()
		http.Error(w, fmt.Sprintf("bucket already exists: %q", cdnBucket), http.StatusBadRequest)
		return
	}
	srv.uploaders[cdnBucket] = uploaderKey
	srv.mu.Unlock()

	w.Write([]byte("OK\n"))
}

func (srv *Server) put(w http.ResponseWriter, req *http.Request) {
	if len(req.TLS.PeerCertificates) == 0 {
		http.Error(w, "expecting peer tls certificate", http.StatusBadRequest)
		return
	}
	cert := req.TLS.PeerCertificates[0]
	peerKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		http.Error(w, "expecting ed25519 certificate", http.StatusUnauthorized)
		return
	}

	cdnBucket, boltBucket, prefix, err := parseURL(req.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	srv.mu.Lock()
	expectedKey, ok := srv.uploaders[cdnBucket]
	srv.mu.Unlock()
	if !ok {
		http.Error(w, fmt.Sprintf("bucket not found: %s", cdnBucket), http.StatusBadRequest)
		return
	}
	if !bytes.Equal(peerKey, expectedKey) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	vals := make(map[string][]byte)
	err = gob.NewDecoder(req.Body).Decode(&vals)
	if err != nil {
		http.Error(w, fmt.Sprintf("gob decoding error: %s", err), http.StatusBadRequest)
		return
	}

	err = srv.db.Update(func(tx *bolt.Tx) error {
		eb := tx.Bucket([]byte("Expires"))

		b, err := tx.CreateBucketIfNotExists([]byte(boltBucket))
		if err != nil {
			return err
		}

		expires := time.Now().Add(defaultTTL).Format(time.RFC3339)
		err = eb.Put([]byte(expires), []byte(cdnBucket))
		if err != nil {
			return err
		}

		for k, v := range vals {
			err := b.Put([]byte(prefix+"/"+k), v)
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
	w.Write([]byte("OK\n"))
}

func (srv *Server) get(w http.ResponseWriter, req *http.Request) {
	cdnBucket, boltBucket, prefix, err := parseURL(req.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	key := req.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "unspecified key", http.StatusBadRequest)
		return
	}

	var val []byte
	srv.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(boltBucket))
		if b == nil {
			return nil
		}

		v := b.Get([]byte(prefix + "/" + key))
		if v != nil {
			val = make([]byte, len(v))
			copy(val, v)
		}
		return nil
	})

	if val == nil {
		http.Error(w, fmt.Sprintf("key not found: %s/%s", cdnBucket, key), http.StatusNotFound)
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
			i := bytes.IndexByte(v, '/')
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
