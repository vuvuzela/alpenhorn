// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pkg

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/dgraph-io/badger"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/bloom"
	"vuvuzela.io/alpenhorn/log"
)

type statusArgs struct {
	Username         string
	Message          [32]byte
	ServerSigningKey ed25519.PublicKey `json:"-"`

	Signature []byte
}

func (a *statusArgs) msg() []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("StatusArgs")
	buf.Write(a.ServerSigningKey)
	id := ValidUsernameToIdentity(a.Username)
	buf.Write(id[:])
	buf.Write(a.Message[:])
	return buf.Bytes()
}

type statusReply struct {
}

func (srv *Server) statusHandler(w http.ResponseWriter, req *http.Request) {
	body := http.MaxBytesReader(w, req.Body, 512)
	args := new(statusArgs)
	err := json.NewDecoder(body).Decode(args)
	if err != nil {
		httpError(w, errorf(ErrBadRequestJSON, "%s", err))
		return
	}
	args.ServerSigningKey = srv.publicKey

	reply, err := srv.checkStatus(args)
	if err != nil {
		if isInternalError(err) {
			srv.log.WithFields(log.Fields{
				"username": args.Username,
				"code":     errorCode(err).String(),
			}).Errorf("Status failed: %s", err)
		}
		httpError(w, err)
		return
	}

	bs, err := json.Marshal(reply)
	if err != nil {
		panic(err)
	}
	w.Write(bs)
}

func (srv *Server) checkStatus(args *statusArgs) (*statusReply, error) {
	user, _, err := srv.getUser(nil, args.Username)
	if err != nil {
		return nil, err
	}

	if !ed25519.Verify(user.LoginKey, args.msg(), args.Signature) {
		return nil, errorf(ErrInvalidSignature, "")
	}

	return &statusReply{}, nil
}

func (srv *Server) RegisteredUsernames() ([]*[64]byte, error) {
	users := make([]*[64]byte, 0, 32)
	err := srv.db.View(func(tx *badger.Txn) error {
		opt := badger.DefaultIteratorOptions
		it := tx.NewIterator(opt)
		for it.Seek(dbUserPrefix); it.ValidForPrefix(dbUserPrefix); it.Next() {
			key := it.Item().Key()
			if !bytes.HasSuffix(key, registrationSuffix) {
				continue
			}
			userID := bytes.TrimSuffix(bytes.TrimPrefix(key, dbUserPrefix), registrationSuffix)
			clone := new([64]byte)
			copy(clone[:], userID)
			users = append(users, clone)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (srv *Server) userFilterHandler(w http.ResponseWriter, req *http.Request) {
	// TODO add some authentication
	usernames, err := srv.RegisteredUsernames()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Leave some room in the bloom filter so the registrar can add its own usernames.
	f := bloom.New(bloom.Optimal(len(usernames)+1000, 0.0001))
	for _, username := range usernames {
		f.Set(username[:])
	}
	data, err := json.Marshal(f)
	if err != nil {
		panic(err)
	}
	w.Write(data)
}
