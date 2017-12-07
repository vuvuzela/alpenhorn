// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pkg

import (
	"bytes"
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/ed25519"

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
	if !user.Verified {
		return nil, errorf(ErrNotVerified, "%q", args.Username)
	}

	if !ed25519.Verify(user.LoginKey, args.msg(), args.Signature) {
		return nil, errorf(ErrInvalidSignature, "")
	}

	return &statusReply{}, nil
}
