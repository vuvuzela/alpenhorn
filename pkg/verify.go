// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pkg

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"time"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/log"
)

type verifyArgs struct {
	Username  string
	Token     []byte
	Signature []byte
}

func (a *verifyArgs) Sign(key ed25519.PrivateKey) {
	a.Signature = ed25519.Sign(key, a.msg())
}

func (a *verifyArgs) Verify(key ed25519.PublicKey) bool {
	return ed25519.Verify(key, a.msg(), a.Signature)
}

func (a *verifyArgs) msg() []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("VerifyArgs")
	id := ValidUsernameToIdentity(a.Username)
	buf.Write(id[:])
	buf.Write(a.Token)
	return buf.Bytes()
}

func (srv *Server) verifyHandler(w http.ResponseWriter, req *http.Request) {
	args := new(verifyArgs)
	err := json.NewDecoder(req.Body).Decode(args)
	if err != nil {
		httpError(w, errorf(ErrBadRequestJSON, "%s", err))
		return
	}

	err = srv.verify(args)
	if err != nil {
		if isInternalError(err) {
			srv.log.WithFields(log.Fields{
				"username": args.Username,
				"code":     errorCode(err).String(),
			}).Errorf("Verify failed: %s", err)
		}
		httpError(w, err)
		return
	}

	w.Write([]byte("\"OK\""))
}

func (srv *Server) verify(args *verifyArgs) error {
	if err := ValidateUsername(args.Username); err != nil {
		return errorf(ErrInvalidUsername, "%s", err)
	}

	tx, err := srv.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	user, err := srv.getUser(tx, args.Username)
	if err != nil {
		return err
	}
	if user == nil {
		return errorf(ErrNotRegistered, "%q", args.Username)
	}
	if user.Status != statusPending {
		return errorf(ErrAlreadyRegistered, "%q", args.Username)
	}

	if !time.Now().Before(*user.TokenExpires) {
		return errorf(ErrExpiredToken, "expired %s", *user.TokenExpires)
	}
	if subtle.ConstantTimeCompare(args.Token, user.Token) != 1 {
		return errorf(ErrInvalidToken, "%x", args.Token)
	}
	if !args.Verify(user.Key) {
		return errorf(ErrInvalidSignature, "key=%x", user.Key)
	}

	_, err = tx.Exec(
		"UPDATE users SET status=$1, token=null, tokenExpires=null WHERE username=$2",
		statusVerified, args.Username,
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}
