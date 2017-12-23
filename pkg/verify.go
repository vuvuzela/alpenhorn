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
	if srv.sendVerificationEmail == nil {
		// Usernames do not need to be verified in FCFS mode.
		http.NotFound(w, req)
		return
	}

	body := http.MaxBytesReader(w, req.Body, 512)
	args := new(verifyArgs)
	err := json.NewDecoder(body).Decode(args)
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
	tx := srv.db.NewTransaction(true)
	defer tx.Discard()

	user, id, err := srv.getUser(tx, args.Username)
	if err != nil {
		return err
	}
	if user.Verified {
		return errorf(ErrAlreadyRegistered, "%q", args.Username)
	}

	tokenExpires := time.Unix(user.TokenExpires, 0)
	if !time.Now().Before(tokenExpires) {
		return errorf(ErrExpiredToken, "registration token expired")
	}
	if subtle.ConstantTimeCompare(args.Token, user.VerificationToken[:]) != 1 {
		return errorf(ErrInvalidToken, "%x", args.Token)
	}
	if !args.Verify(user.LoginKey) {
		return errorf(ErrInvalidSignature, "key=%x", user.LoginKey)
	}

	user.Verified = true
	user.VerificationToken = nil
	err = tx.Set(dbUserKey(id, registrationSuffix), user.Marshal())
	if err != nil {
		return errorf(ErrDatabaseError, "%s", err)
	}

	err = appendLog(tx, id, UserEvent{
		Time:     time.Now(),
		Type:     EventRegistered,
		LoginKey: user.LoginKey,
	})
	if err != nil {
		return err
	}

	err = tx.Commit(nil)
	if err != nil {
		return errorf(ErrDatabaseError, "%s", err)
	}
	return nil
}
