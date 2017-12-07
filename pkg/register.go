// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pkg

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"github.com/dgraph-io/badger"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/log"
)

type registerArgs struct {
	Username string

	// LoginKey is how clients authenticate to the PKG server.
	LoginKey ed25519.PublicKey
}

func (srv *Server) registerHandler(w http.ResponseWriter, req *http.Request) {
	body := http.MaxBytesReader(w, req.Body, 256)
	args := new(registerArgs)
	err := json.NewDecoder(body).Decode(args)
	if err != nil {
		httpError(w, errorf(ErrBadRequestJSON, "%s", err))
		return
	}

	logger := srv.log.WithFields(log.Fields{"username": args.Username, "loginKey": base32.EncodeToString(args.LoginKey)})
	err = srv.register(args.Username, args.LoginKey)
	if err != nil {
		logger = logger.WithFields(log.Fields{"code": errorCode(err).String()})
		if isInternalError(err) {
			logger.Errorf("Registration failed: %s", err)
		} else {
			// Avoid polluting stderr for user-caused errors.
			logger.Infof("Registration failed: %s", err)
		}
		httpError(w, err)
		return
	}
	logger.Info("Registration successful")

	// reply with valid json
	w.Write([]byte("\"OK\""))
}

func (srv *Server) register(username string, loginKey ed25519.PublicKey) error {
	if err := ValidateUsername(username); err != nil {
		return errorf(ErrInvalidUsername, "%s", err)
	}
	if len(loginKey) != ed25519.PublicKeySize {
		return errorf(ErrInvalidLoginKey, "got %d bytes, want %d bytes", len(loginKey), ed25519.PublicKeySize)
	}

	if srv.sendVerificationEmail == nil {
		return srv.registerFCFS(username, loginKey)
	}

	return srv.registerWithVerification(username, loginKey)
}

func (srv *Server) registerFCFS(username string, loginKey ed25519.PublicKey) error {
	id := ValidUsernameToIdentity(username)

	tx := srv.db.NewTransaction(true)
	defer tx.Discard()

	key := dbUserKey(id, registrationSuffix)
	_, err := tx.Get(key)
	if err != nil && err != badger.ErrKeyNotFound {
		return errorf(ErrDatabaseError, "%s", err)
	}
	if err == nil {
		return errorf(ErrAlreadyRegistered, "%q", username)
	}

	newUser := userState{
		Verified: true,
		LoginKey: loginKey,
	}

	err = tx.Set(key, newUser.Marshal())
	if err != nil {
		return errorf(ErrDatabaseError, "%s", err)
	}

	err = tx.Commit(nil)
	if err != nil {
		return errorf(ErrDatabaseError, "%s", err)
	}

	return nil
}

func (srv *Server) registerWithVerification(username string, loginKey ed25519.PublicKey) error {
	id := ValidUsernameToIdentity(username)

	tx := srv.db.NewTransaction(true)
	defer tx.Discard()

	key := dbUserKey(id, registrationSuffix)
	item, err := tx.Get(key)
	if err != nil && err != badger.ErrKeyNotFound {
		return errorf(ErrDatabaseError, "%s", err)
	} else if err == nil {
		// User already exists; check if verified or expired.
		data, err := item.Value()
		if err != nil {
			return errorf(ErrDatabaseError, "%s", err)
		}
		var user userState
		err = user.Unmarshal(data)
		if err != nil {
			return errorf(ErrDatabaseError, "invalid user state: %s", err)
		}
		if user.Verified {
			return errorf(ErrAlreadyRegistered, "%q", username)
		}
		if time.Now().Before(time.Unix(user.TokenExpires, 0)) {
			return errorf(ErrRegistrationInProgress, "try again later")
		}
	}

	newUser := userState{
		Verified:          false,
		LoginKey:          loginKey,
		VerificationToken: newVerificationToken(),
		TokenExpires:      time.Now().Add(24 * time.Hour).Unix(),
	}

	err = tx.Set(key, newUser.Marshal())
	if err != nil {
		return errorf(ErrDatabaseError, "%s", err)
	}
	// Write changes to disk before sending the email.
	if err := tx.Commit(nil); err != nil {
		return errorf(ErrDatabaseError, "%s", err)
	}

	err = srv.sendVerificationEmail(username, newUser.VerificationToken[:])
	if err != nil {
		return errorf(ErrSendingEmail, "%s", err)
	}

	return nil
}

func newVerificationToken() *[32]byte {
	token := new([32]byte)
	_, err := rand.Read(token[:])
	if err != nil {
		panic(err)
	}
	return token
}
