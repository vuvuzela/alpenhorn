// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pkg

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"github.com/dgraph-io/badger"

	"vuvuzela.io/alpenhorn/log"
)

type registerArgs struct {
	Username string

	// LoginKey is how clients authenticate to the PKG server.
	LoginKey ed25519.PublicKey

	// RegistrationToken can be used to authenticate registrations.
	RegistrationToken string
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
	err = srv.register(args)
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

func (srv *Server) register(args *registerArgs) error {
	id, err := UsernameToIdentity(args.Username)
	if err != nil {
		return errorf(ErrInvalidUsername, "%s", err)
	}
	if len(args.LoginKey) != ed25519.PublicKeySize {
		return errorf(ErrInvalidLoginKey, "got %d bytes, want %d bytes", len(args.LoginKey), ed25519.PublicKeySize)
	}

	err = srv.regTokenHandler(args.Username, args.RegistrationToken)
	if err != nil {
		return err
	}

	tx := srv.db.NewTransaction(true)
	defer tx.Discard()

	key := dbUserKey(id, registrationSuffix)
	_, err = tx.Get(key)
	if err != nil && err != badger.ErrKeyNotFound {
		return errorf(ErrDatabaseError, "%s", err)
	}
	if err == nil {
		return errorf(ErrAlreadyRegistered, "%q", args.Username)
	}

	newUser := userState{
		LoginKey: args.LoginKey,
	}

	err = tx.Set(key, newUser.Marshal())
	if err != nil {
		return errorf(ErrDatabaseError, "%s", err)
	}

	err = appendLog(tx, id, UserEvent{
		Time:     time.Now(),
		Type:     EventRegistered,
		LoginKey: args.LoginKey,
	})
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return errorf(ErrDatabaseError, "%s", err)
	}

	return nil
}

func ExternalVerifier(verifyURL string) RegTokenHandler {
	return func(username string, token string) error {
		vals := url.Values{
			"username": []string{username},
			"token":    []string{token},
		}
		resp, err := http.PostForm(verifyURL, vals)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		return errorf(ErrInvalidToken, "")
	}
}
