// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pkg

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"github.com/dgraph-io/badger"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/log"
)

type preregisterArgs struct {
	Username string
	PKGIndex int
	NumPKGs  int
}

func (srv *Server) preregisterHandler(w http.ResponseWriter, req *http.Request) {
	if !srv.authorized(srv.registrarKey, w, req) {
		return
	}

	body := http.MaxBytesReader(w, req.Body, 256)
	args := new(preregisterArgs)
	err := json.NewDecoder(body).Decode(args)
	if err != nil {
		httpError(w, errorf(ErrBadRequestJSON, "%s", err))
		return
	}

	logger := srv.log.WithFields(log.Fields{"username": args.Username})
	err = srv.preregister(args)
	if err != nil {
		logger = logger.WithFields(log.Fields{"code": errorCode(err).String()})
		if isInternalError(err) {
			logger.Errorf("Pre-registration failed: %s", err)
		} else {
			// Avoid polluting stderr for user-caused errors.
			logger.Infof("Pre-registration failed: %s", err)
		}
		httpError(w, err)
		return
	}
	logger.Info("Pre-registration successful")

	// reply with valid json
	w.Write([]byte("\"OK\""))
}

func (srv *Server) preregister(args *preregisterArgs) error {
	id, err := UsernameToIdentity(args.Username)
	if err != nil {
		return errorf(ErrInvalidUsername, "%s", err)
	}

	tx := srv.db.NewTransaction(true)
	defer tx.Discard()

	key := dbUserKey(id, registrationSuffix)
	_, err = tx.Get(key)
	if err != nil && err != badger.ErrKeyNotFound {
		return errorf(ErrDatabaseError, "%s", err)
	}
	if err == nil {
		return errorf(ErrAlreadyRegistered, "%s", args.Username)
	}

	tokenKey := dbUserKey(id, emailTokenSuffix)
	_, err = tx.Get(tokenKey)
	if err != nil && err != badger.ErrKeyNotFound {
		return errorf(ErrDatabaseError, "%s", err)
	}
	if err == nil {
		return errorf(ErrRegistrationInProgress, "%s", args.Username)
	}

	tokenBytes := make([]byte, 24)
	rand.Read(tokenBytes[:])
	token := base32.EncodeToString(tokenBytes)

	emailToken := emailToken{
		Token: token,
	}
	err = tx.SetWithTTL(tokenKey, emailToken.Marshal(), 24*time.Hour)
	if err != nil {
		return errorf(ErrDatabaseError, "%s", err)
	}

	err = tx.Commit(nil)
	if err != nil {
		return errorf(ErrDatabaseError, "%s", err)
	}

	emailData := verifyEmailData{
		From:  srv.smtpRelay.From,
		To:    args.Username,
		Date:  time.Now().Format(time.RFC822),
		Token: token,

		PKGAddr:  srv.addr,
		PKGIndex: args.PKGIndex,
		NumPKGs:  args.NumPKGs,
	}
	msgBuf := new(bytes.Buffer)
	if err := verifyEmailTemplate.Execute(msgBuf, emailData); err != nil {
		return errorf(ErrSendingEmail, "template error: %s", err)
	}

	err = srv.smtpRelay.SendMail(args.Username, msgBuf.Bytes())
	if err != nil {
		return errorf(ErrSendingEmail, "%s", err)
	}

	return nil
}

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

	tx := srv.db.NewTransaction(true)
	defer tx.Discard()

	err = srv.regTokenHandler(args.Username, args.RegistrationToken, tx)
	if err != nil {
		return err
	}

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

	err = tx.Commit(nil)
	if err != nil {
		return errorf(ErrDatabaseError, "%s", err)
	}

	return nil
}

func EmailTokenVerifier() RegTokenHandler {
	return func(username string, token string, tx *badger.Txn) error {
		id := ValidUsernameToIdentity(username)
		item, err := tx.Get(dbUserKey(id, emailTokenSuffix))
		if err != nil && err != badger.ErrKeyNotFound {
			return errorf(ErrDatabaseError, "%s", err)
		}
		if err == badger.ErrKeyNotFound {
			return errorf(ErrNotRegistered, "%s", username)
		}
		emailTokenBytes, err := item.Value()
		if err != nil {
			return errorf(ErrDatabaseError, "%s", err)
		}
		emailToken := new(emailToken)
		if err := emailToken.Unmarshal(emailTokenBytes); err != nil {
			return errorf(ErrDatabaseError, "%s", err)
		}
		if token != emailToken.Token {
			return errorf(ErrInvalidToken, "%q", token)
		}

		return nil
	}
}
