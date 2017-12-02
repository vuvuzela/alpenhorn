// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pkg

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
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

type userStatus int

const (
	statusExpired userStatus = iota
	statusPending
	statusVerified
)

func (srv *Server) register(username string, loginKey ed25519.PublicKey) error {
	if err := ValidateUsername(username); err != nil {
		return errorf(ErrInvalidUsername, "%s", err)
	}
	if len(loginKey) != ed25519.PublicKeySize {
		return errorf(ErrInvalidLoginKey, "got %d bytes, want %d bytes", len(loginKey), ed25519.PublicKeySize)
	}

	tx, err := srv.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var status userStatus
	tokenExpires := new(time.Time)
	row := tx.QueryRow("SELECT status, tokenExpires FROM users WHERE username=$1", username)
	err = row.Scan(&status, &tokenExpires)
	switch {
	case err == nil && status == statusVerified:
		return errorf(ErrAlreadyRegistered, "%q", username)
	case err == nil && status == statusPending:
		// XXX tokenExpires shouldn't be null
		if time.Now().Before(*tokenExpires) {
			return errorf(ErrRegistrationInProgress, "try again later")
		}

		token := make([]byte, 32)
		rand.Read(token)
		expires := time.Now().Add(24 * time.Hour)
		_, err := tx.Exec(
			"UPDATE users SET token=$1, tokenExpires=$2 WHERE username=$3",
			token, expires, username,
		)
		if err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		if err := srv.sendVerificationEmail(username, token); err != nil {
			return errorf(ErrSendingEmail, "%s", err)
		}
		return nil
	case err == sql.ErrNoRows && srv.sendVerificationEmail == nil:
		_, err := tx.Exec(
			"INSERT INTO users (username, status, key) VALUES($1, $2, $3)",
			username, statusVerified, []byte(loginKey),
		)
		if err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		return nil
	case err == sql.ErrNoRows && srv.sendVerificationEmail != nil:
		token := make([]byte, 32)
		rand.Read(token)
		expires := time.Now().Add(24 * time.Hour)
		_, err := tx.Exec(
			"INSERT INTO users (username, status, key, token, tokenExpires) VALUES($1, $2, $3, $4, $5)",
			username, statusPending, []byte(loginKey), token, expires,
		)
		if err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		if err := srv.sendVerificationEmail(username, token); err != nil {
			return errorf(ErrSendingEmail, "%s", err)
		}
		return nil
	case err != nil:
		return err
	}

	return nil
}
