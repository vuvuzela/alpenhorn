// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pkg

import (
	"encoding/json"
	"fmt"
	"log"

	"net/http"

	"github.com/lib/pq"
)

type ErrorCode int

const (
	ErrBadRequestJSON ErrorCode = iota + 1
	ErrDatabaseError
	ErrInvalidUsername
	ErrNotRegistered
	ErrNotVerified
	ErrAlreadyRegistered
	ErrRegistrationInProgress
	ErrSendingEmail
	ErrRoundNotFound
	ErrInvalidSigningKey
	ErrInvalidSignature
	ErrInvalidToken
	ErrExpiredToken

	ErrUnknown
)

var errText = map[ErrorCode]string{
	ErrBadRequestJSON:         "invalid json in request",
	ErrDatabaseError:          "internal database error",
	ErrInvalidUsername:        "invalid username",
	ErrNotRegistered:          "username not registered",
	ErrNotVerified:            "username not verified",
	ErrAlreadyRegistered:      "username already registered",
	ErrRegistrationInProgress: "registration in progress",
	ErrSendingEmail:           "error sending verification email",
	ErrRoundNotFound:          "round not found",
	ErrInvalidSigningKey:      "invalid signing key",
	ErrInvalidSignature:       "invalid signature",
	ErrInvalidToken:           "invalid token",
	ErrExpiredToken:           "expired token",

	ErrUnknown: "unknown error",
}

func (e ErrorCode) httpCode() int {
	switch e {
	case ErrDatabaseError, ErrSendingEmail, ErrUnknown:
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

type Error struct {
	Code    ErrorCode
	Message string
}

func (e Error) Error() string {
	txt, ok := errText[e.Code]
	if !ok {
		return "unknown error code"
	}
	if e.Message == "" {
		return txt
	}
	return fmt.Sprintf("%s: %s", txt, e.Message)
}

func errorf(code ErrorCode, format string, args ...interface{}) error {
	return Error{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

func httpError(w http.ResponseWriter, err error) {
	var pkgError Error
	switch v := err.(type) {
	case *pq.Error:
		pkgError = Error{ErrDatabaseError, err.Error()}
	case Error:
		pkgError = v
	default:
		pkgError = Error{ErrUnknown, err.Error()}
	}
	data, err := json.Marshal(pkgError)
	if err != nil {
		// this shouldn't happen
		panic(err)
	}
	httpCode := pkgError.Code.httpCode()
	if httpCode == http.StatusInternalServerError {
		log.Printf("pkg error: %s", pkgError.Error())
	}
	w.WriteHeader(httpCode)
	w.Write(data)
}
