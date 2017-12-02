// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pkg

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lib/pq"
)

//go:generate stringer -type=ErrorCode
type ErrorCode int

const (
	ErrBadRequestJSON ErrorCode = iota + 1
	ErrDatabaseError
	ErrInvalidUsername
	ErrInvalidLoginKey
	ErrNotRegistered
	ErrNotVerified
	ErrAlreadyRegistered
	ErrRegistrationInProgress
	ErrSendingEmail
	ErrRoundNotFound
	ErrInvalidUserLongTermKey
	ErrInvalidSignature
	ErrInvalidToken
	ErrExpiredToken
	ErrUnauthorized
	ErrBadCommitment

	ErrUnknown
)

var errText = map[ErrorCode]string{
	ErrBadRequestJSON:         "invalid json in request",
	ErrDatabaseError:          "internal database error",
	ErrInvalidUsername:        "invalid username",
	ErrInvalidLoginKey:        "invalid login key",
	ErrNotRegistered:          "username not registered",
	ErrNotVerified:            "username not verified",
	ErrAlreadyRegistered:      "username already registered",
	ErrRegistrationInProgress: "registration in progress",
	ErrSendingEmail:           "error sending verification email",
	ErrRoundNotFound:          "round not found",
	ErrInvalidUserLongTermKey: "invalid user long term key",
	ErrInvalidSignature:       "invalid signature",
	ErrInvalidToken:           "invalid token",
	ErrExpiredToken:           "expired token",
	ErrUnauthorized:           "unauthorized",
	ErrBadCommitment:          "bad commitment",

	ErrUnknown: "unknown error",
}

func (e ErrorCode) httpCode() int {
	switch e {
	case ErrDatabaseError, ErrSendingEmail, ErrUnknown:
		return http.StatusInternalServerError
	case ErrUnauthorized:
		return http.StatusUnauthorized
	default:
		return http.StatusBadRequest
	}
}

func errorCode(err error) ErrorCode {
	switch err := err.(type) {
	case Error:
		return err.Code
	case *pq.Error:
		return ErrDatabaseError
	default:
		return ErrUnknown
	}
}

func isInternalError(err error) bool {
	switch errorCode(err) {
	case ErrDatabaseError, ErrSendingEmail, ErrBadCommitment, ErrUnknown:
		return true
	}
	return false
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

func errorf(code ErrorCode, format string, args ...interface{}) Error {
	return Error{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

func httpError(w http.ResponseWriter, err error) {
	var pkgError Error
	switch v := err.(type) {
	case Error:
		pkgError = v
	default:
		pkgError = Error{errorCode(err), err.Error()}
	}

	data, err := json.Marshal(pkgError)
	if err != nil {
		// this shouldn't happen
		panic(err)
	}
	httpCode := pkgError.Code.httpCode()
	w.WriteHeader(httpCode)
	w.Write(data)
}
