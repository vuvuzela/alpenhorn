// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package errors implements basic error handling.
//
// This package is like github.com/pkg/errors but without the stack traces.
package errors

import (
	"fmt"
)

type errorString struct {
	msg string
}

func (e *errorString) Error() string {
	return e.msg
}

func New(format string, a ...interface{}) error {
	return &errorString{fmt.Sprintf(format, a...)}
}

type withCause struct {
	cause error
	msg   string
}

func (e *withCause) Error() string {
	return e.msg + ": " + e.cause.Error()
}

func Wrap(err error, format string, a ...interface{}) error {
	return &withCause{
		cause: err,
		msg:   fmt.Sprintf(format, a...),
	}
}
