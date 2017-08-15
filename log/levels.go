// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log

import "vuvuzela.io/alpenhorn/log/ansi"

// Level is a logging level. The levels are copied from logrus.
type Level uint32

const (
	PanicLevel Level = iota
	FatalLevel
	ErrorLevel
	WarnLevel
	InfoLevel
	DebugLevel
)

func (level Level) String() string {
	switch level {
	case DebugLevel:
		return "debug"
	case InfoLevel:
		return "info"
	case WarnLevel:
		return "warning"
	case ErrorLevel:
		return "error"
	case FatalLevel:
		return "fatal"
	case PanicLevel:
		return "panic"
	}

	return "unknown"
}

func (level Level) Icon() string {
	switch level {
	case DebugLevel:
		return "·"
	case InfoLevel:
		return " "
	case WarnLevel:
		return "~"
	case ErrorLevel:
		return "!"
	case FatalLevel:
		return "*"
	case PanicLevel:
		return "X"
	}

	return "UNKNOWN"
}

func (level Level) Color() ansi.Code {
	switch level {
	case DebugLevel:
		return ansi.White
	case InfoLevel:
		return ansi.Cyan
	case WarnLevel:
		return ansi.Yellow
	case ErrorLevel:
		return ansi.Red
	case FatalLevel:
		return ansi.Red
	case PanicLevel:
		return ansi.Red
	default:
		return ansi.Red
	}
}
