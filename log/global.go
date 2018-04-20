// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log

import (
	"os"

	"github.com/mattn/go-isatty"
)

var StdLogger = &Logger{
	EntryHandler: &OutputText{
		Out:           Stderr,
		DisableColors: !isatty.IsTerminal(os.Stderr.Fd()),
	},
	Level: InfoLevel,
}

func WithFields(fields Fields) *Logger          { return StdLogger.WithFields(fields) }
func Info(args ...interface{})                  { StdLogger.Info(args...) }
func Infof(format string, args ...interface{})  { StdLogger.Infof(format, args...) }
func Error(args ...interface{})                 { StdLogger.Error(args...) }
func Errorf(format string, args ...interface{}) { StdLogger.Errorf(format, args...) }
func Warn(args ...interface{})                  { StdLogger.Warn(args...) }
func Warnf(format string, args ...interface{})  { StdLogger.Warnf(format, args...) }
func Fatal(args ...interface{})                 { StdLogger.Fatal(args...) }
func Fatalf(format string, args ...interface{}) { StdLogger.Fatalf(format, args...) }
func Debug(args ...interface{})                 { StdLogger.Debug(args...) }
func Debugf(format string, args ...interface{}) { StdLogger.Debugf(format, args...) }
func Panic(args ...interface{})                 { StdLogger.Panic(args...) }
func Panicf(format string, args ...interface{}) { StdLogger.Panicf(format, args...) }
