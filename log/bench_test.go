// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"vuvuzela.io/alpenhorn/log"
)

var (
	fakeMessage  = "This is a simulated log message..."
	fakeDuration = 12345 * time.Second
	fakeError    = errors.New("something failed")
)

func newJSONLogger(out io.Writer) *log.Logger {
	return &log.Logger{
		EntryHandler: log.OutputJSON(log.NewMutexWriter(out)),
		Level:        log.DebugLevel,
	}
}

func newTextLogger(out io.Writer) *log.Logger {
	return &log.Logger{
		EntryHandler: log.OutputText(log.NewMutexWriter(out)),
		Level:        log.DebugLevel,
	}
}

func fakeFields() log.Fields {
	return log.Fields{
		"rpc":      "NewRound",
		"addr":     "127.0.0.1:8080",
		"duration": fakeDuration,
		"error":    fakeError,
		"round":    876543,
	}
}

func newJSONLogrus(out io.Writer) *logrus.Logger {
	return &logrus.Logger{
		Out:       out,
		Formatter: new(logrus.JSONFormatter),
		Hooks:     make(logrus.LevelHooks),
		Level:     logrus.DebugLevel,
	}
}

func newTextLogrus(out io.Writer) *logrus.Logger {
	return &logrus.Logger{
		Out:       out,
		Formatter: new(logrus.TextFormatter),
		Hooks:     make(logrus.LevelHooks),
		Level:     logrus.DebugLevel,
	}
}

func fakeLogrusFields() logrus.Fields {
	return logrus.Fields{
		"rpc":      "NewRound",
		"addr":     "127.0.0.1:8080",
		"duration": fakeDuration,
		"error":    fakeError,
		"round":    876543,
	}
}

func BenchmarkJSONLogrus(b *testing.B) {
	logger := newJSONLogrus(ioutil.Discard)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			logger.WithFields(fakeLogrusFields()).Info(fakeMessage)
		}
	})
}

func BenchmarkJSONLog(b *testing.B) {
	logger := newJSONLogger(ioutil.Discard)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			logger.WithFields(fakeFields()).Info(fakeMessage)
		}
	})
}

func BenchmarkTextLogrus(b *testing.B) {
	logger := newTextLogrus(ioutil.Discard)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			logger.WithFields(fakeLogrusFields()).Info(fakeMessage)
		}
	})
}

func BenchmarkTextLog(b *testing.B) {
	logger := newTextLogger(ioutil.Discard)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			logger.WithFields(fakeFields()).Info(fakeMessage)
		}
	})
}

func TestCompareLogrus(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	fmt.Println("--Logrus Text--")
	textLogrus := newTextLogrus(os.Stderr)
	textLogrus.WithFields(fakeLogrusFields()).Info("This is an informational message")
	textLogrus.WithFields(fakeLogrusFields()).Error("This is an error message")
	textLogrus.WithFields(fakeLogrusFields()).Warn("This is a warning message")
	textLogrus.WithFields(logrus.Fields{"round": 12345, "publicKey": key}).Debug("This is a debug message with key")
	textLogrus.WithFields(fakeLogrusFields()).Infof("This is a very long and inspirational message with an error: %s", errors.New("something failed"))
	textLogrus.WithFields(logrus.Fields{"short": true}).Info("Shortmsg")

	fmt.Println("\n--Log Text--")
	textLogger := newTextLogger(os.Stderr)
	textLogger.WithFields(fakeFields()).Info("This is an informational message")
	textLogger.WithFields(fakeFields()).Error("This is an error message")
	textLogger.WithFields(fakeFields()).Warn("This is a warning message")
	textLogger.WithFields(log.Fields{"round": 12345, "publicKey": key}).Debug("This is a debug message with key")
	textLogger.WithFields(fakeFields()).Infof("This is a very long and inspirational message with an error: %s", errors.New("something failed"))
	textLogger.WithFields(log.Fields{"short": true}).Info("Shortmsg")

	fmt.Println("\n--Logrus JSON--")
	jsonLogrus := newJSONLogrus(os.Stderr)
	jsonLogrus.WithFields(fakeLogrusFields()).Info(fakeMessage)
	jsonLogrus.WithFields(fakeLogrusFields()).Error(fakeMessage)

	fmt.Println("\n--Log JSON--")
	jsonLogger := newJSONLogger(os.Stderr)
	jsonLogger.WithFields(fakeFields()).Info(fakeMessage)
	jsonLogger.WithFields(fakeFields()).Error(fakeMessage)
}
