// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package log provides structured logging.
package log

import (
	"fmt"
	"os"
	"time"
)

type Logger struct {
	EntryHandler
	Level Level

	fields Fields
}

type Entry struct {
	Fields  Fields
	Time    time.Time
	Level   Level
	Message string
}

type EntryHandler interface {
	Fire(*Entry)
}

func (l *Logger) Clone() *Logger {
	return &Logger{
		EntryHandler: l.EntryHandler,
		Level:        l.Level,
		fields:       l.fields,
	}
}

type Fields map[string]interface{}

func (l *Logger) WithFields(fields Fields) *Logger {
	ll := &Logger{
		EntryHandler: l.EntryHandler,
		Level:        l.Level,
		fields:       make(Fields, len(l.fields)+len(fields)),
	}
	for k, v := range l.fields {
		ll.fields[k] = v
	}
	for k, v := range fields {
		ll.fields[k] = v
	}
	return ll
}

func (l *Logger) Info(args ...interface{}) {
	if l.Level >= InfoLevel {
		l.fire(InfoLevel, fmt.Sprint(args...))
	}
}

func (l *Logger) Infof(format string, args ...interface{}) {
	if l.Level >= InfoLevel {
		l.fire(InfoLevel, fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Error(args ...interface{}) {
	if l.Level >= ErrorLevel {
		l.fire(ErrorLevel, fmt.Sprint(args...))
	}
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	if l.Level >= ErrorLevel {
		l.fire(ErrorLevel, fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Warn(args ...interface{}) {
	if l.Level >= WarnLevel {
		l.fire(WarnLevel, fmt.Sprint(args...))
	}
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	if l.Level >= WarnLevel {
		l.fire(WarnLevel, fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Fatal(args ...interface{}) {
	if l.Level >= FatalLevel {
		l.fire(FatalLevel, fmt.Sprint(args...))
	}
	os.Exit(1)
}

func (l *Logger) Fatalf(format string, args ...interface{}) {
	if l.Level >= FatalLevel {
		l.fire(FatalLevel, fmt.Sprintf(format, args...))
	}
	os.Exit(1)
}

func (l *Logger) Debug(args ...interface{}) {
	if l.Level >= DebugLevel {
		l.fire(DebugLevel, fmt.Sprint(args...))
	}
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	if l.Level >= DebugLevel {
		l.fire(DebugLevel, fmt.Sprintf(format, args...))
	}
}

func (l *Logger) Panic(args ...interface{}) {
	msg := fmt.Sprint(args...)
	if l.Level >= PanicLevel {
		l.fire(PanicLevel, msg)
	}
	panic(msg)
}

func (l *Logger) Panicf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if l.Level >= PanicLevel {
		l.fire(PanicLevel, msg)
	}
	panic(msg)
}

func (l *Logger) fire(level Level, msg string) {
	if l.EntryHandler != nil {
		entry := &Entry{
			Fields:  l.fields,
			Time:    time.Now(),
			Level:   level,
			Message: msg,
		}
		l.Fire(entry)
	}
}
