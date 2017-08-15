// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log

import (
	"io"
	"os"
	"sync"
)

var Stdout = NewMutexWriter(os.Stdout)

var Stderr = NewMutexWriter(os.Stderr)

type MutexWriter struct {
	mu    sync.Mutex
	inner io.Writer
}

func NewMutexWriter(w io.Writer) *MutexWriter {
	return &MutexWriter{
		inner: w,
	}
}

func (w *MutexWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	n, err := w.inner.Write(data)
	w.mu.Unlock()
	return n, err
}
