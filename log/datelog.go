// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log

import (
	"fmt"
	"io"
	"time"
)

func LogDates(w io.Writer) {
	go dateLogger(w)
}

func dateLogger(w io.Writer) {
	for {
		now := time.Now()
		fmt.Fprintf(w, "-- %s --\n", now.Format("2006-01-02"))
		y, m, d := now.Date()
		// actually 1ns past midnight
		midnight := time.Date(y, m, d+1, 0, 0, 0, 1, now.Location())
		select {
		case <-time.After(time.Until(midnight)):
		}
	}
}
