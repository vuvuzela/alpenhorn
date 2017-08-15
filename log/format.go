// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/davidlazar/go-crypto/encoding/base32"

	"vuvuzela.io/alpenhorn/log/ansi"
)

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

func (e *Entry) JSON() ([]byte, error) {
	m := make(Fields, len(e.Fields)+3)
	m["time"] = e.Time
	m["level"] = e.Level.String()
	if e.Message != "" {
		m["msg"] = e.Message
	}
	for k, v := range e.Fields {
		switch v := v.(type) {
		case error:
			// Otherwise encoding/json ignores errors.
			m[k] = v.Error()
		default:
			m[k] = v
		}
	}
	return json.Marshal(m)
}

func OutputJSON(dst io.Writer) EntryHandler {
	return &outputJSON{dst}
}

type outputJSON struct {
	dst io.Writer
}

func (h *outputJSON) Fire(e *Entry) {
	msg, err := e.JSON()
	if err != nil {
		fmt.Fprintf(Stderr, "Error marshaling log entry to JSON: %s\n", err)
		return
	}
	_, err = h.dst.Write(append(msg, '\n'))
	if err != nil {
		fmt.Fprintf(Stderr, "Error writing log entry: %s\n", err)
	}
}

type outputText struct {
	dst io.Writer
}

// OutputText returns an entry handler that writes a log entry
// as human-readable text to dst. The entry handler makes exactly
// one call to dst.Write for each entry.
func OutputText(dst io.Writer) EntryHandler {
	return &outputText{dst}
}

func (h *outputText) Fire(e *Entry) {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()

	color := e.Level.Color()
	if e.Level == InfoLevel {
		// Colorful timestamps on info messages is too distracting.
		buf.WriteString(e.Time.Format("15:04:05"))
	} else {
		ansi.WriteString(buf, e.Time.Format("15:04:05"), color, ansi.Bold)
	}
	fmt.Fprintf(buf, " %s %-44s ", e.Level.Icon(), e.Message)
	Logfmt(buf, e.Fields, color)
	buf.WriteByte('\n')

	_, err := h.dst.Write(buf.Bytes())
	if err != nil {
		fmt.Fprintf(Stderr, "Error writing log entry: %s", err)
	}

	bufPool.Put(buf)
}

func Logfmt(dst *bytes.Buffer, data map[string]interface{}, keyColors ...ansi.Code) {
	keys := make([]string, len(data))
	i := 0
	for k := range data {
		keys[i] = k
		i++
	}
	sort.Strings(keys)

	for _, k := range keys {
		dst.WriteByte(' ')
		ansi.WriteString(dst, k, keyColors...)
		dst.WriteByte('=')

		v := data[k]
		var str string
		switch v := v.(type) {
		case string:
			str = v
		case []byte:
			str = base32.EncodeToString(v)
		default:
			str = fmt.Sprint(v)
		}

		if needsQuotes(str) {
			dst.WriteString(fmt.Sprintf("%q", str))
		} else {
			dst.WriteString(str)
		}
	}
}

func needsQuotes(str string) bool {
	if str == "" {
		return true
	}
	return strings.ContainsAny(str, " \\\"\t\r\n")
}
