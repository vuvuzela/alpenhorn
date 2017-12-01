// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"

	"vuvuzela.io/alpenhorn/log/ansi"
)

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

func (e *Entry) JSON(w io.Writer) error {
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
	return json.NewEncoder(w).Encode(m)
}

func OutputJSON(dst io.Writer) EntryHandler {
	return &outputJSON{dst}
}

type outputJSON struct {
	dst io.Writer
}

func (h *outputJSON) Fire(e *Entry) {
	err := e.JSON(h.dst)
	if err != nil {
		fmt.Fprintf(Stderr, "Error marshaling log entry to JSON: %s\n", err)
		return
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

	prettyPrint(buf, e)

	_, err := h.dst.Write(buf.Bytes())
	if err != nil {
		fmt.Fprintf(Stderr, "Error writing log entry: %s", err)
	}

	bufPool.Put(buf)
}

func prettyPrint(buf *bytes.Buffer, e *Entry) {
	color := e.Level.Color()
	if e.Level == InfoLevel {
		// Colorful timestamps on info messages is too distracting.
		buf.WriteString(e.Time.Format("2006-01-02 15:04:05"))
	} else {
		ansi.WriteString(buf, e.Time.Format("2006-01-02 15:04:05"), color, ansi.Bold)
	}
	fmt.Fprintf(buf, " %s %-44s ", e.Level.Icon(), e.Message)
	Logfmt(buf, e.Fields, color)
	buf.WriteByte('\n')
}

type OutputDir struct {
	// Dir is the directory that log files are written to in JSON-line format.
	Dir string

	mu       sync.Mutex
	currPath string
	currDate time.Time
	currFile io.WriteCloser
}

func (h *OutputDir) persistEntry(e *Entry) error {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	y, m, d := e.Time.Date()
	err := e.JSON(buf)
	if err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.currPath != "" {
		yy, mm, dd := h.currDate.Date()
		if (d == dd && m == mm && y == yy) || e.Time.Before(h.currDate) {
			_, err := buf.WriteTo(h.currFile)
			if err != nil {
				return fmt.Errorf("error writing log file %s: %s", h.currPath, err)
			}
			return nil
		}

		err = h.currFile.Close()
		if err != nil {
			return fmt.Errorf("error closing log file %s: %s", h.currPath, err)
		}
	}

	path := filepath.Join(h.Dir, e.Time.Format("2006-01-02")+".log")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("error opening log file %s: %s", path, err)
	}

	h.currDate = e.Time
	h.currPath = path
	h.currFile = file

	_, err = buf.WriteTo(h.currFile)
	if err != nil {
		return fmt.Errorf("error writing log file %s: %s", h.currPath, err)
	}
	return nil
}

func (h *OutputDir) Fire(e *Entry) {
	err := h.persistEntry(e)
	if err != nil {
		fmt.Fprintf(Stderr, "%s\n", err)
	}
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
