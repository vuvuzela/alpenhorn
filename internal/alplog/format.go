// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package alplog

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"

	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/alpenhorn/log/ansi"
)

var bufPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

type ProductionOutput struct {
	dirHandler    *log.OutputDir
	stderrHandler outputText
}

func NewProductionOutput(logsDir string) (ProductionOutput, error) {
	h := ProductionOutput{
		stderrHandler: outputText{
			dst: log.Stderr,
		},
	}

	if logsDir != "" {
		err := os.MkdirAll(logsDir, 0770)
		if err != nil {
			return h, fmt.Errorf("failed to create logs directory: %s", err)
		}

		h.dirHandler = &log.OutputDir{
			Dir: logsDir,
		}
	}

	return h, nil
}

func (h ProductionOutput) Name() string {
	if h.dirHandler == nil {
		return "[stderr]"
	}
	return h.dirHandler.Dir
}

func (h ProductionOutput) Fire(e *log.Entry) {
	if h.dirHandler != nil {
		h.dirHandler.Fire(e)

		// Only print errors to stderr.
		if e.Level > log.ErrorLevel {
			return
		}
	}
	h.stderrHandler.Fire(e)
}

type outputText struct {
	dst io.Writer
}

func OutputText(dst io.Writer) log.EntryHandler {
	return outputText{dst}
}

func (h outputText) Fire(e *log.Entry) {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()

	prettyPrint(buf, e)

	_, err := h.dst.Write(buf.Bytes())
	if err != nil {
		fmt.Fprintf(log.Stderr, "Error writing log entry: %s", err)
	}

	bufPool.Put(buf)
}

func prettyPrint(buf *bytes.Buffer, e *log.Entry) {
	color := e.Level.Color()
	if e.Level == log.InfoLevel {
		// Colorful timestamps on info messages are too distracting.
		buf.WriteString(e.Time.Format("2006-01-02 15:04:05"))
	} else {
		ansi.WriteString(buf, e.Time.Format("2006-01-02 15:04:05"), color, ansi.Bold)
	}

	fmt.Fprintf(buf, " %s ", e.Level.Icon())

	fields := make(log.Fields, len(e.Fields))
	for k, v := range e.Fields {
		fields[k] = v
	}

	service, okService := fields["service"].(string)
	round, okRound := fields["round"].(uint32)
	if okService && okRound {
		delete(fields, "round")
		delete(fields, "service")
		l := len(ansi.AllColors)
		if service == "AddFriend" {
			roundColor := ansi.AllColors[int(round)%l]
			fmt.Fprintf(buf, "%05d  ", ansi.Colorf(round, roundColor, ansi.Reverse))
		} else {
			roundColor := ansi.AllColors[(int(round)+l/2)%l]
			fmt.Fprintf(buf, "%05d  ", ansi.Colorf(round, roundColor))
		}
	}

	tag, okTag := fields["tag"].(string)
	if okTag {
		delete(fields, "tag")
		tag = tag + ": "
	}

	rpc, okRPC := fields["rpc"].(string)
	if okRPC {
		delete(fields, "rpc")
		rpc = rpc + ": "
	}

	fmt.Fprintf(buf, "%-42s ", tag+rpc+e.Message)
	log.Logfmt(buf, fields, color)
	buf.WriteByte('\n')
}
