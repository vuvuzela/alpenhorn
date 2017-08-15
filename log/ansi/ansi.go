// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ansi implements ANSI escape codes for terminal colors.
package ansi

import (
	"bytes"
	"fmt"
	"io"
)

// Code is an ANSI escape code.
type Code int

const (
	Reset   Code = 0
	Bold    Code = 1
	Reverse Code = 7
	Red     Code = 31
	Green   Code = 32
	Yellow  Code = 33
	Blue    Code = 34
	Magenta Code = 35
	Cyan    Code = 36
	White   Code = 37 // Usually light grey.
)

var AllColors = []Code{Red, Green, Yellow, Blue, Magenta, Cyan, White}

type ansiFormatter struct {
	value interface{}
	codes []Code
}

// Colorf returns an fmt.Formatter that colors the value according
// to the codes when passed to an fmt "printf" function. For example:
// fmt.Printf("%d %s", Colorf(42, Blue), Colorf(err, Red)). If codes
// is empty, Colorf returns the original value for efficiency.
func Colorf(value interface{}, codes ...Code) interface{} {
	if len(codes) == 0 {
		return value
	}
	return &ansiFormatter{value, codes}
}

func (af *ansiFormatter) Format(f fmt.State, c rune) {
	// reconstruct the format string in bf
	bf := new(bytes.Buffer)
	bf.WriteByte('%')
	for _, x := range []byte{'-', '+', '#', ' ', '0'} {
		if f.Flag(int(x)) {
			bf.WriteByte(x)
		}
	}
	if w, ok := f.Width(); ok {
		fmt.Fprint(bf, w)
	}
	if p, ok := f.Precision(); ok {
		fmt.Fprintf(bf, ".%d", p)
	}
	bf.WriteRune(c)
	format := bf.String()

	if len(af.codes) == 0 {
		fmt.Fprintf(f, format, af.value)
		return
	}

	fmt.Fprintf(f, "\x1b[%d", af.codes[0])
	for _, code := range af.codes[1:] {
		fmt.Fprintf(f, ";%d", code)
	}
	f.Write([]byte{'m'})
	fmt.Fprintf(f, format, af.value)
	fmt.Fprint(f, "\x1b[0m")
}

func WriteString(dst io.Writer, str string, codes ...Code) (n int, err error) {
	if len(codes) == 0 {
		return io.WriteString(dst, str)
	}

	n, err = fmt.Fprintf(dst, "\x1b[%d", codes[0])
	if err != nil {
		return
	}

	var nn int
	for _, code := range codes[1:] {
		nn, err = fmt.Fprintf(dst, ";%d", code)
		n += nn
		if err != nil {
			return
		}
	}
	nn, err = fmt.Fprint(dst, "m")
	n += nn
	if err != nil {
		return
	}

	nn, err = io.WriteString(dst, str)
	n += nn
	if err != nil {
		return
	}

	nn, err = fmt.Fprint(dst, "\x1b[0m")
	n += nn
	return
}
