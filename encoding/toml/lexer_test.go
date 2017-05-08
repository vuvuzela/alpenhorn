// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toml

import (
	"testing"
)

func TestLexComment(t *testing.T) {
	lx := lex("test", "# hello world\n# foobar\n[hello.world]x = [1,-22.987,3,true,[false]]\ny = false", lexTableBody)
	vals := []string{"[", "hello", "world", "]", "x", "=", "[", "1", ",", "-22.987", ",", "3", ",", "true", ",", "[", "false", "]", "]", "y", "=", "false"}
	i := 0
	for {
		item := lx.nextItem()
		if item.typ == eof || item.typ == itemError {
			break
		}
		if item.val != vals[i] {
			t.Fatalf("item %d: got %q want %q", i, item.val, vals[i])
		}
		i++
	}
}
