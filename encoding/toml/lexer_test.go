// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toml

import (
	"testing"
)

var lexData = `# hello world
# foobar
[hello.world]x = [1,-22.987,3,true,[false]]
y = false

[[thing.fruit]]
name = "apple"
`

func TestLex(t *testing.T) {
	lx := lex("test", lexData, lexTableBody)
	vals := []string{"[", "hello", "world", "]", "x", "=", "[", "1", ",", "-22.987", ",", "3", ",", "true", ",", "[", "false", "]", "]", "y", "=", "false", "[[", "thing", "fruit", "]]", "name", "=", "\"apple\""}
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
