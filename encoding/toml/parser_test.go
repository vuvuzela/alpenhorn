// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toml

import (
	"reflect"
	"testing"
)

const example1 string = `
foo = ["hello\tworld"]
bar = 0

[servers]
a = [1,-19,3]

[servers.alpha] # server settings
ip = "10.0.0.1"
num = 42
float = 1.2345

[servers.beta]
ip = "10.0.0.2"
num = 23
float = -90.73
`

var example1Result = map[string]interface{}{
	"foo": []interface{}{"hello\tworld"},
	"bar": int64(0),
	"servers": map[string]interface{}{
		"a":     []interface{}{int64(1), int64(-19), int64(3)},
		"alpha": map[string]interface{}{"ip": "10.0.0.1", "num": int64(42), "float": float64(1.2345)},
		"beta":  map[string]interface{}{"ip": "10.0.0.2", "num": int64(23), "float": float64(-90.73)},
	},
}

const example2 string = `
[servers]

[servers.alpha]
b = true

[servers.beta]
b = false
`

var example2Result = map[string]interface{}{
	"servers": map[string]interface{}{
		"alpha": map[string]interface{}{"b": true},
		"beta":  map[string]interface{}{"b": false},
	},
}

func shouldParse(t *testing.T, name string, input string, expected interface{}) {
	actual, err := parse(input)
	if err != nil {
		t.Fatalf("toml parse error: %s: %s", name, err)
	}

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("unexpected parse result for %s:\ngot:\n%#v\nwant:\n%#v\n", name, actual, expected)
	}
}

func TestParse(t *testing.T) {
	shouldParse(t, "example1", example1, example1Result)
	shouldParse(t, "example2", example2, example2Result)
}
