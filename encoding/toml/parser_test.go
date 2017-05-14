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

const example3 string = `
[[products]]
name = "Hammer"
sku = 738594937

[[products]]

[[products]]
name = "Nail"
sku = 284758393
color = "gray"
`

var example3Result = map[string]interface{}{
	"products": []map[string]interface{}{
		{"name": "Hammer", "sku": int64(738594937)},
		{},
		{"name": "Nail", "sku": int64(284758393), "color": "gray"},
	},
}

var example4 = `
[[fruit]]
  name = "apple"

  [fruit.physical]
    color = "red"
    shape = "round"

  [[fruit.variety]]
    name = "red delicious"

  [[fruit.variety]]
    name = "granny smith"

[[fruit]]
  name = "banana"

  [[fruit.variety]]
    name = "plantain"
`

var example4Result = map[string]interface{}{
	"fruit": []map[string]interface{}{
		{
			"name": "apple",
			"physical": map[string]interface{}{
				"color": "red",
				"shape": "round",
			},
			"variety": []map[string]interface{}{
				{"name": "red delicious"},
				{"name": "granny smith"},
			},
		},
		{
			"name": "banana",
			"variety": []map[string]interface{}{
				{"name": "plantain"},
			},
		},
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
	shouldParse(t, "example3", example3, example3Result)
	shouldParse(t, "example4", example4, example4Result)
}

var badExample1 = `
[[foo.bar]]
x = 123

[[foo]]
y = 888

[[foo]]
y = 999
`

var badExample2 = `
# INVALID TOML DOC
[[fruit]]
  name = "apple"

  [[fruit.variety]]
    name = "red delicious"

  # This table conflicts with the previous table
  [fruit.variety]
    name = "granny smith"
`

func shouldNotParse(t *testing.T, name string, input string) {
	actual, err := parse(input)
	if err == nil {
		t.Fatalf("expected parse to fail for %s, got:\n%#v\n", name, actual)
	}
}

func TestNoParse(t *testing.T) {
	shouldNotParse(t, "badExample1", badExample1)
	shouldNotParse(t, "badExample2", badExample2)
}
