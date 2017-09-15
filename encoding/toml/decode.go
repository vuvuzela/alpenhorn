// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toml

import (
	"reflect"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"github.com/davidlazar/mapstructure"
)

// Unmarshal parses the TOML-encoded data and stores the result in the
// value pointed to by v.  Unmarshal has special cases for the following
// types:
//
//   []byte can be encoded as a base32 string
//   time.Duration can be encoded as a string in the form "72h3m0.5s"
//
func Unmarshal(data []byte, v interface{}) error {
	m, err := parse(string(data))
	if err != nil {
		return err
	}

	hook := mapstructure.ComposeDecodeHookFunc(
		stringToBytesHook,
		stringToTimeHook,
		mapstructure.StringToTimeDurationHookFunc(),
	)

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: hook,
		Result:     v,
	})
	if err != nil {
		return err
	}

	return decoder.Decode(m)
}

func EncodeBytes(data []byte) string {
	return base32.EncodeToString(data)
}

func DecodeBytes(str string) ([]byte, error) {
	return base32.DecodeString(str)
}

func stringToBytesHook(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
	if from.Kind() != reflect.String {
		return data, nil
	}
	if !to.AssignableTo(reflect.TypeOf([]byte{})) {
		return data, nil
	}
	return DecodeBytes(data.(string))
}

func stringToTimeHook(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
	if from.Kind() != reflect.String {
		return data, nil
	}
	if to != reflect.TypeOf(time.Time{}) {
		return data, nil
	}

	return time.Parse(time.RFC3339, data.(string))
}

func parse(str string) (map[string]interface{}, error) {
	// TODO lex name
	lx := lex("test", str, lexTableBody)
	r := yyParse(lx)
	if r == 0 || lx.err == nil {
		return lx.result, lx.err
	}
	return nil, lx.err
}
