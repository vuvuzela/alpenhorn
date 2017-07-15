// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package mixnetpb

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"testing"
)

func makereq() *AddOnionsRequest {
	req := &AddOnionsRequest{
		Round:  123456,
		Onions: make([][]byte, 1000),
	}
	for i := 0; i < 1000; i++ {
		msg := make([]byte, 32)
		rand.Read(msg)
		req.Onions[i] = msg
	}
	return req
}

func TestCompareGobSize(t *testing.T) {
	if !testing.Verbose() {
		t.Skip("informational test (run with -v)")
	}

	req := makereq()

	buf := new(bytes.Buffer)
	gob.NewEncoder(buf).Encode(req)

	data1 := buf.Bytes()
	data2, _ := req.Marshal()

	t.Logf("gob:%d  proto:%d", len(data1), len(data2))
}

func BenchmarkEncodeProto(b *testing.B) {
	var x []byte
	req := makereq()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x, _ = req.Marshal()
	}
	_ = len(x)
}

func BenchmarkEncodeGob(b *testing.B) {
	req := makereq()
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	enc.Encode(req)
	buf.Reset()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		enc.Encode(req)
		buf.Reset()
	}
}

func BenchmarkDecodeProto(b *testing.B) {
	req := makereq()
	msg, err := req.Marshal()
	if err != nil {
		b.Fatal(err)
	}
	req = new(AddOnionsRequest)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err = req.Unmarshal(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeGob(b *testing.B) {
	req := makereq()

	buf := new(bytes.Buffer)
	err := gob.NewEncoder(buf).Encode(req)
	if err != nil {
		b.Fatal(err)
	}
	msg := buf.Bytes()

	r := new(bytes.Reader)
	req = new(AddOnionsRequest)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		r.Reset(msg)
		err := gob.NewDecoder(r).Decode(req)
		if err != nil {
			b.Fatal(err)
		}
	}
}
