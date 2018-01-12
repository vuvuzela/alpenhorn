// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package bloom implements Bloom filters.
package bloom

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"

	"github.com/dchest/siphash"
)

type Filter struct {
	numHashes int
	data      []byte
}

func New(sizeBits int, numHashes int) *Filter {
	m := (sizeBits + 7) / 8
	return &Filter{
		numHashes: numHashes,
		data:      make([]byte, m),
	}
}

// Optimal computes optimal Bloom filter parameters.
// These parameters are optimal for small bloom filters as
// described in section 4.1 of this paper:
//
//   https://web.stanford.edu/~ashishg/papers/inverted.pdf
func Optimal(numElements int, falsePositiveRate float64) (sizeBits int, numHashes int) {
	n := float64(numElements)
	p := falsePositiveRate
	m := -(n+0.5)*math.Log(p)/math.Pow(math.Log(2), 2) + 1
	k := -math.Log(p) / math.Log(2)
	return int(math.Ceil(m)), int(math.Ceil(k))
}

func (f *Filter) Set(x []byte) {
	hs := hash(x, f.numHashes)
	n := uint32(len(f.data) * 8)
	for _, h := range hs {
		f.set(h % n)
	}
}

func (f *Filter) Test(x []byte) bool {
	hs := hash(x, f.numHashes)
	n := uint32(len(f.data) * 8)
	for _, h := range hs {
		if !f.test(h % n) {
			return false
		}
	}
	return true
}

func (f *Filter) Len() int {
	return len(f.data)
}

func (f *Filter) NumHashes() int {
	return f.numHashes
}

func (f *Filter) MarshalBinary() ([]byte, error) {
	data := make([]byte, len(f.data)+4)
	n := uint32(f.numHashes)
	binary.BigEndian.PutUint32(data[0:4], n)
	copy(data[4:], f.data)
	return data, nil
}

func (f *Filter) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return errors.New("short data")
	}
	f.numHashes = int(binary.BigEndian.Uint32(data[0:4]))
	f.data = data[4:]
	return nil
}

func (f *Filter) MarshalJSON() ([]byte, error) {
	data, err := f.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

func (f *Filter) UnmarshalJSON(data []byte) error {
	var bs []byte
	if err := json.Unmarshal(data, &bs); err != nil {
		return err
	}
	return f.UnmarshalBinary(bs)
}

// Previously, we used the hashing method described in this paper:
// http://www.eecs.harvard.edu/~michaelm/postscripts/rsa2008.pdf
// but this gave us bad false positive rates for small bloom filters.
func hash(x []byte, nhash int) []uint32 {
	res := make([]uint32, nhash+3)

	for i := 0; i < (nhash+3)/4; i++ {
		h1, h2 := siphash.Hash128(uint64(i), 666666, x)

		res[i*4] = uint32(h1)
		res[i*4+1] = uint32(h1 >> 32)
		res[i*4+2] = uint32(h2)
		res[i*4+3] = uint32(h2 >> 32)
	}

	return res[:nhash]
}

func (f *Filter) test(bit uint32) bool {
	i := bit / 8
	return f.data[i]&(1<<(bit%8)) != 0
}

func (f *Filter) set(bit uint32) {
	i := bit / 8
	f.data[i] |= 1 << (bit % 8)
}
