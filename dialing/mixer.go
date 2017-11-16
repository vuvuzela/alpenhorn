// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package dialing provides functionality for Alpenhorn's dialing protocol.
package dialing

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"unsafe"

	"vuvuzela.io/alpenhorn/bloom"
	"vuvuzela.io/concurrency"
	"vuvuzela.io/crypto/onionbox"
	"vuvuzela.io/crypto/rand"
)

const (
	// SizeToken is the number of bytes in a dialing token.
	SizeToken = 32

	sizeMixMessage = int(unsafe.Sizeof(MixMessage{}))
)

type MixMessage struct {
	Mailbox uint32
	Token   [SizeToken]byte
}

type Mixer struct {
	Laplace rand.Laplace
}

func (srv *Mixer) MessageSize() int {
	return sizeMixMessage
}

func (srv *Mixer) NoiseDistribution() rand.Laplace {
	return srv.Laplace
}

var zeroNonce = new([24]byte)

func (srv *Mixer) FillWithNoise(dest [][]byte, noiseCounts []uint32, nextKeys []*[32]byte) {
	bucket := make([]uint32, len(dest))
	idx := 0
	for b, count := range noiseCounts {
		for i := uint32(0); i < count; i++ {
			bucket[idx] = uint32(b)
			idx++
		}
	}

	concurrency.ParallelFor(len(dest), func(p *concurrency.P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			var exchange [sizeMixMessage]byte
			binary.BigEndian.PutUint32(exchange[0:4], bucket[i])
			if bucket[i] != 0 {
				rand.Read(exchange[4:])
			}
			onion, _ := onionbox.Seal(exchange[:], zeroNonce, nextKeys)
			dest[i] = onion
		}
	})
}

func (srv *Mixer) SortMessages(messages [][]byte) map[string][]byte {
	groups := make(map[uint32][][]byte)

	for _, m := range messages {
		if len(m) != sizeMixMessage {
			continue
		}
		mx := new(MixMessage)
		if err := mx.UnmarshalBinary(m); err != nil {
			continue
		}
		if mx.Mailbox == 0 {
			continue // dummy dead drop
		}
		groups[mx.Mailbox] = append(groups[mx.Mailbox], mx.Token[:])
	}

	mailboxes := make(map[string][]byte)
	for mbox, tokens := range groups {
		f := bloom.New(bloom.Optimal(len(tokens), 0.00001))
		for _, token := range tokens {
			f.Set(token)
		}
		mstr := strconv.FormatUint(uint64(mbox), 10)
		mailboxes[mstr], _ = f.MarshalBinary()
	}
	return mailboxes
}

func (e *MixMessage) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, e); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (e *MixMessage) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)
	return binary.Read(buf, binary.BigEndian, e)
}
