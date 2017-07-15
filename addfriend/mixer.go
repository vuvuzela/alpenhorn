// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package addfriend provides functionality for Alpenhorn's add-friend protocol.
package addfriend

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"unsafe"

	"vuvuzela.io/concurrency"
	"vuvuzela.io/crypto/bn256"
	"vuvuzela.io/crypto/ibe"
	"vuvuzela.io/crypto/onionbox"
	"vuvuzela.io/crypto/rand"
)

const (
	// SizeIntro is the size in bytes of an add-friend introduction.
	// This should be equal to int(unsafe.Sizeof(introduction{})) in
	// the alpenhorn package.
	SizeIntro = 228

	// SizeEncryptedIntro is the size of an encrypted introduction.
	SizeEncryptedIntro = SizeIntro + ibe.Overhead

	sizeMixMessage = int(unsafe.Sizeof(MixMessage{}))
)

type MixMessage struct {
	Mailbox        uint32
	EncryptedIntro [SizeEncryptedIntro]byte
}

type Mixer struct {
	Laplace rand.Laplace
}

func (srv *Mixer) MessageSize() int {
	return sizeMixMessage
}

func (srv *Mixer) NoiseCount() uint32 {
	return srv.Laplace.Uint32()
}

var zeroNonce = new([24]byte)

func (srv *Mixer) FillWithNoise(dest [][]byte, noiseCounts []uint32, nextKeys []*[32]byte) {
	mailbox := make([]uint32, len(dest))
	idx := 0
	for b, count := range noiseCounts {
		for i := uint32(0); i < count; i++ {
			mailbox[idx] = uint32(b)
			idx++
		}
	}

	concurrency.ParallelFor(len(dest), func(p *concurrency.P) {
		for i, ok := p.Next(); ok; i, ok = p.Next() {
			var msg [sizeMixMessage]byte
			binary.BigEndian.PutUint32(msg[0:4], mailbox[i])
			if mailbox[i] != 0 {
				// generate a valid-looking ciphertext
				encintro := msg[4:]
				rand.Read(encintro)
				g1 := new(bn256.G1).HashToPoint(encintro[:32])
				copy(encintro, g1.Marshal())
			}
			onion, _ := onionbox.Seal(msg[:], zeroNonce, nextKeys)
			dest[i] = onion
		}
	})
}

func (srv *Mixer) SortMessages(messages [][]byte) map[string][]byte {
	mailboxes := make(map[string][]byte)

	mx := new(MixMessage)
	for _, m := range messages {
		if len(m) != sizeMixMessage {
			continue
		}
		if err := mx.UnmarshalBinary(m); err != nil {
			continue
		}
		if mx.Mailbox == 0 {
			continue // dummy dead drop
		}
		mstr := strconv.FormatUint(uint64(mx.Mailbox), 10)
		mailboxes[mstr] = append(mailboxes[mstr], mx.EncryptedIntro[:]...)
	}

	return mailboxes
}

func (m *MixMessage) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (m *MixMessage) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)
	return binary.Read(buf, binary.BigEndian, m)
}
