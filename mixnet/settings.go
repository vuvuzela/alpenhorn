// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package mixnet

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"vuvuzela.io/alpenhorn/mixnet/mixnetpb"
)

type RoundSettings struct {
	// Service is the name of the mixnet service.
	Service string

	// Round is the round that these settings correspond to.
	Round uint32

	// NumMailboxes is the number of real mailboxes (excludes the dummy mailbox).
	NumMailboxes uint32

	// OnionKeys are the encryption keys in mixnet order.
	OnionKeys []*[32]byte
}

func (s RoundSettings) SigningMessage() []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("RoundSettings")
	buf.WriteString(s.Service)
	binary.Write(buf, binary.BigEndian, s.Round)
	binary.Write(buf, binary.BigEndian, s.NumMailboxes)
	for _, key := range s.OnionKeys {
		buf.Write(key[:])
	}
	return buf.Bytes()
}

func (s *RoundSettings) FromProto(pb *mixnetpb.RoundSettings) error {
	s.Service = pb.Service
	s.Round = pb.Round
	s.NumMailboxes = pb.NumMailboxes
	s.OnionKeys = make([]*[32]byte, len(pb.OnionKeys))
	for i := range s.OnionKeys {
		key := new([32]byte)
		n := copy(key[:], pb.OnionKeys[i])
		if n != 32 {
			return fmt.Errorf("wrong size for key %d: got %d, want %d", i, n, 32)
		}
		s.OnionKeys[i] = key
	}
	return nil
}

func (s RoundSettings) Proto() *mixnetpb.RoundSettings {
	pb := &mixnetpb.RoundSettings{
		Service:      s.Service,
		Round:        s.Round,
		NumMailboxes: s.NumMailboxes,
		OnionKeys:    make([][]byte, len(s.OnionKeys)),
	}
	for i, key := range s.OnionKeys {
		pb.OnionKeys[i] = key[:]
	}
	return pb
}
