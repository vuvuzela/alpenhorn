// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pkg

import (
	"encoding/binary"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/errors"
)

var (
	dbUserPrefix         = []byte("user:")
	registrationSuffix   = []byte(":registration")
	lastExtractionSuffix = []byte(":lastextract")
)

func dbUserKey(identity *[64]byte, suffix []byte) []byte {
	return append(append(dbUserPrefix, identity[:]...), suffix...)
}

type userState struct {
	Verified bool
	LoginKey ed25519.PublicKey

	TokenExpires      int64
	VerificationToken *[32]byte
}

const userStateBinaryVersion byte = 1

func (u userState) Marshal() []byte {
	if u.Verified {
		data := make([]byte, 2+ed25519.PublicKeySize)
		data[0] = userStateBinaryVersion
		data[1] = 1
		copy(data[2:34], u.LoginKey)
		return data
	}

	data := make([]byte, 2+ed25519.PublicKeySize+8+32)
	data[0] = userStateBinaryVersion
	data[1] = 0
	copy(data[2:34], u.LoginKey)
	binary.BigEndian.PutUint64(data[34:42], uint64(u.TokenExpires))
	copy(data[42:74], u.VerificationToken[:])

	return data
}

func (u *userState) Unmarshal(data []byte) error {
	if len(data) < 34 {
		return errors.New("short data: got %d bytes", len(data))
	}
	if data[0] != userStateBinaryVersion {
		return errors.New("userStateBinaryVersion mismatch: got %v, want %v", data[0], userStateBinaryVersion)
	}
	switch data[1] {
	case 0:
		u.Verified = false
	case 1:
		u.Verified = true
	default:
		return errors.New("unexpected verified byte: %v", data[1])
	}
	u.LoginKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(u.LoginKey, data[2:34])

	data = data[34:]
	if u.Verified && len(data) == 0 {
		return nil
	} else if u.Verified {
		return errors.New("unexpected extra data: %v", data)
	}

	if len(data) != 8+32 {
		return errors.New("short data: got %d bytes", 34+len(data))
	}
	u.TokenExpires = int64(binary.BigEndian.Uint64(data[0:8]))
	if u.TokenExpires < 0 {
		return errors.New("unexpected token expiration: %v", u.TokenExpires)
	}
	u.VerificationToken = new([32]byte)
	copy(u.VerificationToken[:], data[8:40])
	return nil
}

type lastExtraction struct {
	Round    uint32
	UnixTime int64
}

const lastExtractionBinaryVersion byte = 1

func (e lastExtraction) size() int {
	return 1 + 4 + 8
}

func (e lastExtraction) Marshal() []byte {
	data := make([]byte, e.size())
	data[0] = lastExtractionBinaryVersion
	binary.BigEndian.PutUint32(data[1:5], e.Round)
	binary.BigEndian.PutUint64(data[5:], uint64(e.UnixTime))
	return data
}

func (e *lastExtraction) Unmarshal(data []byte) error {
	if len(data) != e.size() {
		return errors.New("bad data length: got %d, want %d", len(data), e.size())
	}
	if data[0] != lastExtractionBinaryVersion {
		return errors.New("unexpected binary version: %v", data[0])
	}
	e.Round = binary.BigEndian.Uint32(data[1:5])
	e.UnixTime = int64(binary.BigEndian.Uint64(data[5:]))
	return nil
}
