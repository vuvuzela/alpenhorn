// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package alpenhorn

import (
	"bytes"
	"encoding/binary"
	"unsafe"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/crypto/bls"
)

const (
	sizeIntro = int(unsafe.Sizeof(introduction{}))
)

type introduction struct {
	Username       [64]byte
	DHPublicKey    [32]byte
	DialingRound   uint32
	LongTermKey    [32]byte
	Signature      [64]byte
	ServerMultisig [32]byte
}

func (i *introduction) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, i); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (i *introduction) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)
	return binary.Read(buf, binary.BigEndian, i)
}

func (i *introduction) Verify(serverKeys []*bls.PublicKey) bool {
	longTermKey := ed25519.PublicKey(i.LongTermKey[:])

	msgs := make([][]byte, len(serverKeys))
	for j, key := range serverKeys {
		attestation := &pkg.Attestation{
			AttestKey:       key,
			UserIdentity:    &i.Username,
			UserLongTermKey: longTermKey,
		}
		msgs[j] = attestation.Marshal()
	}
	ok1 := bls.VerifyCompressed(serverKeys, msgs, &i.ServerMultisig)

	ok2 := ed25519.Verify(longTermKey, i.msg(), i.Signature[:])

	return ok1 && ok2
}

func (i *introduction) Sign(key ed25519.PrivateKey) {
	sig := ed25519.Sign(key, i.msg())
	copy(i.Signature[:], sig)
}

func (i *introduction) msg() []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("Introduction")
	buf.Write(i.Username[:])
	buf.Write(i.DHPublicKey[:])
	binary.Write(buf, binary.BigEndian, i.DialingRound)
	return buf.Bytes()
}
