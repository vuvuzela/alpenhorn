// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package addfriend provides functionality for Alpenhorn's add-friend protocol.
package addfriend

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"sync"
	"unsafe"

	"vuvuzela.io/alpenhorn/edhttp"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/concurrency"
	"vuvuzela.io/crypto/bn256"
	"vuvuzela.io/crypto/ibe"
	"vuvuzela.io/crypto/onionbox"
	"vuvuzela.io/crypto/rand"
	"vuvuzela.io/crypto/shuffle"
	"vuvuzela.io/vuvuzela/mixnet"
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
	SigningKey ed25519.PrivateKey

	Laplace rand.Laplace

	once      sync.Once
	cdnClient *edhttp.Client
}

func (srv *Mixer) Bidirectional() bool {
	return false
}

func (srv *Mixer) SizeIncomingMessage() int {
	return sizeMixMessage
}

func (srv *Mixer) SizeReplyMessage() int {
	return -1 // only used in bidirectional mode
}

type ServiceData struct {
	CDNKey       ed25519.PublicKey
	CDNAddress   string
	NumMailboxes uint32
}

const AddFriendServiceDataVersion = 0

func (srv *Mixer) ParseServiceData(data []byte) (interface{}, error) {
	d := new(ServiceData)
	err := d.Unmarshal(data)
	return d, err
}

func (srv *Mixer) GenerateNoise(settings mixnet.RoundSettings, myPos int) [][]byte {
	noiseTotal := uint32(0)
	noiseCounts := make([]uint32, settings.ServiceData.(*ServiceData).NumMailboxes+1)
	for b := range noiseCounts {
		bmu := srv.Laplace.Uint32()
		noiseCounts[b] = bmu
		noiseTotal += bmu
	}
	noise := make([][]byte, noiseTotal)

	mailbox := make([]uint32, len(noise))
	idx := 0
	for b, count := range noiseCounts {
		for i := uint32(0); i < count; i++ {
			mailbox[idx] = uint32(b)
			idx++
		}
	}

	nextServerKeys := settings.OnionKeys[myPos+1:]

	concurrency.ParallelFor(len(noise), func(p *concurrency.P) {
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
			onion, _ := onionbox.Seal(msg[:], mixnet.ForwardNonce(settings.Round), nextServerKeys)
			noise[i] = onion
		}
	})

	return noise
}

func (srv *Mixer) HandleMessages(settings mixnet.RoundSettings, messages [][]byte) (interface{}, error) {
	srv.once.Do(func() {
		srv.cdnClient = &edhttp.Client{
			Key: srv.SigningKey,
		}
	})

	serviceData := settings.ServiceData.(*ServiceData)

	// The last server doesn't shuffle by default, so shuffle here.
	shuffler := shuffle.New(rand.Reader, len(messages))
	shuffler.Shuffle(messages)

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

	buf := new(bytes.Buffer)
	err := gob.NewEncoder(buf).Encode(mailboxes)
	if err != nil {
		return "", errors.Wrap(err, "gob.Encode")
	}

	putURL := fmt.Sprintf("https://%s/put?bucket=%s/%d", serviceData.CDNAddress, settings.Service, settings.Round)
	resp, err := srv.cdnClient.Post(serviceData.CDNKey, putURL, "application/octet-stream", buf)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := ioutil.ReadAll(resp.Body)
		err = errors.New("bad CDN response: %s: %q", resp.Status, msg)
		return "", err
	}

	getURL := fmt.Sprintf("https://%s/get?bucket=%s/%d", serviceData.CDNAddress, settings.Service, settings.Round)
	return getURL, nil
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

func (d *ServiceData) Unmarshal(data []byte) error {
	if len(data) == 0 {
		return errors.New("empty raw service data")
	}
	if data[0] != AddFriendServiceDataVersion {
		return errors.New("invalid version: %d", data[0])
	}
	return json.Unmarshal(data[1:], d)
}

func (d ServiceData) Marshal() []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(AddFriendServiceDataVersion)
	err := json.NewEncoder(buf).Encode(d)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}
