// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package guardian

import (
	"crypto/ed25519"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
)

func Appdir() string {
	u, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	return filepath.Join(u.HomeDir, ".alpenhorn")
}

func DeriveKey(passphrase []byte) []byte {
	dk, err := scrypt.Key(passphrase, []byte("alpenhorn-guardian"), 2<<15, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	return dk
}

const nonceOverhead = 24

func ReadPrivateKey(path string) ed25519.PrivateKey {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	bs, err := base32.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		log.Fatalf("error decoding base32: %s: %s", path, err)
	}

	expectedSize := nonceOverhead + ed25519.PrivateKeySize + secretbox.Overhead
	if len(bs) != expectedSize {
		log.Fatalf("unexpected key length: got %d bytes, want %d", len(bs), expectedSize)
	}

	var nonce [24]byte
	copy(nonce[:], bs[0:24])
	ctxt := bs[24:]

	for {
		fmt.Fprintf(os.Stderr, "Enter passphrase for guardian key: ")
		pw, err := terminal.ReadPassword(0)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			log.Fatalf("terminal.ReadPassword: %s", err)
		}

		dk := DeriveKey(pw)
		var boxKey [32]byte
		copy(boxKey[:], dk)

		msg, ok := secretbox.Open(nil, ctxt, &nonce, &boxKey)
		if ok {
			privateKey := ed25519.PrivateKey(msg)
			return privateKey
		}
		fmt.Fprintln(os.Stderr, "Wrong passphrase. Try again.")
	}
}
