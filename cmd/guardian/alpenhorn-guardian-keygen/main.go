// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh/terminal"

	"vuvuzela.io/alpenhorn/cmd/guardian"
)

var inspirationalMessage = `
!! You are generating an Alpenhorn guardian key.
!! This key is crucial to the security of Alpenhorn.
!! Millions of users are counting on you. Pick a STRONG passphrase.

`

func main() {
	appDir := guardian.Appdir()
	err := os.Mkdir(appDir, 0700)
	if err == nil {
		fmt.Printf("Created directory %s\n", appDir)
	} else if !os.IsExist(err) {
		log.Fatal(err)
	}

	privatePath := filepath.Join(appDir, "guardian.privatekey")
	publicPath := filepath.Join(appDir, "guardian.publickey")
	checkOverwrite(privatePath)
	checkOverwrite(publicPath)

	fmt.Fprintf(os.Stdout, inspirationalMessage)
	pw := confirmPassphrase()
	fmt.Println()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	dk := guardian.DeriveKey(pw)
	var boxKey [32]byte
	copy(boxKey[:], dk)
	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	if err != nil {
		panic(err)
	}
	msg := privateKey[:]
	ctxt := secretbox.Seal(nonce[:], msg, &nonce, &boxKey)

	err = ioutil.WriteFile(publicPath, []byte(base32.EncodeToString(publicKey[:])+"\n"), 0600)
	if err != nil {
		log.Fatalf("failed to write public key: %s", err)
	}
	fmt.Printf("Wrote public key: %s\n", publicPath)

	err = ioutil.WriteFile(privatePath, []byte(base32.EncodeToString(ctxt)+"\n"), 0600)
	if err != nil {
		log.Fatalf("failed to write private key: %s", err)
	}
	fmt.Printf("Wrote private key: %s\n", privatePath)

	fmt.Printf("\n!! You should make a backup of the private key before sharing the public key.\n")
}

func confirmPassphrase() []byte {
	for {
		fmt.Fprintf(os.Stderr, "Enter passphrase: ")
		pw, err := terminal.ReadPassword(0)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			log.Fatalf("terminal.ReadPassword: %s", err)
		}

		if len(pw) == 0 {
			continue
		}

		fmt.Fprintf(os.Stderr, "Enter same passphrase again: ")
		again, err := terminal.ReadPassword(0)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			log.Fatalf("terminal.ReadPassword: %s", err)
		}

		if bytes.Equal(pw, again) {
			return pw
		}

		fmt.Fprintf(os.Stderr, "Passphrases do not match. Try again.\n")
	}
}

func checkOverwrite(path string) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s already exists. Refusing to overwrite.\n", path)
	os.Exit(1)
}
