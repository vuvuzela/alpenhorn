// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package pkg_test

import (
	"bytes"
	"crypto/rand"
	"encoding"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/internal/mock"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/crypto/ibe"
)

func launchPKG(t *testing.T, sendMail pkg.SendMailHandler) (*mock.PKG, *pkg.CoordinatorClient) {
	coordinatorPub, coordinatorPriv, _ := ed25519.GenerateKey(rand.Reader)
	testpkg, err := mock.LaunchPKG(coordinatorPub, sendMail)
	if err != nil {
		t.Fatalf("error launching PKG: %s", err)
	}

	coordinatorClient := &pkg.CoordinatorClient{
		CoordinatorKey: coordinatorPriv,
	}

	return testpkg, coordinatorClient
}

func TestSingleClient(t *testing.T) {
	type msg struct {
		to    string
		token []byte
	}
	emailPipe := make(chan msg, 1)

	testpkg, coordinatorClient := launchPKG(t, func(to string, token []byte) error {
		emailPipe <- msg{to, token}
		return nil
	})
	defer testpkg.Close()

	alicePub, alicePriv, _ := ed25519.GenerateKey(rand.Reader)
	client := &pkg.Client{
		PublicServerConfig: testpkg.PublicServerConfig,
		Username:           "alice@example.org",
		LoginKey:           alicePriv,
		UserLongTermKey:    alicePub,
	}

	err := client.Register()
	if err != nil {
		t.Fatal(err)
	}

	err = client.Register()
	if err.(pkg.Error).Code != pkg.ErrRegistrationInProgress {
		t.Fatal(err)
	}

	err = client.Verify([]byte("wrong token"))
	if err.(pkg.Error).Code != pkg.ErrInvalidToken {
		t.Fatal(err)
	}

	email := <-emailPipe

	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	client.LoginKey = otherPriv
	err = client.Verify(email.token)
	if err.(pkg.Error).Code != pkg.ErrInvalidSignature {
		t.Fatal(err)
	}

	client.LoginKey = alicePriv
	err = client.Verify(email.token)
	if err != nil {
		t.Fatal(err)
	}

	err = client.Register()
	if err.(pkg.Error).Code != pkg.ErrAlreadyRegistered {
		t.Fatal(err)
	}

	err = client.CheckStatus()
	if err != nil {
		t.Fatal(err)
	}

	pkgs := []pkg.PublicServerConfig{testpkg.PublicServerConfig}
	pkgSettings, err := coordinatorClient.NewRound(pkgs, 42)
	if err != nil {
		t.Fatal(err)
	}
	ok := pkgSettings.Verify(42, []ed25519.PublicKey{testpkg.Key})
	if !ok {
		t.Fatal("failed to verify pkg settings")
	}
	revealReply := pkgSettings[hex.EncodeToString(testpkg.Key)]

	result1, err := client.Extract(42)
	if err != nil {
		t.Fatal(err)
	}
	result2, err := client.Extract(42)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(marshal(result1.PrivateKey), marshal(result2.PrivateKey)) {
		t.Fatalf("ibe private key differs across calls to extract")
	}

	_, err = client.Extract(40)
	if err.(pkg.Error).Code != pkg.ErrRoundNotFound {
		t.Fatal(err)
	}

	masterKey := revealReply.MasterPublicKey
	aliceID, _ := pkg.UsernameToIdentity("alice@example.org")
	encintro := ibe.Encrypt(rand.Reader, masterKey, aliceID[:], []byte("Hello Alice!"))
	intro, ok := ibe.Decrypt(result1.PrivateKey, encintro)
	if !ok {
		t.Fatal("failed to decrypt ibe ciphertext")
	}
	if !bytes.Equal(intro, []byte("Hello Alice!")) {
		t.Fatal("messages don't match")
	}
}

func TestRegisterFirstComeFirstServe(t *testing.T) {
	testpkg, coordinatorClient := launchPKG(t, nil)
	defer testpkg.Close()

	alicePub, alicePriv, _ := ed25519.GenerateKey(rand.Reader)
	client := &pkg.Client{
		PublicServerConfig: testpkg.PublicServerConfig,
		Username:           "alice@example.org",
		LoginKey:           alicePriv,
		UserLongTermKey:    alicePub,
	}

	err := client.Register()
	if err != nil {
		t.Fatal(err)
	}

	err = client.Register()
	if err.(pkg.Error).Code != pkg.ErrAlreadyRegistered {
		t.Fatal(err)
	}

	pkgs := []pkg.PublicServerConfig{testpkg.PublicServerConfig}
	_, err = coordinatorClient.NewRound(pkgs, 42)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Extract(42)
	if err != nil {
		t.Fatal(err)
	}
}

func TestManyClients(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	testpkg, coordinatorClient := launchPKG(t, nil)
	defer testpkg.Close()

	numThreads := 10
	usersPerThread := 1000
	clients := make([]*pkg.Client, numThreads*usersPerThread)
	for thread := 0; thread < numThreads; thread++ {
		for i := 0; i < usersPerThread; i++ {
			userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
			clients[thread*usersPerThread+i] = &pkg.Client{
				PublicServerConfig: testpkg.PublicServerConfig,
				Username:           fmt.Sprintf("%d@thread%d", i, thread),
				LoginKey:           userPriv,
				UserLongTermKey:    userPub,
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(numThreads)
	start := time.Now()
	for thread := 0; thread < numThreads; thread++ {
		go func(thread int) {
			for i := 0; i < usersPerThread; i++ {
				client := clients[thread*usersPerThread+i]
				err := client.Register()
				if err != nil {
					t.Fatalf("client register: %s", err)
				}
			}
			wg.Done()
		}(thread)
	}
	wg.Wait()
	end := time.Now()
	t.Logf("Registered %d users in %s", numThreads*usersPerThread, end.Sub(start))

	pkgs := []pkg.PublicServerConfig{testpkg.PublicServerConfig}
	_, err := coordinatorClient.NewRound(pkgs, 42)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(1 * time.Second)

	wg.Add(numThreads)
	start = time.Now()
	for thread := 0; thread < numThreads; thread++ {
		go func(thread int) {
			for i := 0; i < usersPerThread; i++ {
				client := clients[thread*usersPerThread+i]
				reply, err := client.Extract(42)
				if err != nil {
					t.Fatalf("client extract: %s", err)
				}
				_ = reply
			}
			wg.Done()
		}(thread)
	}
	wg.Wait()
	end = time.Now()
	t.Logf("Extracted keys for %d users in %s", numThreads*usersPerThread, end.Sub(start))
}

func marshal(v encoding.BinaryMarshaler) []byte {
	data, err := v.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return data
}
