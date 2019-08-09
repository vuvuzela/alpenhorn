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

	"github.com/dgraph-io/badger"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/edhttp"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/alpenhorn/pkg"
	"vuvuzela.io/crypto/ibe"
	"vuvuzela.io/internal/mock"
)

func launchPKG(t *testing.T, regTokenHandler pkg.RegTokenHandler) (*mock.PKG, *pkg.CoordinatorClient) {
	coordinatorPub, coordinatorPriv, _ := ed25519.GenerateKey(rand.Reader)
	testpkg, err := mock.LaunchPKG(coordinatorPub, regTokenHandler)
	if err != nil {
		t.Fatalf("error launching PKG: %s", err)
	}

	coordinatorClient := &pkg.CoordinatorClient{
		CoordinatorKey: coordinatorPriv,
	}

	return testpkg, coordinatorClient
}

func TestSingleClient(t *testing.T) {
	testpkg, coordinatorClient := launchPKG(t, func(username string, token string) error {
		if token == "valid token" {
			return nil
		}
		return pkg.Error{Code: pkg.ErrInvalidToken}
	})
	defer testpkg.Close()

	aliceUsername := "alice@example.org"
	alicePub, alicePriv, _ := ed25519.GenerateKey(rand.Reader)
	client := &pkg.Client{
		Username:        aliceUsername,
		LoginKey:        alicePriv,
		UserLongTermKey: alicePub,
		HTTPClient:      new(edhttp.Client),
	}

	err := client.Register(testpkg.PublicServerConfig, "wrong token")
	if err.(pkg.Error).Code != pkg.ErrInvalidToken {
		t.Fatal(err)
	}

	err = client.Register(testpkg.PublicServerConfig, "valid token")
	if err != nil {
		t.Fatal(err)
	}

	err = client.Register(testpkg.PublicServerConfig, "valid token")
	if err.(pkg.Error).Code != pkg.ErrAlreadyRegistered {
		t.Fatal(err)
	}

	err = client.CheckStatus(testpkg.PublicServerConfig)
	if err != nil {
		t.Fatal(err)
	}

	aliceLog, err := testpkg.PKGServer.GetUserLog(pkg.ValidUsernameToIdentity(aliceUsername))
	if err != nil {
		t.Fatal(err)
	}
	if len(aliceLog) != 1 {
		t.Fatalf("unexpected user log: %#v", aliceLog)
	}
	if aliceLog[0].Type != pkg.EventRegistered {
		t.Fatalf("unexpected user log: %#v", aliceLog)
	}
	if !bytes.Equal(aliceLog[0].LoginKey, alicePub) {
		t.Fatalf("unexpected user log: %#v", aliceLog)
	}

	_, err = testpkg.PKGServer.GetUserLog(pkg.ValidUsernameToIdentity("nonexistent"))
	if err != badger.ErrKeyNotFound {
		t.Fatal(err)
	}

	usernames, err := testpkg.PKGServer.RegisteredUsernames()
	if err != nil {
		t.Fatal(err)
	}
	if !(len(usernames) == 1 && bytes.Equal(usernames[0][:], pkg.ValidUsernameToIdentity(aliceUsername)[:])) {
		t.Fatalf("unexpected registered usernames: %v", usernames)
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

	result1, err := client.Extract(testpkg.PublicServerConfig, 42)
	if err != nil {
		t.Fatal(err)
	}
	result2, err := client.Extract(testpkg.PublicServerConfig, 42)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(marshal(result1.PrivateKey), marshal(result2.PrivateKey)) {
		t.Fatalf("ibe private key differs across calls to extract")
	}

	_, err = client.Extract(testpkg.PublicServerConfig, 40)
	if err.(pkg.Error).Code != pkg.ErrRoundNotFound {
		t.Fatal(err)
	}

	masterKey := revealReply.MasterPublicKey
	aliceID, _ := pkg.UsernameToIdentity(aliceUsername)
	encintro := ibe.Encrypt(rand.Reader, masterKey, aliceID[:], []byte("Hello Alice!"))
	intro, ok := ibe.Decrypt(result1.PrivateKey, encintro)
	if !ok {
		t.Fatal("failed to decrypt ibe ciphertext")
	}
	if !bytes.Equal(intro, []byte("Hello Alice!")) {
		t.Fatal("messages don't match")
	}
}

func TestManyClients(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	testpkg, coordinatorClient := launchPKG(t, func(username string, token string) error {
		return nil
	})
	defer testpkg.Close()

	numThreads := 4
	usersPerThread := 1000
	clients := make([]*pkg.Client, numThreads*usersPerThread)
	for thread := 0; thread < numThreads; thread++ {
		for i := 0; i < usersPerThread; i++ {
			userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
			clients[thread*usersPerThread+i] = &pkg.Client{
				Username:        fmt.Sprintf("%dthread%d@example.org", i, thread),
				LoginKey:        userPriv,
				UserLongTermKey: userPub,
				HTTPClient:      new(edhttp.Client),
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
				err := client.Register(testpkg.PublicServerConfig, "token")
				if err != nil {
					log.Panicf("client register: %s", err)
				}
			}
			wg.Done()
		}(thread)
	}
	wg.Wait()
	end := time.Now()
	totalUsers := numThreads * usersPerThread
	t.Logf("Registered %d users in %s", totalUsers, end.Sub(start))

	usernames, err := testpkg.PKGServer.RegisteredUsernames()
	if err != nil {
		t.Fatal(err)
	}
	if len(usernames) != totalUsers {
		t.Fatalf("unexpected number of registered users: got %d, want %d", len(usernames), totalUsers)
	}

	pkgs := []pkg.PublicServerConfig{testpkg.PublicServerConfig}
	_, err = coordinatorClient.NewRound(pkgs, 42)
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
				reply, err := client.Extract(testpkg.PublicServerConfig, 42)
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
