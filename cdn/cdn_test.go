// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package cdn

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/davidlazar/go-crypto/encoding/base32"

	"vuvuzela.io/alpenhorn/edtls"
)

func TestCDN(t *testing.T) {
	coordinatorPub, coordinatorPriv, _ := ed25519.GenerateKey(rand.Reader)
	cdnPub, cdnPriv, _ := ed25519.GenerateKey(rand.Reader)

	dir, err := ioutil.TempDir("", "TestCDN")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	defaultTTL = 1 * time.Second
	deleteExpiredTickRate = 1 * time.Second

	dbPath := filepath.Join(dir, "cdn.db")
	cdn, err := New(dbPath, coordinatorPub)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := edtls.Listen("tcp", "127.0.0.1:8080", cdnPriv)
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(listener, cdn)

	data := make(map[string][]byte)
	data["1"] = []byte("hello")
	data["2"] = []byte("world")

	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(data); err != nil {
		t.Fatal(err)
	}

	{
		client := &http.Client{
			Transport: &http.Transport{
				DialTLS: func(network, addr string) (net.Conn, error) {
					return edtls.Dial(network, addr, cdnPub, coordinatorPriv)
				},
			},
		}
		nbURL := fmt.Sprintf("https://%s/newbucket?bucket=%s&uploader=%s", "127.0.0.1:8080", "foo/42", base32.EncodeToString(coordinatorPub))
		resp, err := client.Post(nbURL, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			msg, _ := ioutil.ReadAll(resp.Body)
			t.Fatalf("newbucket failed: %s: %s", resp.Status, msg)
		}
		resp, err = client.Post("https://127.0.0.1:8080/put?bucket=foo/42", "", buf)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("bad response status: %s; body = %q", resp.Status, body)
		}
	}

	{
		client := &http.Client{
			Transport: &http.Transport{
				DialTLS: func(network, addr string) (net.Conn, error) {
					return edtls.Dial(network, addr, cdnPub, nil)
				},
			},
		}
		resp, err := client.Get("https://127.0.0.1:8080/get?bucket=foo/42&key=2")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("bad response status: %s; body = %q", resp.Status, body)
		}
		if !bytes.Equal(body, data["2"]) {
			t.Fatalf("got %q, want %q", body, data["2"])
		}
	}

	{
		time.Sleep(2 * time.Second)
		client := &http.Client{
			Transport: &http.Transport{
				DialTLS: func(network, addr string) (net.Conn, error) {
					return edtls.Dial(network, addr, cdnPub, nil)
				},
			},
		}
		resp, err := client.Get("https://127.0.0.1:8080/get?bucket=foo/42&key=2")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404 not found, got %s", resp.Status)
		}
	}
}
