package edtls

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"
)

func TestServer(t *testing.T) {
	clientPublicKey, clientPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serverPublicKey, serverPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pipeClient, pipeServer := net.Pipe()

	var seen []byte
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer t.Logf("client done")
		defer pipeClient.Close()
		t.Logf("client new")
		conn, err := Client(pipeClient, serverPublicKey, clientPrivateKey)
		if err != nil {
			t.Error(err)
			return
		}
		t.Logf("client writing")
		if _, err := conn.Write([]byte("Greetings")); err != nil {
			t.Error(err)
			return
		}
		t.Logf("client closing")
		if err := conn.Close(); err != nil {
			t.Error(err)
			return
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer t.Logf("server done")
		defer pipeServer.Close()
		t.Logf("server new")
		conn, err := Server(pipeServer, serverPrivateKey)
		if err != nil {
			t.Error(err)
			return
		}
		if err := conn.Handshake(); err != nil {
			conn.Close()
			t.Error(err)
			return
		}
		state := conn.ConnectionState()
		if !state.HandshakeComplete {
			t.Error("TLS handshake did not complete")
			return
		}
		if len(state.PeerCertificates) == 0 {
			t.Error("no TLS peer certificates")
			return
		}
		t.Logf("server verifying")
		ok := Verify(clientPublicKey, state.PeerCertificates[0], time.Now())
		if !ok {
			t.Error("edtls verification failed")
			return
		}
		t.Logf("server reading")
		buf, err := ioutil.ReadAll(conn)
		if err != nil {
			t.Error(err)
			return
		}
		seen = buf
	}()

	wg.Wait()

	if seen == nil {
		t.Fatalf("did not pass greeting")
	}
	if g, e := string(seen), "Greetings"; g != e {
		t.Fatalf("greeting does not match: %q != %q", g, e)
	}
}

func TestExpiration(t *testing.T) {
	oldDuration := certDuration
	certDuration = 3 * time.Second
	defer func() {
		certDuration = oldDuration
	}()

	clientPublicKey, clientPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serverPublicKey, serverPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	l, err := Listen("tcp", "localhost:0", serverPrivateKey)
	go func() {
		for {
			rawConn, err := l.Accept()
			if err != nil {
				return
			}
			conn := rawConn.(*tls.Conn)

			if err := conn.Handshake(); err != nil {
				conn.Close()
				t.Fatalf("TLS handshake failed: %s", err)
			}
			state := conn.ConnectionState()
			if !state.HandshakeComplete {
				t.Fatalf("TLS handshake did not complete")
			}
			if len(state.PeerCertificates) == 0 {
				t.Fatalf("no peer certificates")
			}
			clientCert := state.PeerCertificates[0]

			ok := Verify(clientPublicKey, clientCert, time.Now())
			if !ok {
				t.Fatalf("edtls verification failed with key %q", base64.RawURLEncoding.EncodeToString(clientPublicKey))
			}

			go func(conn *tls.Conn) {
				i := 0
				buf := make([]byte, 4)
				for {
					n, err := conn.Read(buf)
					switch string(buf[:n]) {
					case "Ping":
						out := fmt.Sprintf("Pong%02d", i)
						if _, err := conn.Write([]byte(out)); err != nil {
							t.Fatalf("server write error: %s", err)
						}
						i++
					default:
						break
					}
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatalf("server read error: %s", err)
					}
				}
				conn.Close()
			}(conn)
		}
	}()

	// Confirm that we can keep talking to the server, even after
	// its certificate expires.
	done := make(chan struct{})
	go func() {
		conn, err := Dial("tcp", l.Addr().String(), serverPublicKey, clientPrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		buf := make([]byte, 6)
		for i := 0; i < 10; i++ {
			st := conn.ConnectionState()
			if len(st.PeerCertificates) != 1 {
				t.Fatalf("unexpected number of certificates: %d", len(st.PeerCertificates))
			}
			serverCert := st.PeerCertificates[0]
			if i >= 6 && !time.Now().After(serverCert.NotAfter) {
				t.Fatal("expected certificate to expire after 3 seconds")
			}

			if _, err := conn.Write([]byte("Ping")); err != nil {
				t.Fatalf("client write error: %s", err)
			}
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("client read error: %s", err)
			}
			expected := fmt.Sprintf("Pong%02d", i)
			if !bytes.Equal(buf[:n], []byte(expected)) {
				t.Fatalf("client got %q, want %q", buf[:n], expected)
			}
			time.Sleep(500 * time.Millisecond)
		}
		close(done)
	}()

	var firstSeenCert *x509.Certificate
	for i := 0; i < 5; i++ {
		conn, err := Dial("tcp", l.Addr().String(), serverPublicKey, clientPrivateKey)
		if err != nil {
			t.Fatalf("dial(%d) error: %s", i, err)
		}
		st := conn.ConnectionState()
		if len(st.PeerCertificates) != 1 {
			t.Fatalf("unexpected number of certificates: %d", len(st.PeerCertificates))
		}
		serverCert := st.PeerCertificates[0]
		if firstSeenCert == nil {
			firstSeenCert = serverCert
		} else {
			if serverCert.Equal(firstSeenCert) && i >= 2 {
				t.Fatalf("expected different cert after 2 seconds")
			}
		}
		if _, err := conn.Write([]byte("Ping")); err != nil {
			t.Fatalf("client write error: %s", err)
		}
		buf := make([]byte, 6)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("client read error: %s", err)
		}
		expected := "Pong00"
		if !bytes.Equal(buf[:n], []byte(expected)) {
			t.Fatalf("client got %q, want %q", buf[:n], expected)
		}
		conn.Close()
		time.Sleep(1 * time.Second)
	}

	<-done
}

func BenchmarkNewSelfSignedCert(b *testing.B) {
	_, serverPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		newSelfSignedCert(serverPrivateKey)
	}
}
