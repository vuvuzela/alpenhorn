package edtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/errors"
)

func Listen(network, laddr string, key ed25519.PrivateKey) (net.Listener, error) {
	config := NewTLSServerConfig(key)

	return tls.Listen(network, laddr, config)
}

func Server(conn net.Conn, key ed25519.PrivateKey) *tls.Conn {
	config := NewTLSServerConfig(key)

	return tls.Server(conn, config)
}

func NewTLSServerConfig(key ed25519.PrivateKey) *tls.Config {
	var mu sync.Mutex
	var expiry time.Time
	var currCert *tls.Certificate

	var config = &tls.Config{
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			defer mu.Unlock()

			if currCert != nil && time.Now().Before(expiry) {
				return currCert, nil
			}

			certDER, certKey, err := newSelfSignedCert(key)
			if err != nil {
				return nil, fmt.Errorf("error generating self-signed certificate: %s", err)
			}

			currCert = &tls.Certificate{
				Certificate: [][]byte{certDER},
				PrivateKey:  certKey,
			}
			expiry = time.Now().Add(2 * certDuration / 3)
			return currCert, nil
		},

		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return nil
			}

			if len(rawCerts) != 1 {
				return errors.New("too many peer certificates: %d", len(rawCerts))
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return errors.Wrap(err, "x509.ParseCertificate")
			}

			_, ok := verify(cert, time.Now())
			if !ok {
				return ErrVerificationFailed
			}

			return nil
		},

		RootCAs:    x509.NewCertPool(),
		ClientAuth: tls.RequestClientCert,
		MinVersion: tls.VersionTLS12,
	}

	return config
}

var certDuration = 1 * time.Hour

func newSelfSignedCert(key ed25519.PrivateKey) ([]byte, *ecdsa.PrivateKey, error) {
	dsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// generate a self-signed cert
	now := time.Now()
	expiry := now.Add(certDuration)
	template := &x509.Certificate{
		SerialNumber: new(big.Int),
		NotBefore:    now.UTC().AddDate(0, 0, -1),
		NotAfter:     expiry.UTC(),

		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	if key != nil {
		if err := Vouch(key, template, &dsaKey.PublicKey); err != nil {
			return nil, nil, err
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &dsaKey.PublicKey, dsaKey)
	if err != nil {
		return nil, nil, err
	}

	return certDER, dsaKey, nil
}
