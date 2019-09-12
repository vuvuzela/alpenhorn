package edtls

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

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

			certDER, err := newSelfSignedCert(key)
			if err != nil {
				return nil, fmt.Errorf("error generating self-signed certificate: %s", err)
			}

			currCert = &tls.Certificate{
				Certificate: [][]byte{certDER},
				PrivateKey:  key,
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

			if err := cert.CheckSignatureFrom(cert); err != nil {
				return ErrVerificationFailed
			}

			return nil
		},

		RootCAs:    x509.NewCertPool(),
		ClientAuth: tls.RequestClientCert,
		MinVersion: tls.VersionTLS13,
	}

	return config
}

var certDuration = 1 * time.Hour

func newSelfSignedCert(key ed25519.PrivateKey) ([]byte, error) {
	// generate a self-signed cert
	now := time.Now()
	expiry := now.Add(certDuration)
	template := &x509.Certificate{
		SerialNumber: new(big.Int),
		NotBefore:    now.UTC().AddDate(0, 0, -1),
		NotAfter:     expiry.UTC(),

		BasicConstraintsValid: true,
		IsCA:                  true,

		KeyUsage: x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}

	return certDER, nil
}
