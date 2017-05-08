package edtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ed25519"
)

var (
	ErrNoPeerCertificates = errors.New("peer did not supply a certificate")
	ErrVerificationFailed = errors.New("failed to verify certificate")
)

func Dial(network, addr string, theirKey ed25519.PublicKey, myKey ed25519.PrivateKey) (*tls.Conn, error) {
	config, err := newTLSClientConfig(myKey)
	if err != nil {
		return nil, err
	}

	conn, err := tls.Dial(network, addr, config)
	if err != nil {
		return nil, err
	}

	s := conn.ConnectionState()
	if len(s.PeerCertificates) == 0 {
		// servers are not supposed to be able to do that
		_ = conn.Close()
		return nil, ErrNoPeerCertificates
	}

	ok := Verify(theirKey, s.PeerCertificates[0], time.Now())
	if !ok {
		_ = conn.Close()
		return nil, ErrVerificationFailed
	}

	return conn, nil
}

func Client(rawConn net.Conn, theirKey ed25519.PublicKey, myKey ed25519.PrivateKey) (*tls.Conn, error) {
	config, err := newTLSClientConfig(myKey)
	if err != nil {
		return nil, err
	}

	conn := tls.Client(rawConn, config)
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	s := conn.ConnectionState()
	if len(s.PeerCertificates) == 0 {
		// servers are not supposed to be able to do that
		_ = conn.Close()
		return nil, ErrNoPeerCertificates
	}

	ok := Verify(theirKey, s.PeerCertificates[0], time.Now())
	if !ok {
		_ = conn.Close()
		return nil, ErrVerificationFailed
	}

	return conn, nil
}

func newTLSClientConfig(key ed25519.PrivateKey) (*tls.Config, error) {
	var config = &tls.Config{
		RootCAs:            x509.NewCertPool(),
		ClientAuth:         tls.RequestClientCert,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}

	if key == nil {
		return config, nil
	}

	certDER, certKey, err := newSelfSignedCert(key)
	if err != nil {
		return nil, fmt.Errorf("error generating self-signed certificate: %s", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  certKey,
	}
	config.Certificates = []tls.Certificate{cert}

	return config, nil
}
