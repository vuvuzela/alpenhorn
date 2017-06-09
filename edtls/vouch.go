package edtls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"time"

	"golang.org/x/crypto/ed25519"
)

// generated with a reimplementation of
// https://gallery.technet.microsoft.com/scriptcenter/56b78004-40d0-41cf-b95e-6e795b2e8a06
// via http://msdn.microsoft.com/en-us/library/ms677620(VS.85).aspx
var oid = asn1.ObjectIdentifier{1, 2, 840, 113556, 1, 8000, 2554, 31830, 5190, 18203, 20240, 41147, 7688498, 2373901}

const prefix = "vouch-tls\n"

// Vouch a self-signed certificate that is about to be created with an Ed25519 signature.
func Vouch(signPriv ed25519.PrivateKey, cert *x509.Certificate, tlsPub interface{}) error {
	// note: this is so early the cert is not serialized yet, can't use those fields
	tlsPubDer, err := x509.MarshalPKIXPublicKey(tlsPub)
	if err != nil {
		return err
	}
	msg := make([]byte, 0, len(prefix)+8+len(tlsPubDer))
	msg = append(msg, prefix...)
	var timestamp [8]byte
	binary.LittleEndian.PutUint64(timestamp[:], uint64(cert.NotAfter.Unix()))
	msg = append(msg, timestamp[:]...)
	msg = append(msg, tlsPubDer...)

	sig := ed25519.Sign(signPriv, msg)
	// Including the ed25519 public key in the cert is useful for client certificates
	val := append(signPriv.Public().(ed25519.PublicKey), sig...)
	ext := pkix.Extension{Id: oid, Value: val}
	cert.ExtraExtensions = append(cert.ExtraExtensions, ext)
	return nil
}

func findSig(cert *x509.Certificate) (key ed25519.PublicKey, sig []byte) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oid) {
			continue
		}
		if len(ext.Value) != ed25519.PublicKeySize+ed25519.SignatureSize {
			continue
		}
		key = ed25519.PublicKey(ext.Value[0:ed25519.PublicKeySize])
		sig = ext.Value[ed25519.PublicKeySize:]
		return
	}
	return
}

func GetSigningKey(cert *x509.Certificate) ed25519.PublicKey {
	key, _ := findSig(cert)
	return key
}

// Verify a vouch as offered by the TLS peer.
// Returns false if cert has expired relative to now.
func verify(cert *x509.Certificate, now time.Time) (ed25519.PublicKey, bool) {
	key, sig := findSig(cert)
	if sig == nil {
		return nil, false
	}

	if now.After(cert.NotAfter) {
		return nil, false
	}

	tlsPubDer, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, false
	}
	msg := make([]byte, 0, len(prefix)+8+len(tlsPubDer))
	msg = append(msg, prefix...)
	var timestamp [8]byte
	binary.LittleEndian.PutUint64(timestamp[:], uint64(cert.NotAfter.Unix()))
	msg = append(msg, timestamp[:]...)
	msg = append(msg, tlsPubDer...)

	ok := ed25519.Verify(key, msg, sig[:])
	if ok {
		return key, true
	}
	return nil, false
}
