package debug

import (
	"reflect"

	"golang.org/x/crypto/ed25519"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"github.com/kylelemons/godebug/pretty"
)

func init() {
	pretty.DefaultFormatter[reflect.TypeOf([]byte{})] = prettyBytes
	pretty.DefaultFormatter[reflect.TypeOf(ed25519.PrivateKey{})] = prettyBytes
	pretty.DefaultFormatter[reflect.TypeOf(ed25519.PublicKey{})] = prettyBytes
	pretty.DefaultFormatter[reflect.TypeOf([32]byte{})] = func(data [32]byte) string {
		return prettyBytes(data[:])
	}
}

func prettyBytes(data []byte) string {
	return "\"" + base32.EncodeToString(data) + "\""
}

func Pretty(v interface{}) string {
	return pretty.Sprint(v)
}
