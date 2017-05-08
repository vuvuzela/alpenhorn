package debug

import (
	"reflect"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"github.com/kylelemons/godebug/pretty"
)

func init() {
	pretty.DefaultFormatter[reflect.TypeOf([]byte{})] = func(data []byte) string {
		return "\"" + base32.EncodeToString(data) + "\""
	}
	pretty.DefaultFormatter[reflect.TypeOf([32]byte{})] = func(data [32]byte) string {
		return "\"" + base32.EncodeToString(data[:]) + "\""
	}
}

func Pretty(v interface{}) string {
	return pretty.Sprint(v)
}
