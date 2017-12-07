package pkg

import (
	"crypto/rand"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"
)

func TestMarshalUserState(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)

	verifiedUser := userState{
		Verified: true,
		LoginKey: publicKey,
	}
	data := verifiedUser.Marshal()

	var verifiedUser2 userState
	if err := verifiedUser2.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(verifiedUser, verifiedUser2) {
		t.Fatalf("got %#v, want %#v", verifiedUser2, verifiedUser)
	}

	unverifiedUser := userState{
		Verified:          false,
		LoginKey:          publicKey,
		TokenExpires:      time.Now().Unix(),
		VerificationToken: new([32]byte),
	}
	rand.Read(unverifiedUser.VerificationToken[:])
	data = unverifiedUser.Marshal()

	var unverifiedUser2 userState
	if err := unverifiedUser2.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(unverifiedUser, unverifiedUser2) {
		t.Fatalf("got %#v, want %#v", unverifiedUser2, unverifiedUser)
	}
}

func TestMarshalLastExtraction(t *testing.T) {
	e := lastExtraction{
		Round:    12345,
		UnixTime: time.Now().Unix(),
	}
	data := e.Marshal()
	var e2 lastExtraction
	if err := e2.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e, e2) {
		t.Fatalf("after unmarshal: got %#v, want %#v", e2, e)
	}
}
