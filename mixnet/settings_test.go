// Copyright 2017 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package mixnet

import (
	"crypto/rand"
	"reflect"
	"testing"

	"vuvuzela.io/alpenhorn/internal/debug"
)

func TestSettingsRoundTrip(t *testing.T) {
	settings := &RoundSettings{
		Service:      "AddFriend",
		Round:        424041,
		NumMailboxes: 4,
		OnionKeys:    make([]*[32]byte, 3),
	}
	for i := range settings.OnionKeys {
		key := new([32]byte)
		rand.Read(key[:])
		settings.OnionKeys[i] = key
	}

	pb := settings.Proto()
	s2 := new(RoundSettings)

	err := s2.FromProto(pb)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(settings, s2) {
		t.Fatalf("settings differ:\n%s\n%s\n", debug.Pretty(settings), debug.Pretty(s2))
	}
}
