// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package mixnet

import (
	"crypto/rand"
	"net"
	"net/rpc"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ed25519"
)

type mixer struct{}

func (m *mixer) Service() string {
	return "TestMixer"
}

func (m *mixer) MessageSize() int {
	return 1
}
func (m *mixer) FillWithNoise(dest [][]byte, noiseCounts []uint32, nextKeys []*[32]byte) {
	return
}
func (m *mixer) SortMessages(messages [][]byte) (mailboxes map[string][]byte) {
	return nil
}

// Test that the entry server can only access the NewRound and
// SetRoundSettings RPCs, but not Add or Close.
func TestAccessControl(t *testing.T) {
	_, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	mixServer := &Server{
		SigningKey: serverKey,
		NumServers: 1,
		Mixer:      new(mixer),
	}
	coordinatorService := &CoordinatorService{mixServer}
	chainService := &ChainService{mixServer}

	typ := reflect.TypeOf(coordinatorService)
	if typ.NumMethod() != 2 {
		t.Fatalf("CoordinatorService type should have 2 methods, but it has %d", typ.NumMethod())
	}

	client, server := net.Pipe()

	rpcServer := new(rpc.Server)
	if err := rpcServer.RegisterName("AddFriendCoordinator", coordinatorService); err != nil {
		t.Fatalf("rpc.Register: %s", err)
	}
	if err := rpcServer.RegisterName("AddFriendChain", chainService); err != nil {
		t.Fatalf("rpc.Register: %s", err)
	}
	go rpcServer.ServeConn(server)

	rpcClient := rpc.NewClient(client)

	settings := &RoundSettings{
		Round: 1,
	}

	{
		args := &NewRoundArgs{
			Round: 1,
		}
		reply := new(NewRoundReply)
		err := rpcClient.Call("AddFriendCoordinator.NewRound", args, reply)
		if err != nil {
			t.Fatalf("AddFriend.NewRound: %s", err)
		}
		settings.OnionKeys = []*[32]byte{reply.OnionKey}
	}

	{
		reply := new(SetRoundSettingsReply)
		err := rpcClient.Call("AddFriendCoordinator.SetRoundSettings", settings, reply)
		if err != nil {
			t.Fatalf("AddFriend.SetRoundSettings: %s", err)
		}
	}

	{
		args := new(AddArgs)
		err := rpcClient.Call("AddFriendCoordinator.Add", args, nil)
		if err == nil {
			t.Fatalf("entry server should not have access to Add RPC")
		}
		if !strings.Contains(err.Error(), "can't find method AddFriendCoordinator.Add") {
			t.Fatalf("unexpected error from AddFriend.Add RPC: %s", err)
		}
	}

	{
		args := &AddArgs{
			Round: 1,
		}
		err := rpcClient.Call("AddFriendChain.Add", args, nil)
		if err != nil {
			t.Fatalf("AddFriendChain.Add: %s", err)
		}
	}
}
