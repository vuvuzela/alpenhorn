// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package mixnet

import (
	"bytes"
	cryptoRand "crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"

	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/vrpc"
	"vuvuzela.io/concurrency"
	"vuvuzela.io/crypto/onionbox"
	"vuvuzela.io/crypto/rand"
	"vuvuzela.io/crypto/shuffle"
)

// A Mixer provides functionality needed by a mixnet Server.
type Mixer interface {
	// Service returns the name of this mix service (for example,
	// "AddFriend" or "Dialing"). This is used to distinguish
	// multiple mix servers listening on the same port.
	Service() string

	// MessageSize returns the expected size of messages in bytes
	// after the last onion layer is peeled.
	MessageSize() int

	// FillWithNoise generates noise to provide differential privacy.
	// noiseCounts specifies how much noise to add to each mailbox.
	FillWithNoise(dest [][]byte, noiseCounts []uint32, nextKeys []*[32]byte)

	// SortMessages sorts messages into mailboxes that are uploaded
	// to the CDN. It is called only by the last server in a chain.
	SortMessages(messages [][]byte) (mailboxes map[string][]byte)
}

type Server struct {
	Mixer Mixer

	SigningKey     ed25519.PrivateKey
	ServerPosition int // position in chain, starting at 0
	NumServers     int
	NextServer     *vrpc.Client
	CDNPublicKey   ed25519.PublicKey
	CDNAddr        string

	Laplace rand.Laplace

	roundsMu sync.RWMutex
	rounds   map[uint32]*roundState
}

type CoordinatorService struct {
	*Server
}

type ChainService struct {
	*Server
}

type roundState struct {
	mu                sync.Mutex
	closed            bool
	incoming          [][]byte
	settingsSignature []byte
	url               string
	err               error

	onionPrivateKey *[32]byte
	onionPublicKey  *[32]byte
	nextServerKeys  []*[32]byte
	numMailboxes    uint32

	noise     [][]byte
	noiseDone chan struct{}
}

func (srv *Server) getRound(round uint32) (*roundState, error) {
	var ok bool
	var st *roundState

	srv.roundsMu.RLock()
	if srv.rounds == nil {
		ok = false
	} else {
		st, ok = srv.rounds[round]
	}
	srv.roundsMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("round %d not found", round)
	}
	return st, nil
}

type NewRoundArgs struct {
	Round uint32
}

type NewRoundReply struct {
	OnionKey *[32]byte
}

func (srv *CoordinatorService) NewRound(args *NewRoundArgs, reply *NewRoundReply) error {
	log.WithFields(log.Fields{"service": srv.Mixer.Service(), "rpc": "NewRound", "round": args.Round}).Info()

	srv.roundsMu.Lock()
	if srv.rounds == nil {
		srv.rounds = make(map[uint32]*roundState)
	}
	st := srv.rounds[args.Round]
	srv.roundsMu.Unlock()

	if st != nil {
		reply.OnionKey = st.onionPublicKey
		return nil
	}

	public, private, err := box.GenerateKey(cryptoRand.Reader)
	if err != nil {
		return fmt.Errorf("box.GenerateKey error: %s", err)
	}

	st = &roundState{
		onionPublicKey:  public,
		onionPrivateKey: private,
	}

	srv.roundsMu.Lock()
	srv.rounds[args.Round] = st
	srv.roundsMu.Unlock()

	reply.OnionKey = public

	return nil
}

type RoundSettings struct {
	Round uint32
	// NumMailboxes is the number of real mailboxes (excludes the dummy mailbox).
	NumMailboxes uint32
	// OnionKeys are the encryption keys in mixnet order.
	OnionKeys []*[32]byte
}

func (r *RoundSettings) Sign(key ed25519.PrivateKey) []byte {
	return ed25519.Sign(key, r.msg())
}

func (r *RoundSettings) Verify(key ed25519.PublicKey, sig []byte) bool {
	return ed25519.Verify(key, r.msg(), sig)
}

func (r *RoundSettings) msg() []byte {
	buf := new(bytes.Buffer)
	buf.WriteString("RoundSettings")
	binary.Write(buf, binary.BigEndian, r.Round)
	binary.Write(buf, binary.BigEndian, r.NumMailboxes)
	for _, key := range r.OnionKeys {
		buf.Write(key[:])
	}
	return buf.Bytes()
}

type SetRoundSettingsReply struct {
	// Signature on RoundSettings
	Signature []byte
}

// SetRoundSettings is an RPC used by the coordinator to set the
// parameters for a round. The RPC returns a signature of the round
// settings. Clients must verify this signature from each server
// before participating in the round. This prevents dishonest servers
// from tricking clients and other servers into using different keys
// or a different number of mailboxes in a round (which can lead to
// distinguishable noise).
func (srv *CoordinatorService) SetRoundSettings(settings *RoundSettings, reply *SetRoundSettingsReply) error {
	log.WithFields(log.Fields{"service": srv.Mixer.Service(), "rpc": "SetRoundSettings", "round": settings.Round}).Info()

	st, err := srv.getRound(settings.Round)
	if err != nil {
		return err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if st.settingsSignature != nil {
		reply.Signature = st.settingsSignature
		// round settings have already been set
		return nil
	}

	if len(settings.OnionKeys) != srv.NumServers {
		return errors.New("bad round settings: want %d keys, got %d", srv.NumServers, len(settings.OnionKeys))
	}

	if !bytes.Equal(settings.OnionKeys[srv.ServerPosition][:], st.onionPublicKey[:]) {
		return errors.New("bad round settings: unexpected key at position %d", srv.ServerPosition)
	}

	st.settingsSignature = settings.Sign(srv.SigningKey)
	reply.Signature = st.settingsSignature

	st.numMailboxes = settings.NumMailboxes
	st.nextServerKeys = settings.OnionKeys[srv.ServerPosition+1:]
	st.noiseDone = make(chan struct{})

	// Now is a good time to start generating noise.
	go func() {
		// NOTE: unlike the convo protocol, the last server also adds noise
		noiseTotal := uint32(0)
		noiseCounts := make([]uint32, st.numMailboxes+1)
		for b := range noiseCounts {
			bmu := srv.Laplace.Uint32()
			noiseCounts[b] = bmu
			noiseTotal += bmu
		}
		st.noise = make([][]byte, noiseTotal)

		srv.Mixer.FillWithNoise(st.noise, noiseCounts, st.nextServerKeys)
		close(st.noiseDone)
	}()

	return nil
}

type AddArgs struct {
	Round  uint32
	Onions [][]byte
}

var zeroNonce = new([24]byte)

// Add is an RPC used to add onions to the mix.
func (srv *ChainService) Add(args *AddArgs, _ *struct{}) error {
	log.WithFields(log.Fields{"service": srv.Mixer.Service(), "rpc": "Add", "round": args.Round, "onions": len(args.Onions)}).Debug()

	st, err := srv.getRound(args.Round)
	if err != nil {
		return err
	}

	messages := make([][]byte, 0, len(args.Onions))
	expectedOnionSize := (srv.NumServers-srv.ServerPosition)*onionbox.Overhead + srv.Mixer.MessageSize()

	for _, onion := range args.Onions {
		if len(onion) == expectedOnionSize {
			var theirPublic [32]byte
			copy(theirPublic[:], onion[0:32])

			message, ok := box.Open(nil, onion[32:], zeroNonce, &theirPublic, st.onionPrivateKey)
			if ok {
				messages = append(messages, message)
			} else {
				log.WithFields(log.Fields{"service": srv.Mixer.Service(), "rpc": "Add", "round": args.Round}).Error("Decrypting onion failed")
			}
		}
	}

	st.mu.Lock()
	if !st.closed {
		st.incoming = append(st.incoming, messages...)
	} else {
		err = fmt.Errorf("round %d closed", args.Round)
	}
	st.mu.Unlock()

	return err
}

func (srv *Server) filterIncoming(st *roundState) {
	incomingValid := make([][]byte, 0, len(st.incoming))

	seen := make(map[uint64]bool)
	for _, msg := range st.incoming {
		// last 8 bytes because key is at the beginning
		msgkey := binary.BigEndian.Uint64(msg[len(msg)-8:])
		if !seen[msgkey] {
			seen[msgkey] = true
			incomingValid = append(incomingValid, msg)
		}
	}

	st.incoming = incomingValid
}

type CloseReply struct {
	URL string
}

func (srv *ChainService) Close(round uint32, reply *CloseReply) error {
	log.WithFields(log.Fields{"service": srv.Mixer.Service(), "rpc": "Close", "round": round}).Info()

	st, err := srv.getRound(round)
	if err != nil {
		return err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if st.closed {
		reply.URL = st.url
		return st.err
	}
	st.closed = true

	log.WithFields(log.Fields{
		"service": srv.Mixer.Service(),
		"rpc":     "Close",
		"round":   round,
		"onions":  len(st.incoming),
	}).Info()

	srv.filterIncoming(st)

	<-st.noiseDone
	st.incoming = append(st.incoming, st.noise...)

	shuffler := shuffle.New(rand.Reader, len(st.incoming))
	shuffler.Shuffle(st.incoming)

	url, err := srv.nextHop(round, st.incoming)
	st.url = url
	st.err = err
	reply.URL = url

	st.incoming = nil
	st.noise = nil
	return nil
}

func (srv *Server) lastServer() bool {
	return srv.ServerPosition == srv.NumServers-1
}

func (srv *Server) nextHop(round uint32, onions [][]byte) (url string, err error) {
	logger := log.WithFields(log.Fields{
		"service":  srv.Mixer.Service(),
		"rpc":      "Close",
		"round":    round,
		"outgoing": len(onions),
	})
	startTime := time.Now()

	if !srv.lastServer() {
		url, err = RunRound(srv.Mixer.Service(), srv.NextServer, round, onions)
		if err != nil {
			err = fmt.Errorf("RunRound: %s", err)
			goto End
		}
	} else {
		// last server
		mailboxes := srv.Mixer.SortMessages(onions)

		buf := new(bytes.Buffer)
		err = gob.NewEncoder(buf).Encode(mailboxes)
		if err != nil {
			err = errors.Wrap(err, "gob.Encode")
			goto End
		}
		totalUpload := buf.Len()

		logger = logger.WithFields(log.Fields{
			"totalUpload": totalUpload,
			"mailboxes":   len(mailboxes),
		})

		client := &http.Client{
			Transport: &http.Transport{
				DialTLS: func(network, addr string) (net.Conn, error) {
					return edtls.Dial(network, addr, srv.CDNPublicKey, srv.SigningKey)
				},
			},
		}

		putURL := fmt.Sprintf("https://%s/put?bucket=%s&prefix=%d", srv.CDNAddr, srv.Mixer.Service(), round)
		var resp *http.Response
		resp, err = client.Post(putURL, "application/octet-stream", buf)
		if err != nil {
			err = errors.Wrap(err, "http.Post CDN")
			goto End
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			// TODO read error message from body
			err = errors.New("bad CDN response: %s", resp.Status)
			goto End
		}
		url = fmt.Sprintf("https://%s/get?bucket=%s&prefix=%d", srv.CDNAddr, srv.Mixer.Service(), round)
	}

End:
	endTime := time.Now()
	logger = logger.WithField("duration", endTime.Sub(startTime))
	if err == nil {
		logger.Info(url)
	} else {
		logger.Error(err)
	}
	return
}

// NewRound starts a new mixing round on the given servers.
// NewRound fills in settings.OnionKeys and returns the servers'
// signatures of the round settings.
//
// settings.Round and settings.NumMailboxes must be set.
func NewRound(service string, servers []*vrpc.Client, settings *RoundSettings) ([][]byte, error) {
	settings.OnionKeys = make([]*[32]byte, len(servers))

	for i, server := range servers {
		args := &NewRoundArgs{Round: settings.Round}
		reply := new(NewRoundReply)
		if err := server.Call(service+"Coordinator.NewRound", args, reply); err != nil {
			return nil, fmt.Errorf("server %s: %s", server.Address, err)
		}
		settings.OnionKeys[i] = reply.OnionKey
	}

	signatures := make([][]byte, len(servers))
	for i, server := range servers {
		reply := new(SetRoundSettingsReply)
		if err := server.Call(service+"Coordinator.SetRoundSettings", settings, reply); err != nil {
			return signatures, fmt.Errorf("server %s: %s", server.Address, err)
		}
		signatures[i] = reply.Signature
	}
	return signatures, nil
}

func RunRound(service string, server *vrpc.Client, round uint32, onions [][]byte) (string, error) {
	spans := concurrency.Spans(len(onions), 4000)
	calls := make([]*vrpc.Call, len(spans))

	for i := range calls {
		span := spans[i]
		calls[i] = &vrpc.Call{
			Method: service + "Chain.Add",
			Args: &AddArgs{
				Round:  round,
				Onions: onions[span.Start : span.Start+span.Count],
			},
			Reply: nil,
		}
	}

	if err := server.CallMany(calls); err != nil {
		return "", fmt.Errorf("Add: %s", err)
	}

	reply := new(CloseReply)
	if err := server.Call(service+"Chain.Close", round, reply); err != nil {
		return "", fmt.Errorf("Close: %s", err)
	}

	return reply.URL, nil
}
