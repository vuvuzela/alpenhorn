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
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"vuvuzela.io/alpenhorn/edhttp"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/log"
	pb "vuvuzela.io/alpenhorn/mixnet/mixnetpb"
	"vuvuzela.io/concurrency"
	"vuvuzela.io/crypto/onionbox"
	"vuvuzela.io/crypto/rand"
	"vuvuzela.io/crypto/shuffle"
)

// Use github.com/davidlazar/easyjson:
//go:generate easyjson mixnet.go

// MixService provides functionality needed by a mixnet Server.
type MixService interface {
	// MessageSize returns the expected size of messages in bytes
	// after the last onion layer is peeled.
	MessageSize() int

	// NoiseCount returns how much noise to generate for a mailbox.
	NoiseCount() uint32

	// FillWithNoise generates noise to provide differential privacy.
	// noiseCounts specifies how much noise to add to each mailbox.
	FillWithNoise(dest [][]byte, noiseCounts []uint32, nextKeys []*[32]byte)

	// SortMessages sorts messages into mailboxes that are uploaded
	// to the CDN. It is called only by the last server in a chain.
	SortMessages(messages [][]byte) (mailboxes map[string][]byte)
}

type Server struct {
	SigningKey ed25519.PrivateKey

	CoordinatorKey ed25519.PublicKey

	Services map[string]MixService

	Log *log.Logger

	roundsMu sync.RWMutex
	rounds   map[serviceRound]*roundState

	once      sync.Once
	mixClient *Client
	cdnClient *edhttp.Client
}

type serviceRound struct {
	Service string
	Round   uint32
}

type roundState struct {
	mu                sync.Mutex
	closed            bool
	incoming          [][]byte
	settingsSignature []byte
	url               string
	err               error

	chain           []PublicServerConfig
	myPos           int
	cdnAddress      string
	cdnKey          ed25519.PublicKey
	onionPrivateKey *[32]byte
	onionPublicKey  *[32]byte
	nextServerKeys  []*[32]byte
	numMailboxes    uint32

	noise     [][]byte
	noiseDone chan struct{}
}

func (srv *Server) getRound(service string, round uint32) (*roundState, error) {
	var ok bool
	var st *roundState

	srv.roundsMu.RLock()
	if srv.rounds == nil {
		ok = false
	} else {
		st, ok = srv.rounds[serviceRound{service, round}]
	}
	srv.roundsMu.RUnlock()
	if !ok {
		return nil, errors.New("round %d not found", round)
	}
	return st, nil
}

func (srv *Server) auth(ctx context.Context, expectedKey ed25519.PublicKey) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Errorf(codes.DataLoss, "failed to get peer from ctx")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return status.Errorf(codes.Unauthenticated, "unknown AuthInfo type: %s", p.AuthInfo.AuthType())
	}

	certs := tlsInfo.State.PeerCertificates
	if len(certs) != 1 {
		status.Errorf(codes.Unauthenticated, "expecting 1 peer certificate, got %d", len(certs))
	}
	peerKey := edtls.GetSigningKey(certs[0])

	if !bytes.Equal(expectedKey, peerKey) {
		return status.Errorf(codes.Unauthenticated, "wrong edtls key")
	}

	return nil
}

func (srv *Server) NewRound(ctx context.Context, req *pb.NewRoundRequest) (*pb.NewRoundResponse, error) {
	if err := srv.auth(ctx, srv.CoordinatorKey); err != nil {
		return nil, err
	}

	_, ok := srv.Services[req.Service]
	if !ok {
		return nil, errors.New("unknown service: %q", req.Service)
	}

	srv.roundsMu.Lock()
	if srv.rounds == nil {
		srv.rounds = make(map[serviceRound]*roundState)
	}
	st := srv.rounds[serviceRound{req.Service, req.Round}]
	srv.roundsMu.Unlock()

	if st != nil {
		return &pb.NewRoundResponse{
			OnionKey: st.onionPublicKey[:],
		}, nil
	}

	public, private, err := box.GenerateKey(cryptoRand.Reader)
	if err != nil {
		panic(err)
	}

	chain := make([]PublicServerConfig, len(req.Chain))
	myPos := -1
	myPub := srv.SigningKey.Public().(ed25519.PublicKey)
	for i, conf := range req.Chain {
		if err := chain[i].FromProto(conf); err != nil {
			return nil, err
		}
		if bytes.Equal(conf.Key, myPub) {
			myPos = i
		}
	}
	if myPos == -1 {
		return nil, errors.New("my key is not in the chain")
	}
	if myPos == len(chain)-1 {
		// check CDN info if the last server
		if req.CDNAddress == "" || len(req.CDNKey) != ed25519.PublicKeySize {
			return nil, errors.New("incomplete CDN info")
		}
	}

	st = &roundState{
		chain:           chain,
		myPos:           myPos,
		cdnAddress:      req.CDNAddress,
		cdnKey:          req.CDNKey,
		onionPublicKey:  public,
		onionPrivateKey: private,
	}

	srv.roundsMu.Lock()
	srv.rounds[serviceRound{req.Service, req.Round}] = st
	srv.roundsMu.Unlock()

	srv.Log.WithFields(log.Fields{
		"service": req.Service,
		"round":   req.Round,
		"rpc":     "NewRound",
		"mixers":  len(chain),
		"pos":     myPos,
	}).Info("Created new round")

	return &pb.NewRoundResponse{
		OnionKey: public[:],
	}, nil
}

// SetRoundSettings is an RPC used by the coordinator to set the
// parameters for a round. The RPC returns a signature of the round
// settings. Clients must verify this signature from each server
// before participating in the round. This prevents dishonest servers
// from tricking clients and other servers into using different keys
// or a different number of mailboxes in a round (which can lead to
// distinguishable noise).
func (srv *Server) SetRoundSettings(ctx context.Context, req *pb.SetRoundSettingsRequest) (*pb.RoundSettingsSignature, error) {
	if err := srv.auth(ctx, srv.CoordinatorKey); err != nil {
		return nil, err
	}

	var settings RoundSettings
	err := settings.FromProto(req.Settings)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid round settings: %s", err)
	}

	st, err := srv.getRound(settings.Service, settings.Round)
	if err != nil {
		return nil, err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if st.settingsSignature != nil {
		// round settings have already been set
		return &pb.RoundSettingsSignature{
			Signature: st.settingsSignature,
		}, nil
	}

	if len(settings.OnionKeys) != len(st.chain) {
		return nil, errors.New("bad round settings: want %d keys, got %d", len(st.chain), len(settings.OnionKeys))
	}

	if !bytes.Equal(settings.OnionKeys[st.myPos][:], st.onionPublicKey[:]) {
		return nil, errors.New("bad round settings: unexpected key at position %d", st.myPos)
	}

	sig := ed25519.Sign(srv.SigningKey, settings.SigningMessage())
	st.settingsSignature = sig

	srv.Log.WithFields(log.Fields{
		"service": settings.Service,
		"round":   settings.Round,
		"rpc":     "SetRoundSettings",
	}).Info("Accepted round settings")

	st.numMailboxes = settings.NumMailboxes
	st.nextServerKeys = settings.OnionKeys[st.myPos+1:]
	st.noiseDone = make(chan struct{})

	// Now is a good time to start generating noise.
	go func() {
		service := srv.Services[settings.Service]

		// NOTE: unlike the convo protocol, the last server also adds noise
		noiseTotal := uint32(0)
		noiseCounts := make([]uint32, st.numMailboxes+1)
		for b := range noiseCounts {
			bmu := service.NoiseCount()
			noiseCounts[b] = bmu
			noiseTotal += bmu
		}
		st.noise = make([][]byte, noiseTotal)

		service.FillWithNoise(st.noise, noiseCounts, st.nextServerKeys)
		close(st.noiseDone)
	}()

	return &pb.RoundSettingsSignature{
		Signature: sig,
	}, nil
}

var zeroNonce = new([24]byte)

func (srv *Server) AddOnions(ctx context.Context, req *pb.AddOnionsRequest) (*pb.Nothing, error) {
	st, err := srv.getRound(req.Service, req.Round)
	if err != nil {
		return nil, err
	}

	// Limit this RPC to the "previous" server in the chain.
	var expectedKey ed25519.PublicKey
	if st.myPos == 0 {
		expectedKey = srv.CoordinatorKey
	} else {
		expectedKey = st.chain[st.myPos-1].Key
	}
	if err := srv.auth(ctx, expectedKey); err != nil {
		return nil, err
	}

	srv.Log.WithFields(log.Fields{
		"service": req.Service,
		"round":   req.Round,
		"rpc":     "AddOnions",
		"onions":  len(req.Onions),
	}).Debug("Decrypting onions")

	service := srv.Services[req.Service]

	messages := make([][]byte, 0, len(req.Onions))
	expectedOnionSize := (len(st.chain)-st.myPos)*onionbox.Overhead + service.MessageSize()

	for _, onion := range req.Onions {
		if len(onion) == expectedOnionSize {
			var theirPublic [32]byte
			copy(theirPublic[:], onion[0:32])

			message, ok := box.Open(nil, onion[32:], zeroNonce, &theirPublic, st.onionPrivateKey)
			if ok {
				messages = append(messages, message)
			} else {
				srv.Log.WithFields(log.Fields{
					"service": req.Service,
					"round":   req.Round,
					"rpc":     "Add",
				}).Warn("Decrypting onion failed")
			}
		}
	}

	st.mu.Lock()
	if !st.closed {
		st.incoming = append(st.incoming, messages...)
	} else {
		err = errors.New("round %d closed", req.Round)
	}
	st.mu.Unlock()

	return &pb.Nothing{}, err
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

func (srv *Server) CloseRound(ctx context.Context, req *pb.CloseRoundRequest) (*pb.CloseRoundResponse, error) {
	st, err := srv.getRound(req.Service, req.Round)
	if err != nil {
		return nil, err
	}
	var expectedKey ed25519.PublicKey
	if st.myPos == 0 {
		expectedKey = srv.CoordinatorKey
	} else {
		expectedKey = st.chain[st.myPos-1].Key
	}
	if err := srv.auth(ctx, expectedKey); err != nil {
		return nil, err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if st.closed {
		return &pb.CloseRoundResponse{
			BaseURL: st.url,
		}, st.err
	}
	st.closed = true

	numIncoming := len(st.incoming)
	srv.filterIncoming(st)
	numFiltered := numIncoming - len(st.incoming)

	srv.Log.WithFields(log.Fields{
		"service":  req.Service,
		"round":    req.Round,
		"rpc":      "CloseRound",
		"incoming": numIncoming,
		"filtered": numFiltered,
	}).Info("Filtered onions")

	<-st.noiseDone
	st.incoming = append(st.incoming, st.noise...)

	shuffler := shuffle.New(rand.Reader, len(st.incoming))
	shuffler.Shuffle(st.incoming)

	url, err := srv.nextHop(ctx, req, st)
	st.url = url
	st.err = err

	st.incoming = nil
	st.noise = nil
	return &pb.CloseRoundResponse{
		BaseURL: url,
	}, err
}

func (srv *Server) nextHop(ctx context.Context, req *pb.CloseRoundRequest, st *roundState) (url string, err error) {
	srv.once.Do(func() {
		// The server's position in the chain can change, so init both
		// the mix client and the CDN client now. This is simpler than
		// using two sync.Once values.
		srv.mixClient = &Client{
			Key: srv.SigningKey,
		}
		srv.cdnClient = &edhttp.Client{
			Key: srv.SigningKey,
		}
	})

	onions := st.incoming
	logger := srv.Log.WithFields(log.Fields{
		"service":  req.Service,
		"round":    req.Round,
		"rpc":      "CloseRound",
		"outgoing": len(onions),
	})

	startTime := time.Now()
	// if not the last server
	if st.myPos < len(st.chain)-1 {
		url, err = srv.mixClient.RunRound(ctx, st.chain[st.myPos+1], req.Service, req.Round, onions)
		if err != nil {
			err = errors.New("RunRound: %s", err)
			goto End
		}
	} else {
		// last server
		mailboxes := srv.Services[req.Service].SortMessages(onions)

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

		putURL := fmt.Sprintf("https://%s/put?bucket=%s/%d", st.cdnAddress, req.Service, req.Round)
		var resp *http.Response
		resp, err = srv.cdnClient.Post(st.cdnKey, putURL, "application/octet-stream", buf)
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
		url = fmt.Sprintf("https://%s/get?bucket=%s/%d", st.cdnAddress, req.Service, req.Round)
		logger = logger.WithFields(log.Fields{
			"url": url,
		})
	}

End:
	endTime := time.Now()
	logger = logger.WithFields(log.Fields{"duration": endTime.Sub(startTime)})
	if err == nil {
		logger.Info("Next hop success")
	} else {
		logger.Errorf("Next hop failed: %s", err)
	}
	return
}

//easyjson:readable
type PublicServerConfig struct {
	Key     ed25519.PublicKey
	Address string
}

func (c PublicServerConfig) Proto() *pb.PublicServerConfig {
	return &pb.PublicServerConfig{
		Key:     c.Key,
		Address: c.Address,
	}
}

func (c *PublicServerConfig) FromProto(pbc *pb.PublicServerConfig) error {
	if len(pbc.Key) != ed25519.PublicKeySize {
		return errors.New("invalid key in PublicServerConfig protobuf: %#v", pbc.Key)
	}
	c.Key = pbc.Key
	c.Address = pbc.Address
	return nil
}

type Client struct {
	Key ed25519.PrivateKey

	mu    sync.Mutex
	conns map[[ed25519.PublicKeySize]byte]*grpc.ClientConn
}

func (c *Client) getConn(server PublicServerConfig) (pb.MixnetClient, error) {
	var k [ed25519.PublicKeySize]byte
	copy(k[:], server.Key)

	c.mu.Lock()
	if c.conns == nil {
		c.conns = make(map[[ed25519.PublicKeySize]byte]*grpc.ClientConn)
	}
	cc := c.conns[k]
	c.mu.Unlock()

	if cc == nil {
		creds := credentials.NewTLS(edtls.NewTLSClientConfig(c.Key, server.Key))

		var err error
		cc, err = grpc.Dial(server.Address, grpc.WithTransportCredentials(creds))
		if err != nil {
			return nil, err
		}

		c.mu.Lock()
		c.conns[k] = cc
		c.mu.Unlock()
	}

	return pb.NewMixnetClient(cc), nil
}

// NewRound starts a new mixing round on the given servers.
// NewRound fills in settings.OnionKeys and returns the servers'
// signatures of the round settings.
//
// settings.Round and settings.NumMailboxes must be set.
func (c *Client) NewRound(ctx context.Context, servers []PublicServerConfig, cdnAddr string, cdnKey ed25519.PublicKey, settings *RoundSettings) ([][]byte, error) {
	settings.OnionKeys = make([]*[32]byte, len(servers))

	chain := make([]*pb.PublicServerConfig, len(servers))
	for i, conf := range servers {
		chain[i] = conf.Proto()
	}
	newRoundReq := &pb.NewRoundRequest{
		Service:    settings.Service,
		Round:      settings.Round,
		Chain:      chain,
		CDNAddress: cdnAddr,
		CDNKey:     cdnKey,
	}

	conns := make([]pb.MixnetClient, len(servers))
	for i, server := range servers {
		conn, err := c.getConn(server)
		if err != nil {
			return nil, err
		}
		conns[i] = conn
	}

	for i, server := range servers {
		response, err := conns[i].NewRound(ctx, newRoundReq)
		if err != nil {
			return nil, errors.Wrap(err, "server %s: NewRound", server.Address)
		}
		key := new([32]byte)
		copy(key[:], response.OnionKey[:])
		settings.OnionKeys[i] = key
	}

	setSettingsReq := &pb.SetRoundSettingsRequest{
		Settings: settings.Proto(),
	}
	signatures := make([][]byte, len(servers))
	for i, server := range servers {
		response, err := conns[i].SetRoundSettings(ctx, setSettingsReq)
		if err != nil {
			return signatures, errors.Wrap(err, "server %s: SetRoundSettings", server.Address)
		}
		signatures[i] = response.Signature
	}
	return signatures, nil
}

func (c *Client) RunRound(ctx context.Context, server PublicServerConfig, service string, round uint32, onions [][]byte) (string, error) {
	conn, err := c.getConn(server)
	if err != nil {
		return "", err
	}

	spans := concurrency.Spans(len(onions), 4000)

	errs := make(chan error, 1)
	for _, span := range spans {
		go func(span concurrency.Span) {
			req := &pb.AddOnionsRequest{
				Service: service,
				Round:   round,
				Onions:  onions[span.Start : span.Start+span.Count],
			}
			_, err := conn.AddOnions(ctx, req)
			errs <- err
		}(span)
	}

	var addErr error
	for i := 0; i < len(spans); i++ {
		err := <-errs
		if addErr == nil && err != nil {
			addErr = err
		}
	}

	closeReq := &pb.CloseRoundRequest{
		Service: service,
		Round:   round,
	}
	closeResponse, closeErr := conn.CloseRound(ctx, closeReq)

	url := ""
	if closeErr == nil {
		url = closeResponse.BaseURL
	}
	err = addErr
	if err == nil {
		err = closeErr
	}

	return url, err
}
