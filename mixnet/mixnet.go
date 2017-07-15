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

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/errors"
	pb "vuvuzela.io/alpenhorn/mixnet/mixnetpb"
	"vuvuzela.io/concurrency"
	"vuvuzela.io/crypto/onionbox"
	"vuvuzela.io/crypto/rand"
	"vuvuzela.io/crypto/shuffle"
)

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

	ServerPosition int // position in chain, starting at 0
	NumServers     int
	NextServer     PublicServerConfig
	CDNPublicKey   ed25519.PublicKey
	CDNAddr        string

	roundsMu sync.RWMutex
	rounds   map[serviceRound]*roundState

	once      sync.Once
	mixClient *Client
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
		return nil, fmt.Errorf("round %d not found", round)
	}
	return st, nil
}

func (srv *Server) authCoordinator(ctx context.Context) error {
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

	if !bytes.Equal(srv.CoordinatorKey, peerKey) {
		return status.Errorf(codes.Unauthenticated, "wrong edtls key")
	}

	return nil
}

func (srv *Server) NewRound(ctx context.Context, req *pb.NewRoundRequest) (*pb.NewRoundResponse, error) {
	log.WithFields(log.Fields{"service": req.Service, "rpc": "NewRound", "round": req.Round}).Info()
	if err := srv.authCoordinator(ctx); err != nil {
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
		return nil, fmt.Errorf("box.GenerateKey error: %s", err)
	}

	st = &roundState{
		onionPublicKey:  public,
		onionPrivateKey: private,
	}

	srv.roundsMu.Lock()
	srv.rounds[serviceRound{req.Service, req.Round}] = st
	srv.roundsMu.Unlock()

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
	if err := srv.authCoordinator(ctx); err != nil {
		return nil, err
	}

	var settings RoundSettings
	err := settings.FromProto(req.Settings)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid round settings: %s", err)
	}

	log.WithFields(log.Fields{"service": settings.Service, "rpc": "SetRoundSettings", "round": settings.Round}).Info()

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

	if len(settings.OnionKeys) != srv.NumServers {
		return nil, errors.New("bad round settings: want %d keys, got %d", srv.NumServers, len(settings.OnionKeys))
	}

	if !bytes.Equal(settings.OnionKeys[srv.ServerPosition][:], st.onionPublicKey[:]) {
		return nil, errors.New("bad round settings: unexpected key at position %d", srv.ServerPosition)
	}

	sig := ed25519.Sign(srv.SigningKey, settings.SigningMessage())
	st.settingsSignature = sig

	st.numMailboxes = settings.NumMailboxes
	st.nextServerKeys = settings.OnionKeys[srv.ServerPosition+1:]
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
	log.WithFields(log.Fields{"service": req.Service, "rpc": "AddOnions", "round": req.Round, "onions": len(req.Onions)}).Debug()

	st, err := srv.getRound(req.Service, req.Round)
	if err != nil {
		return nil, err
	}
	service := srv.Services[req.Service]

	messages := make([][]byte, 0, len(req.Onions))
	expectedOnionSize := (srv.NumServers-srv.ServerPosition)*onionbox.Overhead + service.MessageSize()

	for _, onion := range req.Onions {
		if len(onion) == expectedOnionSize {
			var theirPublic [32]byte
			copy(theirPublic[:], onion[0:32])

			message, ok := box.Open(nil, onion[32:], zeroNonce, &theirPublic, st.onionPrivateKey)
			if ok {
				messages = append(messages, message)
			} else {
				log.WithFields(log.Fields{"service": req.Service, "rpc": "Add", "round": req.Round}).Error("Decrypting onion failed")
			}
		}
	}

	st.mu.Lock()
	if !st.closed {
		st.incoming = append(st.incoming, messages...)
	} else {
		err = fmt.Errorf("round %d closed", req.Round)
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
	log.WithFields(log.Fields{"service": req.Service, "rpc": "CloseRound", "round": req.Round}).Info()

	st, err := srv.getRound(req.Service, req.Round)
	if err != nil {
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

	log.WithFields(log.Fields{
		"service": req.Service,
		"rpc":     "CloseRound",
		"round":   req.Round,
		"onions":  len(st.incoming),
	}).Info()

	srv.filterIncoming(st)

	<-st.noiseDone
	st.incoming = append(st.incoming, st.noise...)

	shuffler := shuffle.New(rand.Reader, len(st.incoming))
	shuffler.Shuffle(st.incoming)

	url, err := srv.nextHop(ctx, req.Service, req.Round, st.incoming)
	st.url = url
	st.err = err

	st.incoming = nil
	st.noise = nil
	return &pb.CloseRoundResponse{
		BaseURL: url,
	}, err
}

func (srv *Server) lastServer() bool {
	return srv.ServerPosition == srv.NumServers-1
}

func (srv *Server) nextHop(ctx context.Context, serviceName string, round uint32, onions [][]byte) (url string, err error) {
	logger := log.WithFields(log.Fields{
		"service":  serviceName,
		"rpc":      "CloseRound",
		"round":    round,
		"outgoing": len(onions),
	})
	startTime := time.Now()

	if !srv.lastServer() {
		srv.once.Do(func() {
			if srv.mixClient == nil {
				srv.mixClient = &Client{
					Key: srv.SigningKey,
				}
			}
		})
		url, err = srv.mixClient.RunRound(ctx, srv.NextServer, serviceName, round, onions)
		if err != nil {
			err = fmt.Errorf("RunRound: %s", err)
			goto End
		}
	} else {
		// last server
		mailboxes := srv.Services[serviceName].SortMessages(onions)

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

		putURL := fmt.Sprintf("https://%s/put?bucket=%s/%d", srv.CDNAddr, serviceName, round)
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
		url = fmt.Sprintf("https://%s/get?bucket=%s/%d", srv.CDNAddr, serviceName, round)
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

type PublicServerConfig struct {
	Key     ed25519.PublicKey
	Address string
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
func (c *Client) NewRound(ctx context.Context, servers []PublicServerConfig, settings *RoundSettings) ([][]byte, error) {
	settings.OnionKeys = make([]*[32]byte, len(servers))

	newRoundReq := &pb.NewRoundRequest{
		Service: settings.Service,
		Round:   settings.Round,
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
