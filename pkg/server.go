// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package pkg implements a Private Key Generator (PKG) for
// Identity-Based Encryption (IBE).
package pkg

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/edhttp"
	"vuvuzela.io/alpenhorn/edtls"
	"vuvuzela.io/alpenhorn/errors"
	"vuvuzela.io/alpenhorn/log"
	"vuvuzela.io/crypto/bls"
	"vuvuzela.io/crypto/ibe"
)

// Use github.com/davidlazar/easyjson:
//go:generate easyjson server.go

// A Server is a Private Key Generator (PKG).
type Server struct {
	db       *sql.DB
	userStmt *sql.Stmt
	log      *log.Logger

	mu     sync.Mutex
	rounds map[uint32]*roundState

	privateKey     ed25519.PrivateKey
	publicKey      ed25519.PublicKey
	coordinatorKey ed25519.PublicKey

	sendVerificationEmail SendMailHandler
}

type roundState struct {
	masterPublicKey  *ibe.MasterPublicKey
	masterPrivateKey *ibe.MasterPrivateKey
	blsPublicKey     *bls.PublicKey
	blsPrivateKey    *bls.PrivateKey
	revealSignature  []byte
}

type SendMailHandler func(toUsername string, token []byte) error

// A Config is used to configure a PKG server.
type Config struct {
	// DBName is the PostgreSQL dbname parameter.
	DBName string

	// SigningKey is the PKG server's long-term signing key.
	SigningKey ed25519.PrivateKey

	// CoordinatorKey is the key that's authorized to start new PKG rounds.
	CoordinatorKey ed25519.PublicKey

	// Logger is the logger used to write log messages. The standard logger
	// is used if Logger is nil.
	Logger *log.Logger

	// SendVerificationEmail is invoked by the PKG to verify the identity
	// of a user when they register. This function should send an email
	// containing the token to the given username.
	//
	// If this function is nil, the PKG operates in first-come-first-serve
	// mode. In this mode, the PKG does not verify ownership of usernames;
	// the first user to register a username owns it.
	SendVerificationEmail SendMailHandler
}

// The PKG does not yet use the userlog table.
const schema string = `
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(255) UNIQUE,
  status INTEGER,
  key BYTEA,
  token BYTEA,
  tokenExpires TIMESTAMP
);

CREATE TABLE IF NOT EXISTS userlog (
  id SERIAL PRIMARY KEY,
  time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  username VARCHAR(255),
  type INTEGER,
  extra BYTEA
);
`

const userQuery = "SELECT username, status, key, token, tokenExpires FROM users WHERE username=$1"

func NewServer(conf *Config) (*Server, error) {
	connstr := fmt.Sprintf("host=/var/run/postgresql dbname=%s", conf.DBName)
	db, err := sql.Open("postgres", connstr)
	if err != nil {
		return nil, errors.Wrap(err, "sql.Open")
	}
	if err := db.Ping(); err != nil {
		return nil, errors.Wrap(err, "sql.Ping")
	}
	// avoid "too many clients" errors
	db.SetMaxOpenConns(90)
	// avoid "cannot assign requested address" errors
	db.SetMaxIdleConns(5)

	_, err = db.Exec(schema)
	if err != nil {
		return nil, errors.Wrap(err, "sql exec schema")
	}

	stmt, err := db.Prepare(userQuery)
	if err != nil {
		return nil, err
	}

	logger := conf.Logger
	if logger == nil {
		logger = log.StdLogger
	}

	s := &Server{
		db:             db,
		userStmt:       stmt,
		log:            logger,
		rounds:         make(map[uint32]*roundState),
		privateKey:     conf.SigningKey,
		publicKey:      conf.SigningKey.Public().(ed25519.PublicKey),
		coordinatorKey: conf.CoordinatorKey,

		sendVerificationEmail: conf.SendVerificationEmail,
	}
	return s, nil
}

func (srv *Server) Close() error {
	return srv.db.Close()
}

// ServeHTTP implements an http.Handler that answers PKG requests.
func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/extract":
		srv.extractHandler(w, r)
	case "/status":
		srv.statusHandler(w, r)
	case "/register":
		srv.registerHandler(w, r)
	case "/verify":
		srv.verifyHandler(w, r)
	case "/commit":
		srv.commitHandler(w, r)
	case "/reveal":
		srv.revealHandler(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (srv *Server) authorized(key ed25519.PublicKey, w http.ResponseWriter, req *http.Request) bool {
	if len(req.TLS.PeerCertificates) == 0 {
		httpError(w, errorf(ErrUnauthorized, "no peer tls certificate"))
		return false
	}
	peerKey := edtls.GetSigningKey(req.TLS.PeerCertificates[0])
	if !bytes.Equal(peerKey, key) {
		httpError(w, errorf(ErrUnauthorized, "peer key is not authorized"))
		return false
	}
	return true
}

type commitArgs struct {
	Round uint32
}

type commitReply struct {
	Commitment []byte
}

func (srv *Server) commitHandler(w http.ResponseWriter, req *http.Request) {
	if !srv.authorized(srv.coordinatorKey, w, req) {
		return
	}

	args := new(commitArgs)
	err := json.NewDecoder(req.Body).Decode(args)
	if err != nil {
		httpError(w, errorf(ErrBadRequestJSON, "%s", err))
		return
	}
	round := args.Round

	srv.mu.Lock()
	st, ok := srv.rounds[round]
	srv.mu.Unlock()
	if !ok {
		ibePub, ibePriv := ibe.Setup(rand.Reader)

		blsPub, blsPriv, err := bls.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}

		st = &roundState{
			masterPublicKey:  ibePub,
			masterPrivateKey: ibePriv,
			blsPublicKey:     blsPub,
			blsPrivateKey:    blsPriv,
		}
		srv.mu.Lock()
		srv.rounds[round] = st
		srv.mu.Unlock()
	}

	srv.log.WithFields(log.Fields{"round": args.Round}).Info("Commit")

	srv.mu.Lock()
	for r, _ := range srv.rounds {
		if r < round-1 {
			delete(srv.rounds, r)
		}
	}
	srv.mu.Unlock()

	reply := &commitReply{
		Commitment: commitTo(st.masterPublicKey, st.blsPublicKey),
	}
	bs, err := json.Marshal(reply)
	if err != nil {
		panic(err)
	}

	w.Write(bs)
}

func commitTo(ibeKey *ibe.MasterPublicKey, blsKey *bls.PublicKey) []byte {
	ibeKeyBytes, _ := ibeKey.MarshalBinary()
	blsKeyBytes, _ := blsKey.MarshalBinary()
	h := sha256.Sum256(append(ibeKeyBytes, blsKeyBytes...))
	return h[:]
}

type revealArgs struct {
	Round       uint32
	Commitments map[string][]byte // map from hex(signingPublicKey) -> commitment
}

type RevealReply struct {
	MasterPublicKey *ibe.MasterPublicKey
	BLSPublicKey    *bls.PublicKey

	// Signature signs the commitments in RevealArgs.
	Signature []byte
}

func (srv *Server) revealHandler(w http.ResponseWriter, req *http.Request) {
	if !srv.authorized(srv.coordinatorKey, w, req) {
		return
	}

	args := new(revealArgs)
	err := json.NewDecoder(req.Body).Decode(args)
	if err != nil {
		httpError(w, errorf(ErrBadRequestJSON, "%s", err))
		return
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()

	st, ok := srv.rounds[args.Round]
	if !ok {
		httpError(w, errorf(ErrRoundNotFound, "round %d", args.Round))
		return
	}

	if st.revealSignature == nil {
		commitment := args.Commitments[hex.EncodeToString(srv.publicKey)]
		expected := commitTo(st.masterPublicKey, st.blsPublicKey)
		if !bytes.Equal(commitment, expected) {
			httpError(w, errorf(ErrBadCommitment, "unexpected commitment for key %x", srv.publicKey))
			return
		}

		hexkeys := make([]string, 0, len(args.Commitments))
		for k := range args.Commitments {
			hexkeys = append(hexkeys, k)
		}
		sort.Strings(hexkeys)

		buf := new(bytes.Buffer)
		buf.WriteString("Commitments")
		binary.Write(buf, binary.BigEndian, args.Round)

		for _, hexkey := range hexkeys {
			if len(hexkey) != hex.EncodedLen(ed25519.PublicKeySize) {
				httpError(w, errorf(ErrBadCommitment, "bad public key length for hex key %s: %d != %d",
					hexkey, len(hexkey), hex.EncodedLen(ed25519.PublicKeySize)))
				return
			}

			commitment := args.Commitments[hexkey]
			if len(commitment) != len(expected) {
				httpError(w, errorf(ErrBadCommitment, "bad commitment length for key %s: %d != %d",
					hexkey, len(commitment), len(expected)))
				return
			}

			buf.WriteString(hexkey)
			buf.Write(commitment)
		}
		st.revealSignature = ed25519.Sign(srv.privateKey, buf.Bytes())
	}

	srv.log.WithFields(log.Fields{"round": args.Round}).Info("Reveal")

	reply := &RevealReply{
		MasterPublicKey: st.masterPublicKey,
		BLSPublicKey:    st.blsPublicKey,
		Signature:       st.revealSignature,
	}
	bs, err := json.Marshal(reply)
	if err != nil {
		panic(err)
	}
	w.Write(bs)
}

type RoundSettings map[string]RevealReply

func (s RoundSettings) Verify(round uint32, keys []ed25519.PublicKey) bool {
	hexkeys := make([]string, len(keys))
	for i := range keys {
		hexkeys[i] = hex.EncodeToString(keys[i])
	}
	sort.Strings(hexkeys)

	buf := new(bytes.Buffer)
	buf.WriteString("Commitments")
	binary.Write(buf, binary.BigEndian, round)

	for _, hexkey := range hexkeys {
		reveal, ok := s[hexkey]
		if !ok {
			return false
		}

		commitment := commitTo(reveal.MasterPublicKey, reveal.BLSPublicKey)

		buf.WriteString(hexkey)
		buf.Write(commitment)
	}
	msg := buf.Bytes()

	for _, key := range keys {
		sig := s[hex.EncodeToString(key)].Signature
		if !ed25519.Verify(key, msg, sig) {
			return false
		}
	}
	return true
}

//easyjson:readable
type PublicServerConfig struct {
	Key     ed25519.PublicKey
	Address string
}

type CoordinatorClient struct {
	CoordinatorKey ed25519.PrivateKey

	initOnce sync.Once
	client   *edhttp.Client
}

func (c *CoordinatorClient) init() {
	c.initOnce.Do(func() {
		c.client = &edhttp.Client{
			Key: c.CoordinatorKey,
		}
	})
}

func (c *CoordinatorClient) NewRound(pkgs []PublicServerConfig, round uint32) (RoundSettings, error) {
	c.init()

	commitments := make(map[string][]byte)
	commitArgs := &commitArgs{
		Round: round,
	}
	for _, pkg := range pkgs {
		commitReply := new(commitReply)
		req := &pkgRequest{
			PublicServerConfig: pkg,

			Path:   "commit",
			Args:   commitArgs,
			Reply:  commitReply,
			Client: c.client,
		}
		err := req.Do()
		if err != nil {
			return nil, err
		}
		commitments[hex.EncodeToString(pkg.Key)] = commitReply.Commitment
	}

	settings := make(RoundSettings)
	revealArgs := &revealArgs{
		Round:       round,
		Commitments: commitments,
	}
	for _, pkg := range pkgs {
		var reply RevealReply
		req := &pkgRequest{
			PublicServerConfig: pkg,

			Path:   "reveal",
			Args:   revealArgs,
			Reply:  &reply,
			Client: c.client,
		}
		err := req.Do()
		if err != nil {
			return nil, err
		}
		settings[hex.EncodeToString(pkg.Key)] = reply
	}

	keys := make([]ed25519.PublicKey, len(pkgs))
	for i := range pkgs {
		keys[i] = pkgs[i].Key
	}
	if !settings.Verify(round, keys) {
		return nil, errors.New("could not verify round settings")
	}

	return settings, nil
}

// ValidateUsername returns nil if username is a valid username,
// otherwise returns an error that explains why the username is invalid.
func ValidateUsername(username string) error {
	if len(username) > 64 {
		return errors.New("username must be 64 characters or less: %s", username)
	}
	parts := strings.Split(username, "@")
	if len(parts) != 2 || len(parts[0]) == 0 || len(parts[1]) == 0 {
		return errors.New("username must be a valid email address: %s", username)
	}
	for _, c := range username {
		if c >= 'A' && c <= 'Z' {
			return errors.New("username must be lowercase: %s", username)
		}
		if !validChar(c) {
			return errors.New("invalid character in username: %s", c)
		}
	}
	return nil
}

// UsernameToIdentity converts a username to an identity that can be
// used with IBE. An error is returned if the username is not valid.
func UsernameToIdentity(username string) (*[64]byte, error) {
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}
	return ValidUsernameToIdentity(username), nil
}

// ValidUsernameToIdentity converts a valid username to an identity.
// The result is undefined if username is invalid.
func ValidUsernameToIdentity(username string) *[64]byte {
	id := new([64]byte)
	copy(id[:], []byte(username))
	return id
}

func validChar(c rune) bool {
	if c >= 'a' && c <= 'z' {
		return true
	}
	if c >= '0' && c <= '9' {
		return true
	}
	if c == '.' || c == '-' || c == '_' || c == '\'' || c == '@' {
		return true
	}
	return false
}

func IdentityToUsername(identity *[64]byte) string {
	ix := bytes.IndexByte(identity[:], 0)
	if ix == -1 {
		return string(identity[:])
	}
	return string(identity[0:ix])
}
