// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package config manages global server configuration.
package config

import (
	"io/ioutil"

	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/encoding/toml"
	"vuvuzela.io/alpenhorn/errors"
)

type GlobalConfig interface {
	// AlpenhornConfig returns the Alpenhorn configuration from a global
	// config. It does not return an error if fields are missing, so the
	// caller should validate required fields before using them.
	AlpenhornConfig() (*AlpenhornConfig, error)

	// VuvuzelaConfig returns the Vuvuzela configuration from a global
	// config with the same caveat as AlpenhornConfig.
	VuvuzelaConfig() (*VuvuzelaConfig, error)
}

type AlpenhornConfig struct {
	Coordinator Coordinator
	PKGs        []PKG
	Mixers      []Mixer
	CDN         CDN
}

type VuvuzelaConfig struct {
	Coordinator Coordinator
	Mixers      []Mixer
}

type Coordinator struct {
	Key           ed25519.PublicKey
	ClientAddress string
}

type PKG struct {
	Key                ed25519.PublicKey
	ClientAddress      string
	CoordinatorAddress string
}

type Mixer struct {
	Key     ed25519.PublicKey
	Address string
}

type CDN struct {
	Key     ed25519.PublicKey
	Address string
}

// globalConfig and its corresponding types are used to
// decode the TOML config file.
type globalConfig struct {
	Alpenhorn *alpenhornConfig
	Vuvuzela  *vuvuzelaConfig
	Keys      map[string]ed25519.PublicKey
}

type alpenhornConfig struct {
	Coordinator coordinatorConfig
	PKG         []pkgConfig
	Mixer       []mixerConfig
	CDN         cdnConfig
}

type coordinatorConfig struct {
	Key           string // Key is an entry in the globalConfig.Keys map.
	ClientAddress string
}

type pkgConfig struct {
	Key                string
	ClientAddress      string
	CoordinatorAddress string
}

type mixerConfig struct {
	Key     string
	Address string
}

type cdnConfig struct {
	Key     string
	Address string
}

type vuvuzelaConfig struct {
	Coordinator coordinatorConfig
	Mixer       []mixerConfig
}

func (conf *globalConfig) getKey(keyName string) (ed25519.PublicKey, error) {
	if keyName == "" {
		return nil, nil
	}
	key, ok := conf.Keys[keyName]
	if !ok {
		return nil, errors.New("key %q not found", keyName)
	}
	return key, nil
}

func (conf *globalConfig) AlpenhornConfig() (*AlpenhornConfig, error) {
	if conf.Alpenhorn == nil {
		return nil, errors.New("no alpenhorn config")
	}

	coordinatorKey, err := conf.getKey(conf.Alpenhorn.Coordinator.Key)
	if err != nil {
		return nil, err
	}
	coordinator := Coordinator{
		Key:           coordinatorKey,
		ClientAddress: conf.Alpenhorn.Coordinator.ClientAddress,
	}

	pkgs := make([]PKG, len(conf.Alpenhorn.PKG))
	for i, pkgConf := range conf.Alpenhorn.PKG {
		key, err := conf.getKey(pkgConf.Key)
		if err != nil {
			return nil, err
		}
		pkgs[i] = PKG{
			Key:                key,
			ClientAddress:      pkgConf.ClientAddress,
			CoordinatorAddress: pkgConf.CoordinatorAddress,
		}
	}

	mixers := make([]Mixer, len(conf.Alpenhorn.Mixer))
	for i, mixerConf := range conf.Alpenhorn.Mixer {
		key, err := conf.getKey(mixerConf.Key)
		if err != nil {
			return nil, err
		}
		mixers[i] = Mixer{
			Key:     key,
			Address: mixerConf.Address,
		}
	}

	cdnKey, err := conf.getKey(conf.Alpenhorn.CDN.Key)
	if err != nil {
		return nil, err
	}
	cdn := CDN{
		Key:     cdnKey,
		Address: conf.Alpenhorn.CDN.Address,
	}

	return &AlpenhornConfig{
		Coordinator: coordinator,
		PKGs:        pkgs,
		Mixers:      mixers,
		CDN:         cdn,
	}, nil
}

func (conf *globalConfig) VuvuzelaConfig() (*VuvuzelaConfig, error) {
	if conf.Vuvuzela == nil {
		return nil, errors.New("no vuvuzela config")
	}

	coordinatorKey, err := conf.getKey(conf.Vuvuzela.Coordinator.Key)
	if err != nil {
		return nil, err
	}
	coordinator := Coordinator{
		Key:           coordinatorKey,
		ClientAddress: conf.Vuvuzela.Coordinator.ClientAddress,
	}

	mixers := make([]Mixer, len(conf.Vuvuzela.Mixer))
	for i, mixerConf := range conf.Vuvuzela.Mixer {
		key, err := conf.getKey(mixerConf.Key)
		if err != nil {
			return nil, err
		}
		mixers[i] = Mixer{
			Key:     key,
			Address: mixerConf.Address,
		}
	}

	return &VuvuzelaConfig{
		Coordinator: coordinator,
		Mixers:      mixers,
	}, nil
}

func decodeGlobalConfig(data []byte) (GlobalConfig, error) {
	globalConf := new(globalConfig)
	err := toml.Unmarshal(data, globalConf)
	if err != nil {
		return nil, err
	}

	return globalConf, nil
}

func ReadGlobalConfigFile(path string) (GlobalConfig, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return decodeGlobalConfig(data)
}
