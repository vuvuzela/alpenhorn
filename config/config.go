// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

// Package config manages global server configuration.
package config

import (
	"fmt"
	"io/ioutil"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/crypto/ed25519"

	"vuvuzela.io/alpenhorn/encoding/toml"
)

type ServerInfo struct {
	Address   string
	PublicKey ed25519.PublicKey

	// EntryAddress is only used by PKG servers.
	EntryAddress string `json:",omitempty"`
}

type ServerMap map[string]*ServerInfo

type ServerList []*ServerInfo

func (m ServerMap) GetServer(server string) *ServerInfo {
	return m[server]
}

func (m ServerMap) GetServers(servers []string) ServerList {
	infos := make(ServerList, len(servers))
	for i, srv := range servers {
		info, ok := m[srv]
		if !ok {
			log.Fatalf("GetServers: server %s not found", srv)
		}
		infos[i] = info
	}
	return infos
}

func (xs ServerList) Addrs() []string {
	keys := make([]string, len(xs))
	for i, srv := range xs {
		keys[i] = srv.Address
	}
	return keys
}

func (xs ServerList) Keys() []ed25519.PublicKey {
	keys := make([]ed25519.PublicKey, len(xs))
	for i, srv := range xs {
		keys[i] = srv.PublicKey
	}
	return keys
}

type Config struct {
	ServerMap `mapstructure:"servers"`

	*AlpenhornSettings `mapstructure:"alpenhorn"`
}

type AlpenhornSettings struct {
	// These strings are keys into a ServerMap.

	PKGServers []string
	Mixers     []string

	CDN         string
	EntryServer string
}

func ReadFile(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	conf := new(Config)
	err = toml.Unmarshal(data, conf)
	if err != nil {
		return nil, fmt.Errorf("error parsing %q: %s", path, err)
	}

	srvlists := [][]string{
		conf.PKGServers,
		conf.Mixers,
		[]string{conf.CDN},
	}
	for _, srvlist := range srvlists {
		for _, srv := range srvlist {
			info := conf.ServerMap[srv]
			if info == nil {
				return nil, fmt.Errorf("server %q not configured", srv)
			}
		}
	}

	return conf, nil
}

func (c *Config) PrevMixer(srv string) *ServerInfo {
	ix := index(c.Mixers, srv)
	if ix < 0 {
		return nil
	}
	if ix == 0 {
		return c.ServerMap[c.EntryServer]
	}
	prev := c.Mixers[ix-1]
	return c.ServerMap[prev]
}

func (c *Config) NextMixer(srv string) *ServerInfo {
	ix := index(c.Mixers, srv)
	if ix == -1 || ix >= len(c.Mixers)-1 {
		return nil
	}
	next := c.Mixers[ix+1]
	return c.ServerMap[next]
}

func (c *Config) MixerPosition(srv string) int {
	return index(c.Mixers, srv)
}

func index(list []string, item string) int {
	for i, s := range list {
		if s == item {
			return i
		}
	}
	return -1
}
