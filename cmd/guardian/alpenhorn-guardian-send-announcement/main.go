// Copyright 2018 David Lazar. All rights reserved.
// Use of this source code is governed by the GNU AGPL
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"vuvuzela.io/alpenhorn/cmd/guardian"
	"vuvuzela.io/alpenhorn/config"
	"vuvuzela.io/alpenhorn/edhttp"
	"vuvuzela.io/vuvuzela/convo"
	"vuvuzela.io/vuvuzela/coordinator"
)

var globalMsg = flag.String("msg", "", "message to announce")

func main() {
	flag.Parse()

	if *globalMsg == "" {
		fmt.Println("Specify message with -msg.")
		os.Exit(1)
	}

	conf, err := config.StdClient.CurrentConfig("Convo")
	if err != nil {
		fmt.Printf("error fetching convo config: %s\n", err)
		os.Exit(1)
	}
	convoConfig := conf.Inner.(*convo.ConvoConfig)

	appDir := guardian.Appdir()
	privatePath := filepath.Join(appDir, "guardian.privatekey")

	privateKey := guardian.ReadPrivateKey(privatePath)

	url := fmt.Sprintf("https://%s/convo/sendannouncement", convoConfig.Coordinator.Address)
	client := edhttp.Client{
		Key: privateKey,
	}
	resp, err := client.PostJSON(convoConfig.Coordinator.Key, url, coordinator.GlobalAnnouncement{
		Message: *globalMsg,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	reply, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("%s: %s", resp.Status, reply)
	}
	log.Printf("%s: %s", resp.Status, reply)
}
