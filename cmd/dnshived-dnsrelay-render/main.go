// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// dnshived-dnsrelay-render is a small, standalone CLI wrapping
// internal/dnsrelayrender.WriteRelayConfig.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"dnshived/internal/config"
	"dnshived/internal/dnsrelayrender"
)

var version = "0.9.7-dev"

func main() {
	clusterPath := flag.String("cluster", "/etc/dnshived/cluster.json", "path to a real dnshived cluster.json")
	outPath := flag.String("config", "/etc/dnshived/dnsrelay.json", "path to the dnshived-dnsrelay config file to update (created if missing)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("dnshived-dnsrelay-render", version)
		os.Exit(0)
	}

	cluster, err := config.Load(*clusterPath)
	if err != nil {
		log.Fatalf("load cluster config: %v", err)
	}
	if res := cluster.ValidateExtended(); !res.OK() {
		log.Fatalf("cluster config failed validation: %v", res.Errors)
	}

	if err := dnsrelayrender.WriteRelayConfig(*outPath, *cluster); err != nil {
		log.Fatalf("render dnsrelay config: %v", err)
	}
	fmt.Printf("wrote %s from %s\n", *outPath, *clusterPath)
}
