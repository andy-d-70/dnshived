// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/dhcprelay"
	"dnshived/internal/relayrender"
)

var version = "0.9.7-dev"

func main() {
	configPath := flag.String("config", "/etc/dnshived/relay.json", "path to relay config")
	showVersion := flag.Bool("version", false, "print version and exit")
	statusInterval := flag.Duration("status-interval", time.Minute, "how often to log a metrics summary (0 disables)")
	renderFrom := flag.String("render-from", "", "render relay config from a dnshived cluster.json and write it to --config, instead of starting the relay")
	flag.Parse()

	if *showVersion {
		fmt.Println("dnshived-relay", version)
		os.Exit(0)
	}

	if *renderFrom != "" {
		if err := renderConfigFromCluster(*renderFrom, *configPath); err != nil {
			log.Fatalf("[RELAY] render config: %v", err)
		}
		fmt.Printf("wrote %s from %s\n", *configPath, *renderFrom)
		os.Exit(0)
	}

	cfg, err := dhcprelay.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[RELAY] load config: %v", err)
	}

	r, err := dhcprelay.New(*cfg)
	if err != nil {
		log.Fatalf("[RELAY] init: %v", err)
	}

	if err := r.Start(); err != nil {
		log.Fatalf("[RELAY] start: %v", err)
	}
	log.Printf("[RELAY] started: %d client interface(s), server %s", len(cfg.ClientInterfaces), cfg.ServerAddr)

	stopStatus := make(chan struct{})
	if *statusInterval > 0 {
		go logStatusPeriodically(r, *statusInterval, stopStatus)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	for s := range sig {
		if s == syscall.SIGHUP {
			reloadConfig(r, *configPath)
			continue
		}
		break
	}

	close(stopStatus)
	log.Print("[RELAY] shutting down")
	r.Stop()
	log.Printf("[RELAY] stopped: %+v", r.Snapshot())
}

// reloadConfig re-reads configPath and applies it via r.Reconfigure.
func reloadConfig(r *dhcprelay.Relay, configPath string) {
	cfg, err := dhcprelay.LoadConfig(configPath)
	if err != nil {
		log.Printf("[RELAY] reload: read config: %v (keeping current config, nothing changed)", err)
		return
	}
	if err := r.Reconfigure(*cfg); err != nil {
		log.Printf("[RELAY] reload: apply config: %v (keeping current config, nothing changed)", err)
	}
}

func renderConfigFromCluster(clusterPath, outPath string) error {
	cluster, err := config.Load(clusterPath)
	if err != nil {
		return fmt.Errorf("load cluster config: %w", err)
	}
	if res := cluster.ValidateExtended(); !res.OK() {
		return fmt.Errorf("cluster config failed validation: %v", res.Errors)
	}
	return relayrender.WriteRelayConfig(outPath, *cluster, relayrender.DefaultServerAddr)
}

func logStatusPeriodically(r *dhcprelay.Relay, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s := r.Snapshot()
			log.Printf("[RELAY] requests: seen=%d forwarded=%d dropped=%d  replies: seen=%d forwarded=%d dropped=%d  pending=%d",
				s.RequestsSeen, s.RequestsForwarded, s.RequestsDropped,
				s.RepliesSeen, s.RepliesForwarded, s.RepliesDropped, s.Pending)
		}
	}
}
