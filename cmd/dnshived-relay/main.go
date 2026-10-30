// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dnshived/internal/cliguard"
	"dnshived/internal/config"
	"dnshived/internal/dhcprelay"
	"dnshived/internal/instlock"
	"dnshived/internal/relayrender"
)

var version = "0.9.7-dev"

func main() {
	configPath := flag.String("config", "/etc/dnshived/relay.json", "path to relay config")
	showVersion := flag.Bool("version", false, "print version and exit")
	statusInterval := flag.Duration("status-interval", time.Minute, "how often to log a metrics summary (0 disables)")
	renderFrom := flag.String("render-from", "", "render relay config from a dnshived cluster.json and write it to --config, instead of starting the relay")
	gateSocket := flag.String("gate-socket", "/run/dnshived-relay/relay-gate.sock", "control socket for the authority gate")
	runtimeDir := flag.String("runtime-dir", "/run/dnshived-relay", "directory for the per-scope track files")
	showStatus := flag.Bool("status", false, "print the running relay's status (gate socket) and exit")
	cliguard.Parse("dnshived-relay", false)

	if *showVersion {
		fmt.Println("dnshived-relay", version)
		os.Exit(0)
	}

	role := cliguard.Daemon
	if *showStatus {
		role = cliguard.RootTool
	}
	cliguard.CheckUser("dnshived-relay", role, "dnshived-relay")
	if role == cliguard.Daemon {
		if err := instlock.Hold(*runtimeDir + "/relay.lock"); err != nil {
			cliguard.Exit("dnshived-relay", err)
		}
	}

	if *showStatus {
		if err := printStatus(*gateSocket); err != nil {
			log.Fatalf("[RELAY] status: %v", err)
		}
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
	if err := r.ConfigureGate(*gateSocket, *runtimeDir, version); err != nil {
		log.Fatalf("[RELAY] gate: %v", err)
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

// printStatus asks the running relay for its status over the gate socket and prints the reply as indented JSON.
func printStatus(sockPath string) error {
	conn, err := net.DialTimeout("unix", sockPath, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(`{"command":"status"}` + "\n")); err != nil {
		return err
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, bytes.TrimSpace(body), "", "  "); err != nil {
		return fmt.Errorf("reply is not JSON: %w", err)
	}
	fmt.Println(out.String())
	return nil
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
			log.Printf("[RELAY] requests: seen=%d forwarded=%d dropped=%d  replies: seen=%d forwarded=%d dropped=%d  pending=%d  client_limited=%d pending_full=%d",
				s.RequestsSeen, s.RequestsForwarded, s.RequestsDropped,
				s.RepliesSeen, s.RepliesForwarded, s.RepliesDropped, s.Pending,
				s.RequestsClientLimit, s.RequestsPendingFull)
		}
	}
}
