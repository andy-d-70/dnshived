// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// dnshived-web-helper is a minimal privileged helper for cmd/dnshived-web,
// mirroring cmd/dnshived-probe-helper's Unix-socket model.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var version = "0.9.7-dev"

// Request matches internal/webhelper.Client's wire shape.
type Request struct {
	Command string `json:"command"`
}

// Response matches internal/webhelper.Client's wire shape.
type Response struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	Throttled bool   `json:"throttled,omitempty"`
}

var connWG sync.WaitGroup

func main() {
	socketPath := flag.String("socket", "/run/dnshived/web-helper.sock", "Unix socket path")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("dnshived-web-helper", version)
		os.Exit(0)
	}

	socketDir := filepath.Dir(*socketPath)
	os.MkdirAll(socketDir, 0o755)
	os.Remove(*socketPath)

	ln, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	os.Chmod(*socketPath, 0o660)

	log.Printf("[WEB-HELPER:INIT] listening on %s", *socketPath)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed") {
					return
				}
				log.Printf("[WEB-HELPER:ERROR] accept: %v", err)
				continue
			}
			connWG.Add(1)
			go func() {
				defer connWG.Done()
				handleConn(conn)
			}()
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("[WEB-HELPER] shutting down, draining in-flight requests")
	ln.Close()
	connWG.Wait()
	os.Remove(*socketPath)
	log.Printf("[WEB-HELPER] shutdown complete")
	os.Exit(0)
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		log.Printf("[WEB-HELPER:ERROR] decode: %v", err)
		return
	}

	switch req.Command {
	case "restart-self":
		throttled, err := restartSelf()
		if err != nil {
			log.Printf("[WEB-HELPER:ERROR] restart-self: %v", err)
			respond(conn, Response{OK: false, Error: err.Error()})
			return
		}
		log.Printf("[WEB-HELPER:OK] restart-self (throttled=%v)", throttled)
		respond(conn, Response{OK: true, Throttled: throttled})

	default:
		log.Printf("[WEB-HELPER:DENY] unknown command %q", req.Command)
		respond(conn, Response{OK: false, Error: "unknown command: " + req.Command})
	}
}

func respond(conn net.Conn, resp Response) {
	json.NewEncoder(conn).Encode(resp)
}

// restartMu/lastRestartAt rate-limit restartSelf to at most once per 10s
// — same tier as dnshived-probe-helper's own restart-self.
var (
	restartMu     sync.Mutex
	lastRestartAt time.Time
)

func restartSelf() (throttled bool, err error) {
	restartMu.Lock()
	defer restartMu.Unlock()
	if time.Since(lastRestartAt) < 10*time.Second {
		log.Printf("[WEB-HELPER:RATE_LIMIT] restart-self suppressed (< 10s since last restart)")
		return true, nil
	}
	if err := exec.Command("systemctl", "restart", "dnshived-web.service").Run(); err != nil {
		return false, fmt.Errorf("restart dnshived-web.service: %w", err)
	}
	lastRestartAt = time.Now()
	return false, nil
}
