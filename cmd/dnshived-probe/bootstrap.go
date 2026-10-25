// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"dnshived/internal/bootstrap"
	"dnshived/internal/discovery"
	"dnshived/internal/probehelper"
)

// defaultProbeHelperSocket is dnshived-probe-helper's own documented
// default (packaging/systemd/dnshived-probe-helper.service's ExecStart).
const defaultProbeHelperSocket = "/run/dnshived/probe-helper.sock"

// defaultProbeBootstrapOTPPath is the same file cmd/dnshived uses, so a
// fresh host shows one join code for either role.
const defaultProbeBootstrapOTPPath = "/run/dnshived-bootstrap/otp"

// probeBootstrapUnits is empty.
var probeBootstrapUnits []string

// probeBootstrapPaths derives DetectExisting's Paths for this binary.
func probeBootstrapPaths(cfgPath string) bootstrap.Paths {
	dir := filepath.Dir(cfgPath)
	return bootstrap.Paths{
		ClusterConfigPath: filepath.Join(dir, "cluster.json"),
		ProbeConfigPath:   cfgPath,
		WebUsersPath:      filepath.Join(dir, "webui-users.json"),
		Units:             probeBootstrapUnits,
	}
}

// probeBootstrapStatusResponse is GET /api/v1/bootstrap/status's body.
type probeBootstrapStatusResponse struct {
	Configured bool   `json:"configured"`
	Hostname   string `json:"hostname"`
	Version    string `json:"version"`
}

func probeBootstrapStatusHandler(hostname string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(probeBootstrapStatusResponse{
			Configured: false,
			Hostname:   hostname,
			Version:    version,
		})
	}
}

// probeAdoptRequest is POST /api/v1/bootstrap/adopt's body.
type probeAdoptRequest struct {
	Code   string          `json:"code"`
	Config json.RawMessage `json:"config"`
}

func probeAdoptHandler(otp string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var env struct {
			probeAdoptRequest
			bootstrap.Sealed
		}
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		req := env.probeAdoptRequest
		if env.IsSealed() {
			plain, err := bootstrap.Open(otp, bootstrap.PurposeProbeAdopt, env.Sealed)
			if err != nil {
				http.Error(w, "wrong join code", http.StatusUnauthorized)
				return
			}
			req = probeAdoptRequest{}
			if err := json.Unmarshal(plain, &req); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
		} else {
			if subtle.ConstantTimeCompare([]byte(req.Code), []byte(otp)) != 1 {
				http.Error(w, "wrong join code", http.StatusUnauthorized)
				return
			}
			log.Printf("[BOOTSTRAP:ADOPT] unencrypted adopt push from %s (sender older than 0.9.8.6): the probe tokens crossed the network in cleartext", r.RemoteAddr)
		}

		var pc ProbeConfig
		if err := json.Unmarshal(req.Config, &pc); err != nil {
			http.Error(w, "invalid probe config: "+err.Error(), http.StatusBadRequest)
			return
		}
		if pc.ListenAddr == "" || pc.TrunkParent == "" || pc.ClusterToken == "" || len(pc.ClusterNodes) == 0 {
			http.Error(w, "probe config missing required fields (listen_addr/trunk_parent/cluster_token/cluster_nodes)", http.StatusBadRequest)
			return
		}

		if err := probeHelperWriteConfigFunc(req.Config); err != nil {
			http.Error(w, "write config via probe-helper: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if err := probeHelperStopCoreDaemonsFunc(); err != nil {
			log.Printf("[BOOTSTRAP:ADOPT] stop core daemons (mutual exclusion): %v", err)
		}

		log.Printf("[BOOTSTRAP:ADOPT] real probe config received and written (%d cluster node(s)) — restarting as a configured probe", len(pc.ClusterNodes))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		go func() {
			time.Sleep(300 * time.Millisecond)
			probeReExecFunc()
		}()
	}
}

// probeReExecFunc is probeReExecAsConfigured by default.
var probeReExecFunc = probeReExecAsConfigured

// probeHelperWriteConfigFunc is probeHelperWriteConfig by default.
var probeHelperWriteConfigFunc = probeHelperWriteConfig

func probeHelperWriteConfig(content []byte) error {
	return probehelper.NewClient(defaultProbeHelperSocket).WriteConfig(content)
}

// probeHelperStopCoreDaemonsFunc mirrors probeHelperWriteConfigFunc's own
// testability pattern exactly.
var probeHelperStopCoreDaemonsFunc = probeHelperStopCoreDaemons

func probeHelperStopCoreDaemons() error {
	return probehelper.NewClient(defaultProbeHelperSocket).StopCoreDaemons()
}

func probeReExecAsConfigured() {
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("[BOOTSTRAP:ADOPT] find own executable path: %v", err)
	}
	log.Printf("[REEXEC] re-executing dnshived-probe")
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		log.Fatalf("[BOOTSTRAP:ADOPT] re-exec: %v", err)
	}
}

// runProbeBootstrapMode mirrors cmd/dnshived's runBootstrapMode.
func runProbeBootstrapMode(cfgPath, addr, otpPath string) {
	paths := probeBootstrapPaths(cfgPath)
	findings := bootstrap.DetectExisting(paths)
	if !findings.Fresh() {
		log.Printf("[BOOTSTRAP:REFUSE] %s is missing, but this host isn't fresh — refusing to auto-bootstrap", cfgPath)
		log.Printf("[BOOTSTRAP:REFUSE] found: %s", findings.String())
		log.Printf("[BOOTSTRAP:REFUSE] resolve this by hand before retrying — this is not a self-service action")
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(otpPath), 0o750); err != nil {
		log.Fatalf("[BOOTSTRAP:INIT] create %s: %v", filepath.Dir(otpPath), err)
	}
	otp, err := bootstrap.LoadOrCreateOTP(otpPath)
	if err != nil {
		log.Fatalf("[BOOTSTRAP:INIT] otp: %v", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	log.Printf("[BOOTSTRAP:READY] this probe host is not yet configured (no %s)", cfgPath)
	log.Printf("[BOOTSTRAP:READY] hostname: %s", hostname)
	log.Printf("[BOOTSTRAP:READY] join code: %s (the same code for a core role and for a probe role)", otp)
	log.Printf("[BOOTSTRAP:READY] enter this code when adopting this host as a probe from the core cluster's setup wizard")

	log.Printf("[DISCOVERY] broadcasting as unclaimed on port %d every 5s", discovery.Port)
	go discovery.Broadcast(context.Background(), hostname, version, discovery.PortFromAddr(addr, 9444))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/bootstrap/status", probeBootstrapStatusHandler(hostname))
	mux.HandleFunc("POST /api/v1/bootstrap/adopt", probeAdoptHandler(otp))
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[BOOTSTRAP:INIT] listen on %s: %v", addr, err)
	}
}
