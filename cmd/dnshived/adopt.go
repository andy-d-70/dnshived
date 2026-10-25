// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"crypto/subtle"
	"dnshived/internal/bootstrap"
	"dnshived/internal/loglevel"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"dnshived/internal/config"
)

// bootstrapAdoptRequest is POST /api/v1/bootstrap/adopt's body.
type bootstrapAdoptRequest struct {
	Code           string          `json:"code"`
	ClusterJSON    json.RawMessage `json:"cluster_json"`
	WebUsersJSON   json.RawMessage `json:"web_users_json,omitempty"`
	WebConfigJSON  json.RawMessage `json:"web_config_json,omitempty"`
	TLSCertPEM     []byte          `json:"tls_cert_pem,omitempty"`
	TLSKeyPEM      []byte          `json:"tls_key_pem,omitempty"`
	CoreTLSCertPEM []byte          `json:"core_tls_cert_pem,omitempty"`
	CoreTLSKeyPEM  []byte          `json:"core_tls_key_pem,omitempty"`
}

// bootstrapAdoptHandler receives a real cluster.json pushed by a builder
// session, validates it, writes it, and hands off to the real daemon.
func bootstrapAdoptHandler(otp, cfgPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var env struct {
			bootstrapAdoptRequest
			bootstrap.Sealed
		}
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		req := env.bootstrapAdoptRequest
		if env.IsSealed() {
			plain, err := bootstrap.Open(otp, bootstrap.PurposeCoreAdopt, env.Sealed)
			if err != nil {
				http.Error(w, "wrong join code", http.StatusUnauthorized)
				return
			}
			req = bootstrapAdoptRequest{}
			if err := json.Unmarshal(plain, &req); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
		} else {
			if subtle.ConstantTimeCompare([]byte(req.Code), []byte(otp)) != 1 {
				http.Error(w, "wrong join code", http.StatusUnauthorized)
				return
			}
			loglevel.Warnf("[BOOTSTRAP:ADOPT] unencrypted adopt push from %s (sender older than 0.9.8.6): the cluster secrets crossed the network in cleartext", r.RemoteAddr)
		}

		var c config.Cluster
		if err := json.Unmarshal(req.ClusterJSON, &c); err != nil {
			http.Error(w, "invalid cluster config: "+err.Error(), http.StatusBadRequest)
			return
		}
		result := c.ValidateExtended()
		if !result.OK() {
			http.Error(w, "cluster config failed validation: "+strings.Join(result.Errors, "; "), http.StatusBadRequest)
			return
		}

		if len(req.CoreTLSCertPEM) > 0 && len(req.CoreTLSKeyPEM) > 0 && c.TLSCert != "" && c.TLSKey != "" {
			os.MkdirAll(filepath.Dir(c.TLSCert), 0o755)
			os.MkdirAll(filepath.Dir(c.TLSKey), 0o755)
			if err := os.WriteFile(c.TLSCert, req.CoreTLSCertPEM, 0o644); err != nil {
				loglevel.Warnf("[BOOTSTRAP:ADOPT] write core TLS cert %s: %v", c.TLSCert, err)
			}
			if err := os.WriteFile(c.TLSKey, req.CoreTLSKeyPEM, 0o600); err != nil {
				loglevel.Warnf("[BOOTSTRAP:ADOPT] write core TLS key %s: %v", c.TLSKey, err)
			}
		}

		if err := os.WriteFile(cfgPath, req.ClusterJSON, 0o640); err != nil {
			http.Error(w, "write config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Best-effort: a working core cluster matters more than the web UI
		// convenience layer coming up immediately.
		writeAndStartWebUI(req.WebUsersJSON, req.WebConfigJSON, req.TLSCertPEM, req.TLSKeyPEM)
		reenableHelperAfterAdopt()
		stopProbeDaemonsOnThisHost()

		loglevel.Infof("[BOOTSTRAP:ADOPT] real cluster config received and written (role=%s, cluster_id=%s) — restarting as a configured daemon", c.Role, c.ClusterID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		go func() {
			time.Sleep(300 * time.Millisecond)
			reExecFunc()
		}()
	}
}

// reExecFunc is reExecAsConfiguredDaemon by default.
var reExecFunc = reExecAsConfiguredDaemon

// reExecAsConfiguredDaemon replaces this process's image in place with a
// fresh invocation of the same binary and the same arguments.
func reExecAsConfiguredDaemon() {
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("[BOOTSTRAP:ADOPT] find own executable path: %v", err)
	}
	loglevel.Infof("[BOOTSTRAP:ADOPT] re-executing as the now-configured daemon")
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		log.Fatalf("[BOOTSTRAP:ADOPT] re-exec: %v", err)
	}
}
