// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"dnshived/internal/auth"
	"dnshived/internal/daemonstatus"
	"dnshived/internal/eventlog"
	"dnshived/internal/probehelper"
	"dnshived/internal/sysinfo"
)

// allowedProbeJournalUnits is the daemon-log endpoint's own boundary
// check.
var allowedProbeJournalUnits = map[string]bool{
	"dnshived-probe.service":        true,
	"dnshived-probe-helper.service": true,
}

// startAPIServer exposes this probe host's own read-only status.
func startAPIServer(cfg *ProbeConfig, cfgPath string, store *resultStore, tracker *probeLogTracker, events *eventlog.Ring, debounce *ownershipDebounce, startedAt time.Time, authMw *auth.Middleware) error {
	mux := http.NewServeMux()
	refresh := newRefreshLimiter()

	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		results := store.all()
		scopes := make([]string, 0, len(results))
		for name := range results {
			scopes = append(scopes, name)
		}
		hostname, _ := os.Hostname()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"role":     "probe",
			"hostname": hostname, // best-effort, empty on failure

			"version":           version,
			"listen_addr":       cfg.ListenAddr,
			"trunk_parent":      cfg.TrunkParent,
			"configured_scopes": scopes,
			"parallel_probing":  cfg.Parallel(),
			"started_at":        startedAt.UTC().Format(time.RFC3339),
			"server_time":       time.Now().UTC().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/api/v1/system", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sysinfo.Collect())
	})

	mux.HandleFunc("/api/v1/daemons", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		s := daemonstatus.Query("dnshived-probe.service", "")
		s.Version = version
		json.NewEncoder(w).Encode(map[string]interface{}{
			"node_id": "probe",
			"daemons": []daemonstatus.Status{s},
		})
	})

	mux.HandleFunc("GET /api/v1/daemon-log/{unit}", func(w http.ResponseWriter, r *http.Request) {
		unit := r.PathValue("unit")
		if !allowedProbeJournalUnits[unit] {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "unit not allowed: " + unit})
			return
		}
		n := 100
		if nStr := r.URL.Query().Get("n"); nStr != "" {
			if parsed, err := strconv.Atoi(nStr); err == nil && parsed > 0 {
				n = parsed
			}
		}
		client := probehelper.NewClient(cfg.ProbeHelperSocket)
		lines, err := client.GetJournalTail(unit, n)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"lines": lines})
	})

	mux.HandleFunc("/api/v1/probe/{scope}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		scope := r.PathValue("scope")
		result, ok := store.get(scope)
		if !ok {
			json.NewEncoder(w).Encode(map[string]interface{}{"scope": scope, "pending": true})
			return
		}
		json.NewEncoder(w).Encode(result)
	})

	// POST /api/v1/probe/{scope}/refresh — on-demand probe, independent of
	// the fixed sweep ticker.
	mux.HandleFunc("POST /api/v1/probe/{scope}/refresh", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		scope := r.PathValue("scope")
		if !refresh.tryStart(scope) {
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{"error": "a probe for this scope is already running"})
			return
		}
		defer refresh.finish(scope)

		result, published, err := probeScopeNow(cfg, store, tracker, events, debounce, scope)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		if !published {
			json.NewEncoder(w).Encode(map[string]interface{}{"scope": scope, "pending": true})
			return
		}
		json.NewEncoder(w).Encode(result)
	})

	mux.HandleFunc("/api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		sinceStr := r.URL.Query().Get("since")
		sinceIDStr := r.URL.Query().Get("since_id")
		nStr := r.URL.Query().Get("n")

		if sinceIDStr != "" {
			id, err := strconv.ParseInt(sinceIDStr, 10, 64)
			if err == nil {
				json.NewEncoder(w).Encode(events.SinceID(id))
				return
			}
		}

		if sinceStr != "" {
			ts, err := strconv.ParseInt(sinceStr, 10, 64)
			if err == nil {
				json.NewEncoder(w).Encode(events.Since(time.Unix(ts, 0)))
				return
			}
		}

		n := 100
		if nStr != "" {
			if parsed, err := strconv.Atoi(nStr); err == nil && parsed > 0 {
				n = parsed
			}
		}
		json.NewEncoder(w).Encode(events.Last(n))
	})

	registerConfigEndpoint(mux, cfg, cfgPath, authMw)

	// POST /api/v1/restart — admin-gated.
	mux.HandleFunc("POST /api/v1/restart", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if cfg.ProbeHelperSocket == "" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "no probe_helper_socket configured on this host"})
			return
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		go func() {
			time.Sleep(300 * time.Millisecond)
			client := probehelper.NewClient(cfg.ProbeHelperSocket)
			if _, err := client.RestartSelf(); err != nil {
				log.Printf("[API:RESTART] dnshived-probe.service: %v", err)
			}
		}()
	}))

	mux.HandleFunc("POST /api/v1/self-decommission", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if cfg.ProbeHelperSocket == "" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "no probe_helper_socket configured on this host"})
			return
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		go func() {
			time.Sleep(300 * time.Millisecond)
			probeSelfDecommission(cfg, "requested via POST /api/v1/self-decommission")
		}()
	}))

	handler := authMw.Wrap(mux)
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("dnshived-probe API listener: %w", err)
	}
	go func() {
		if err := http.Serve(ln, handler); err != nil {
			log.Fatalf("dnshived-probe API server: %v", err)
		}
	}()
	return nil
}

// registerConfigEndpoint wires POST /api/v1/config — admin-gated, two
// independently-optional patch fields.
func registerConfigEndpoint(mux *http.ServeMux, cfg *ProbeConfig, cfgPath string, authMw *auth.Middleware) {
	mux.HandleFunc("POST /api/v1/config", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if cfg.ProbeHelperSocket == "" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "no probe_helper_socket configured on this host"})
			return
		}
		var patch struct {
			ParallelProbing *bool         `json:"parallel_probing"`
			ClusterNodes    []ClusterNode `json:"cluster_nodes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body: " + err.Error()})
			return
		}
		if patch.ParallelProbing == nil && len(patch.ClusterNodes) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "nothing to patch — provide parallel_probing and/or a non-empty cluster_nodes"})
			return
		}

		raw, err := os.ReadFile(cfgPath)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "read current config: " + err.Error()})
			return
		}
		var current ProbeConfig
		if err := json.Unmarshal(raw, &current); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "parse current config: " + err.Error()})
			return
		}
		if patch.ParallelProbing != nil {
			current.ParallelProbing = *patch.ParallelProbing
		}
		if len(patch.ClusterNodes) > 0 {
			current.ClusterNodes = patch.ClusterNodes
			log.Printf("[API:CONFIG] cluster_nodes -> %d node(s), restarting to apply", len(patch.ClusterNodes))
		}
		data, err := json.MarshalIndent(&current, "", "  ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "marshal updated config: " + err.Error()})
			return
		}
		data = append(data, '\n')

		client := probehelper.NewClient(cfg.ProbeHelperSocket)
		if err := client.WriteConfig(data); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "write config: " + err.Error()})
			return
		}

		if patch.ParallelProbing != nil {
			cfg.SetParallel(*patch.ParallelProbing)
		}
		if len(patch.ClusterNodes) == 0 {
			// parallel_probing only: applied live, results kept.
			log.Printf("[API:CONFIG] parallel_probing -> %v (applied live from the next sweep, no restart)", *patch.ParallelProbing)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "restarting": false})
			return
		}
		if patch.ParallelProbing != nil {
			log.Printf("[API:CONFIG] parallel_probing -> %v, restarting to apply", *patch.ParallelProbing)
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "restarting": true})
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		go func() {
			time.Sleep(300 * time.Millisecond)
			if _, err := client.RestartSelf(); err != nil {
				log.Printf("[API:CONFIG] restart after config write: %v", err)
			}
		}()
	}))
}
