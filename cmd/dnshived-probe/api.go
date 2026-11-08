// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"dnshived/internal/auth"
	"dnshived/internal/config"
	"dnshived/internal/daemonstatus"
	"dnshived/internal/eventlog"
	"dnshived/internal/passpolicy"
	"dnshived/internal/probehelper"
	"dnshived/internal/probepin"
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

	tlsCert, tlsFingerprint, err := loadOrCreateProbeCert(probeCertDir)
	if err != nil {
		return fmt.Errorf("probe API certificate: %w", err)
	}
	setLiveCert(tlsCert, tlsFingerprint)
	initial := append([]config.APIToken(nil), cfg.APITokens...)
	liveTokens.Store(&initial)

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
			"tls_port":          probeTLSPort,
			"tls_fingerprint":   currentFingerprint(),
			"plain_http":        cfg.plainHTTP(),
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

	mux.HandleFunc("GET /api/v1/tls-info", tlsInfoHandler)

	mux.HandleFunc("GET /api/v1/history", historyHandler)

	mux.HandleFunc("GET /api/v1/watch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"manual_probes": watchResults.list(cfg.manualProbeList())})
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

	mux.HandleFunc("POST /api/v1/tls", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body struct {
			CertPEM string `json:"cert_pem"`
			KeyPEM  string `json:"key_pem"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*maxUploadedPEM)).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
			return
		}
		pair, fp, err := installUploadedCert(probeCertDir, []byte(body.CertPEM), []byte(body.KeyPEM))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		setLiveCert(pair, fp)
		log.Printf("[API:TLS] probe certificate replaced, new fingerprint %s", fp)
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "tls_fingerprint": fp, "tls_port": probeTLSPort})
	}))

	mux.HandleFunc("POST /api/v1/rotate-token", authMw.RequireAdmin(rotateTokenHandler(cfg, cfgPath, authMw)))

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
	host, _, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("dnshived-probe TLS API address: %w", err)
	}
	tlsLn, err := net.Listen("tcp", net.JoinHostPort(host, probeTLSPort))
	if err != nil {
		return fmt.Errorf("dnshived-probe TLS API listener: %w", err)
	}
	if cfg.plainHTTP() {
		ln, err := net.Listen("tcp", cfg.ListenAddr)
		if err != nil {
			tlsLn.Close()
			return fmt.Errorf("dnshived-probe API listener: %w", err)
		}
		go func() {
			if err := http.Serve(ln, handler); err != nil {
				log.Fatalf("dnshived-probe API server: %v", err)
			}
		}()
	} else {
		log.Printf("[INIT] plain HTTP API is switched off (plain_http=false): only the TLS API on port %s answers", probeTLSPort)
	}
	tlsCfg := &tls.Config{GetCertificate: serveLiveCert, MinVersion: tls.VersionTLS12}
	go func() {
		if err := http.Serve(tls.NewListener(tlsLn, tlsCfg), handler); err != nil {
			log.Fatalf("dnshived-probe TLS API server: %v", err)
		}
	}()
	log.Printf("[INIT] TLS API on port %s, certificate %s", probeTLSPort, currentFingerprint())
	return nil
}

// liveTokens is the token set now in force; tls-info signs with its admin tokens.
var liveTokens atomic.Pointer[[]config.APIToken]

var nonceRE = regexp.MustCompile(`^[0-9a-zA-Z_-]{8,64}$`)

// tlsInfoHandler reports the TLS port and the certificate fingerprint served
// now. Both are public, and the route is exempt from token auth so a probe can
// be pinned before any token is sent to it. With a nonce it also returns, per
// admin token name, a proof that only a holder of that token can check, which
// lets an adopter that already holds the token pin without comparing anything.
func tlsInfoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fp := currentFingerprint()
	out := map[string]interface{}{"tls_port": probeTLSPort, "tls_fingerprint": fp}
	if nonce := r.URL.Query().Get("nonce"); nonceRE.MatchString(nonce) {
		proofs := map[string]string{}
		if toks := liveTokens.Load(); toks != nil {
			for _, t := range *toks {
				if t.Role == "admin" && len(proofs) < 4 {
					proofs[t.Name] = probepin.TokenProof(t.Token, fp, nonce)
				}
			}
		}
		out["proofs"] = proofs
	}
	json.NewEncoder(w).Encode(out)
}

// rotateTokenHandler replaces the token that authenticated the call. It only
// answers over TLS: the new token must never cross an unencrypted connection.
func rotateTokenHandler(cfg *ProbeConfig, cfgPath string, authMw *auth.Middleware) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.TLS == nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "a token may only be replaced over the TLS API"})
			return
		}
		if cfg.ProbeHelperSocket == "" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "no probe_helper_socket configured on this host"})
			return
		}
		var body struct {
			NewToken string `json:"new_token"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
			return
		}
		if problems := passpolicy.CheckToken(body.NewToken); len(problems) > 0 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "new token refused: " + strings.Join(problems, "; ")})
			return
		}
		used, ok := auth.TokenFromContext(r)
		if !ok {
			w.WriteHeader(http.StatusForbidden)
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
		replaced := false
		for i := range current.APITokens {
			if current.APITokens[i].Token == used.Token {
				current.APITokens[i].Token = body.NewToken
				replaced = true
			}
		}
		if !replaced {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "the token used for this call is not in the probe configuration"})
			return
		}
		data, err := json.MarshalIndent(&current, "", "  ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err := probehelper.NewClient(cfg.ProbeHelperSocket).WriteConfig(append(data, '\n')); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "write config: " + err.Error()})
			return
		}
		authMw.SetTokens(current.APITokens)
		toks := append([]config.APIToken(nil), current.APITokens...)
		liveTokens.Store(&toks)
		log.Printf("[API:TOKEN] the %q token was replaced over TLS", used.Name)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}
}

// historyHandler serves GET /api/v1/history: the newest matching records
// first, with the settings in force, the size on disk and the number of
// records dropped because the writer could not keep up.
func historyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	q, err := parseHistoryQuery(r.URL.Query())
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	recs, truncated, err := readHistory(historyDir, q)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if recs == nil {
		recs = []HistoryRecord{}
	}
	hc := histRec.Config()
	maxBytes, files, age := hc.limits()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"records": recs, "truncated": truncated, "dropped": histRec.Dropped(), "size_bytes": historySizeBytes(historyDir),
		"settings": map[string]interface{}{
			"dhcp": hc.mode("dhcp"), "dns": hc.mode("dns"), "syslog": hc.syslogOn(),
			"max_file_mb": maxBytes >> 20, "max_files": files, "max_age_days": int(age.Hours() / 24),
		},
	})
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
			ParallelProbing *bool          `json:"parallel_probing"`
			ClusterNodes    []ClusterNode  `json:"cluster_nodes"`
			ManualProbes    *[]ManualProbe `json:"manual_probes"`
			PlainHTTP       *bool          `json:"plain_http"`
			History         *HistoryConfig `json:"history"`
		}
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body: " + err.Error()})
			return
		}
		if patch.ParallelProbing == nil && len(patch.ClusterNodes) == 0 && patch.ManualProbes == nil && patch.PlainHTTP == nil && patch.History == nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "nothing to patch — provide parallel_probing, manual_probes, plain_http, history and/or a non-empty cluster_nodes"})
			return
		}
		if patch.History != nil {
			if err := validateHistory(*patch.History); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
		}
		if patch.ManualProbes != nil {
			if err := validateManualProbes(cfg, *patch.ManualProbes); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
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
		if patch.ManualProbes != nil {
			current.ManualProbes = *patch.ManualProbes
		}
		if patch.PlainHTTP != nil {
			current.PlainHTTP = patch.PlainHTTP
		}
		if patch.History != nil {
			current.History = patch.History
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
		if patch.History != nil {
			histRec.SetConfig(*patch.History)
			log.Printf("[API:CONFIG] history -> dhcp=%s dns=%s (applied live, no restart)", patch.History.mode("dhcp"), patch.History.mode("dns"))
		}
		if patch.ManualProbes != nil {
			cfg.SetManualProbes(*patch.ManualProbes)
			log.Printf("[API:CONFIG] manual_probes -> %d probe(s) (applied live from the next plan refresh, no restart)", len(*patch.ManualProbes))
		}
		if len(patch.ClusterNodes) == 0 && patch.PlainHTTP == nil {
			// live-applied fields only: results kept, no restart.
			if patch.ParallelProbing != nil {
				log.Printf("[API:CONFIG] parallel_probing -> %v (applied live, no restart)", *patch.ParallelProbing)
			}
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
