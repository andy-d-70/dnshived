// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"dnshived/internal/probepin"
)

// probeTLSInfo is what a probe host's plain status reports about its TLS API.
type probeTLSInfo struct {
	TLSPort        string `json:"tls_port"`
	TLSFingerprint string `json:"tls_fingerprint"`
}

// fetchProbeTLSInfo reads a probe host's TLS port and certificate fingerprint over its plain API.
// It asks the public /api/v1/tls-info, which needs no token, so no token crosses the unencrypted connection;
// a probe build that predates it is asked on /api/v1/status, which answers without a token only on a probe with no API tokens.
// The result is only ever checked against what the operator confirms; it is never trusted on its own.
func fetchProbeTLSInfo(host NodeConfig) (probeTLSInfo, error) {
	plain := NodeConfig{Name: host.Name, Addr: host.Addr}
	info, status, err := getProbeTLSInfo(plain, "/api/v1/tls-info")
	if err == nil && status == http.StatusOK {
		return info, nil
	}
	if status != http.StatusNotFound {
		if err == nil {
			err = fmt.Errorf("status %d", status)
		}
		return probeTLSInfo{}, err
	}
	info, status, err = getProbeTLSInfo(plain, "/api/v1/status")
	if err == nil && status != http.StatusOK {
		err = fmt.Errorf("status %d (this probe host needs an upgrade to be pinned: its status needs a token)", status)
	}
	return info, err
}

func getProbeTLSInfo(plain NodeConfig, path string) (probeTLSInfo, int, error) {
	var info probeTLSInfo
	req, err := http.NewRequest(http.MethodGet, plain.baseURL()+path, nil)
	if err != nil {
		return info, 0, err
	}
	resp, err := directHTTPClient.Do(req)
	if err != nil {
		return info, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return info, resp.StatusCode, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return info, resp.StatusCode, err
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return info, resp.StatusCode, fmt.Errorf("parse %s: %w", path, err)
	}
	return info, resp.StatusCode, nil
}

// checkPinnedTLS confirms that host answers over TLS with exactly the certificate fp, before the pin is saved.
// The pinned handshake is the proof: any HTTP answer means it succeeded, so a token-protected route may
// answer 401 and still pass. The public tls-info route is asked, and when it answers with a fingerprint
// that must be fp as well.
func checkPinnedTLS(host NodeConfig, fp string) error {
	pinned := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: probepin.Config(fp)},
	}
	req, err := http.NewRequest(http.MethodGet, "https://"+host.tlsAddr()+"/api/v1/tls-info", nil)
	if err != nil {
		return err
	}
	resp, err := pinned.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusInternalServerError {
		return fmt.Errorf("TLS status %s", resp.Status)
	}
	if resp.StatusCode == http.StatusOK {
		var info probeTLSInfo
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		if json.Unmarshal(body, &info) == nil && info.TLSFingerprint != "" && info.TLSFingerprint != fp {
			return fmt.Errorf("the probe reports the fingerprint %s over TLS, not the pinned one", info.TLSFingerprint)
		}
	}
	return nil
}

// handleProbePin serves POST /probes/pin. The operator types the fingerprint from the probe host's own log;
// the pin is saved only if the probe answers over TLS with that certificate.
func handleProbePin(cfgPath string, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		cfg := ref.Load()
		addr := strings.TrimSpace(r.PostForm.Get("addr"))
		fp := strings.TrimSpace(r.PostForm.Get("tls_fingerprint"))

		idx := -1
		for i, h := range cfg.ProbeHosts {
			if h.Addr == addr {
				idx = i
				break
			}
		}
		if idx < 0 {
			http.Error(w, "no probe host at address "+addr, http.StatusNotFound)
			return
		}
		if !probepin.Valid(fp) {
			http.Error(w, "fingerprint must look like sha256: followed by 64 lowercase hex digits", http.StatusBadRequest)
			return
		}

		host := cfg.ProbeHosts[idx]
		info, err := fetchProbeTLSInfo(host)
		if err != nil {
			http.Error(w, "read probe status: "+err.Error(), http.StatusBadGateway)
			return
		}
		if info.TLSPort == "" || info.TLSFingerprint == "" {
			http.Error(w, "this probe host has no TLS API yet — upgrade it first", http.StatusConflict)
			return
		}
		if info.TLSFingerprint != fp {
			http.Error(w, "the probe reports a different fingerprint than the one typed — check the probe host's log", http.StatusConflict)
			return
		}

		host.TLSPort = info.TLSPort
		host.TLSFingerprint = fp
		if err := checkPinnedTLS(host, fp); err != nil {
			http.Error(w, "TLS check with this fingerprint failed: "+err.Error(), http.StatusBadGateway)
			return
		}

		hosts := append([]NodeConfig{}, cfg.ProbeHosts...)
		hosts[idx] = host
		newCfg := *cfg
		newCfg.ProbeHosts = hosts
		if err := saveWebConfig(cfgPath, &newCfg); err != nil {
			http.Error(w, "save web config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		ref.Store(&newCfg)
		http.Redirect(w, r, "/probes", http.StatusSeeOther)
	}
}

// handleProbeUnpin serves POST /probes/unpin. The probe goes back to plain HTTP until it is pinned again.
func handleProbeUnpin(cfgPath string, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		cfg := ref.Load()
		addr := strings.TrimSpace(r.PostForm.Get("addr"))

		idx := -1
		for i, h := range cfg.ProbeHosts {
			if h.Addr == addr {
				idx = i
				break
			}
		}
		if idx < 0 {
			http.Error(w, "no probe host at address "+addr, http.StatusNotFound)
			return
		}

		hosts := append([]NodeConfig{}, cfg.ProbeHosts...)
		hosts[idx].TLSPort = ""
		hosts[idx].TLSFingerprint = ""
		newCfg := *cfg
		newCfg.ProbeHosts = hosts
		if err := saveWebConfig(cfgPath, &newCfg); err != nil {
			http.Error(w, "save web config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		ref.Store(&newCfg)
		http.Redirect(w, r, "/probes", http.StatusSeeOther)
	}
}
