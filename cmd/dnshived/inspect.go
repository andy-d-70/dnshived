// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"context"
	"dnshived/internal/loglevel"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"dnshived/internal/discovery"
	"dnshived/internal/rpfilter"
)

// inspectBurstDurationNS is how long each of a candidate's own interfaces
// gets tested for, one at a time.
var inspectBurstDurationNS atomic.Int64

func init() {
	inspectBurstDurationNS.Store(int64(4 * time.Second))
}

// inspectBurstDuration returns the current value.
func inspectBurstDuration() time.Duration {
	return time.Duration(inspectBurstDurationNS.Load())
}

// inspectBurstDurationForTest temporarily shrinks inspectBurstDuration for
// a fast test.
func inspectBurstDurationForTest(d time.Duration) func() {
	orig := inspectBurstDurationNS.Swap(int64(d))
	return func() { inspectBurstDurationNS.Store(orig) }
}

// inspectHTTPTimeout bounds the plain, unauthenticated calls this handler
// makes to the still-untrusted candidate (status fetch, the
// probe-interface trigger).
func inspectHTTPTimeout() time.Duration {
	return inspectBurstDuration() + 5*time.Second
}

// inspectCandidateRequest is POST /api/v1/nodes/inspect's body.
type inspectCandidateRequest struct {
	Addr string `json:"addr"`
}

// inspectCandidateResponse is what an operator actually reviews before
// committing to Onboard/Replace.
type inspectCandidateResponse struct {
	OK                  bool              `json:"ok"`
	Error               string            `json:"error,omitempty"`
	OS                  string            `json:"os"`
	CandidateInterfaces []string          `json:"candidate_interfaces"`
	Mapping             map[string]string `json:"mapping"`

	CandidateVersion string `json:"candidate_version,omitempty"`
	ThisVersion      string `json:"this_version,omitempty"`
	VersionMismatch  bool   `json:"version_mismatch,omitempty"`
}

// bootstrapStatusFromCandidate is a plain, unauthenticated GET against a
// still-untrusted candidate's own bootstrap status.
func bootstrapStatusFromCandidate(addr string) (bootstrapStatusResponse, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/api/v1/bootstrap/status")
	if err != nil {
		return bootstrapStatusResponse{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return bootstrapStatusResponse{}, fmt.Errorf("%s: %s", resp.Status, string(body))
	}
	var s bootstrapStatusResponse
	if err := json.Unmarshal(body, &s); err != nil {
		return bootstrapStatusResponse{}, err
	}
	return s, nil
}

// triggerCandidateInterfaceBurst tells the candidate to burst-broadcast on
// candIface for burstDuration.
func triggerCandidateInterfaceBurst(addr, candIface string, burstDuration time.Duration) error {
	body, _ := json.Marshal(bootstrapProbeInterfaceRequest{
		Interface: candIface, DurationMS: int(burstDuration.Milliseconds()),
	})
	client := &http.Client{Timeout: inspectHTTPTimeout()}
	resp, err := client.Post("http://"+addr+"/api/v1/bootstrap/probe-interface", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s: %s", resp.Status, string(b))
	}
	return nil
}

// correlateCandidateInterfaces always talks to the candidate's core
// bootstrap API: a host awaiting adoption also runs the probe daemon,
// whose discovery announcement may carry the probe port instead.
func correlateCandidateInterfaces(ctx context.Context, myTrunks []string, candidateAddr string) (map[string]string, bootstrapStatusResponse, error) {
	candidateAddr = coreBootstrapContactAddr(candidateAddr)
	status, err := bootstrapStatusFromCandidate(candidateAddr)
	if err != nil {
		return nil, bootstrapStatusResponse{}, fmt.Errorf("reach candidate: %w", err)
	}
	if status.MgmtInterface == "" {
		loglevel.Infof("[API:NODES] interface check: %s reported no management interface", candidateAddr)
	}

	mapping := make(map[string]string, len(myTrunks))
	for _, t := range myTrunks {
		mapping[t] = ""
		discovery.EnsureUp(t)
	}

	for _, candIface := range status.Interfaces {
		burst := inspectBurstDuration()
		burstCtx, cancel := context.WithTimeout(ctx, burst+2*time.Second)

		var wg sync.WaitGroup
		var mu sync.Mutex
		heardOn := make([]string, 0, 1)
		for _, trunk := range myTrunks {
			wg.Add(1)
			go func(trunk string) {
				defer wg.Done()
				if _, ok := discovery.ListenOnInterface(burstCtx, trunk, burst); ok {
					mu.Lock()
					heardOn = append(heardOn, trunk)
					mu.Unlock()
				}
			}(trunk)
		}
		go triggerCandidateInterfaceBurst(candidateAddr, candIface, burst)

		wg.Wait()
		cancel()
		for _, trunk := range heardOn {
			mapping[trunk] = candIface
		}
	}

	for _, t := range myTrunks {
		if mapping[t] == "" {
			loglevel.Infof("[API:NODES] interface check: nothing heard from %s on trunk %s (rp_filter=%s; non-zero drops the probe on an address-less trunk)", candidateAddr, t, rpfilter.Value(t))
		}
	}
	return mapping, status, nil
}

// inspectNodeHandler (POST /api/v1/nodes/inspect, admin-gated) is the
// already-running-cluster half of correlateCandidateInterfaces.
func inspectNodeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req inspectCandidateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Addr == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "addr is required"})
			return
		}

		cfg := currentConfig.Load()
		var trunks []string
		canonicalOf := make(map[string]string)
		if cfg.Platform != nil {
			for _, canonical := range cfg.Platform.Workers {
				local := cfg.Platform.ResolveParent(cfg.Role, canonical)
				trunks = append(trunks, local)
				canonicalOf[local] = canonical
			}
		}

		localMapping, status, err := correlateCandidateInterfaces(r.Context(), trunks, req.Addr)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, inspectCandidateResponse{Error: err.Error()})
			return
		}
		mapping := make(map[string]string, len(localMapping))
		for local, candIface := range localMapping {
			mapping[canonicalOf[local]] = candIface
		}

		writeJSON(w, http.StatusOK, inspectCandidateResponse{
			OK:                  true,
			OS:                  status.OS,
			CandidateInterfaces: append([]string{}, status.Interfaces...),
			Mapping:             mapping,
			CandidateVersion:    status.Version,
			ThisVersion:         version,
			VersionMismatch:     status.Version != "" && status.Version != version,
		})
	}
}

// sortedTrunkNames is a small display helper.
func sortedTrunkNames(mapping map[string]string) []string {
	out := make([]string, 0, len(mapping))
	for k := range mapping {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
