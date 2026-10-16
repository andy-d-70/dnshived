// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"dnshived/internal/tlspin"
)

// inspectClient has a generous timeout.
var inspectClient = &http.Client{
	Timeout:   60 * time.Second,
	Transport: &http.Transport{TLSClientConfig: tlspin.Config()},
}

// inspectResponse mirrors cmd/dnshived's own inspectCandidateResponse.
type inspectResponse struct {
	OK                  bool              `json:"ok"`
	Error               string            `json:"error,omitempty"`
	OS                  string            `json:"os"`
	CandidateInterfaces []string          `json:"candidate_interfaces"`
	Mapping             map[string]string `json:"mapping"`
	CandidateVersion    string            `json:"candidate_version,omitempty"`
	ThisVersion         string            `json:"this_version,omitempty"`
	VersionMismatch     bool              `json:"version_mismatch,omitempty"`
}

// inspectNodeFormHandler (POST /nodes/inspect) is the precheck popup's
// backend.
func inspectNodeFormHandler(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		addr := r.FormValue("addr")
		if addr == "" {
			http.Error(w, "address is required", http.StatusBadRequest)
			return
		}

		// Any real core node — every core role is fully symmetric and can have
		// real trunk interfaces constructed on it.
		var runner *NodeConfig
		for i := range cfg.Nodes {
			if isCoreRole(cfg.Nodes[i].Name) {
				n := cfg.Nodes[i]
				runner = &n
				break
			}
		}
		if runner == nil {
			http.Error(w, "no core node configured — nothing has real trunk interfaces to inspect against", http.StatusServiceUnavailable)
			return
		}

		body, _ := json.Marshal(map[string]string{"addr": addr})
		req, err := http.NewRequest(http.MethodPost, runner.baseURL()+"/api/v1/nodes/inspect", bytes.NewReader(body))
		if err != nil {
			http.Error(w, "build request: "+err.Error(), http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if runner.AdminToken != "" {
			req.Header.Set("Authorization", "Bearer "+runner.AdminToken)
		}
		resp, err := inspectClient.Do(req)
		if err != nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintf(w, "FAILED: could not reach %s to run the inspection: %s\n", runner.Name, err.Error())
			return
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)

		var result inspectResponse
		if err := json.Unmarshal(respBody, &result); err != nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintf(w, "FAILED: unexpected response from %s: %s\n", runner.Name, string(respBody))
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, formatInspectResult(addr, result))
	}
}

// formatInspectResult renders inspectResponse as plain, operator-readable
// text.
func formatInspectResult(addr string, r inspectResponse) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Inspecting %s\n\n", addr)
	if !r.OK {
		fmt.Fprintf(&b, "FAILED: %s\n", r.Error)
		return b.String()
	}
	if r.OS != "" {
		fmt.Fprintf(&b, "OS: %s\n", r.OS)
	} else {
		fmt.Fprint(&b, "OS: (not reported)\n")
	}
	if r.VersionMismatch {
		fmt.Fprintf(&b, "\n⚠ VERSION MISMATCH: candidate is running %s, this cluster is on %s.\n", r.CandidateVersion, r.ThisVersion)
		fmt.Fprint(&b, "  Onboarding a node on a different version may fail, or behave\n")
		fmt.Fprint(&b, "  unexpectedly once joined (a newer feature the candidate doesn't\n")
		fmt.Fprint(&b, "  understand, or vice versa). Go ahead at your own risk.\n")
	}
	fmt.Fprintf(&b, "\nCandidate interfaces seen: %s\n\n", strings.Join(r.CandidateInterfaces, ", "))

	fmt.Fprint(&b, "Trunk interface assignment:\n")
	trunks := make([]string, 0, len(r.Mapping))
	for t := range r.Mapping {
		trunks = append(trunks, t)
	}
	sort.Strings(trunks)
	allDetected := len(trunks) > 0
	for _, trunk := range trunks {
		detected := r.Mapping[trunk]
		switch {
		case detected == "":
			fmt.Fprintf(&b, "  %s -> NOT DETECTED — no candidate interface was physically seen on this trunk. Verify manually before onboarding.\n", trunk)
			allDetected = false
		case detected == trunk:
			fmt.Fprintf(&b, "  %s -> %s (detected, name matches)\n", trunk, detected)
		default:
			fmt.Fprintf(&b, "  %s -> %s (detected, but the candidate calls it %q — names differ)\n", trunk, detected, detected)
		}
	}
	fmt.Fprint(&b, "\n")
	if allDetected {
		fmt.Fprint(&b, "Every trunk was physically detected. Review above, then Onboard/Replace as usual.\n")
	} else {
		fmt.Fprint(&b, "At least one trunk was NOT detected — this candidate may be missing a cable, on the wrong bridge, or its interface simply never came up. Do not assume it's fine; verify by hand before proceeding.\n")
	}
	return b.String()
}
