// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/probepin"
)

func TestMgmtIfaceIfServing(t *testing.T) {
	p := &config.Platform{Mgmt: "ens18", Workers: []string{"ens19"}}
	if got := mgmtIfaceIfServing(p); got != "" {
		t.Errorf("got %q, want none while the management interface is not switched on", got)
	}
	p.Serving = map[string]bool{"ens18": true}
	if got := mgmtIfaceIfServing(p); got != "ens18" {
		t.Errorf("got %q, want ens18 once it serves", got)
	}
	if got := mgmtIfaceIfServing(nil); got != "" {
		t.Errorf("got %q for no platform, want none", got)
	}
}

func TestProvenProbePin_OnlyAFingerprintProvenWithTheJoinCodeIsPinned(t *testing.T) {
	fp := "sha256:" + strings.Repeat("ab", 32)
	reply := func(fingerprint, proof string) []byte {
		b, _ := json.Marshal(map[string]string{"tls_port": "9445", "tls_fingerprint": fingerprint, "tls_proof": proof})
		return b
	}
	tests := []struct {
		name  string
		reply []byte
		want  string
	}{
		{"proven", reply(fp, probepin.AdoptProof("JOIN-CODE", fp)), fp},
		{"proof from another join code", reply(fp, probepin.AdoptProof("OTHER", fp)), ""},
		{"no proof", reply(fp, ""), ""},
		{"fingerprint swapped after proving", reply("sha256:"+strings.Repeat("cd", 32), probepin.AdoptProof("JOIN-CODE", fp)), ""},
		{"malformed fingerprint", reply("nope", probepin.AdoptProof("JOIN-CODE", "nope")), ""},
		{"older probe, no fingerprint at all", []byte(`{"ok":true}`), ""},
		{"not JSON", []byte("x"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := provenProbePin("192.0.2.9:9444", "JOIN-CODE", tt.reply); got.Fingerprint != tt.want {
				t.Errorf("pinned %q, want %q", got.Fingerprint, tt.want)
			}
		})
	}
}
