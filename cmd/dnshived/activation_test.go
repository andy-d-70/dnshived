// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"testing"

	"dnshived/internal/activation"
)

func TestActivationMembers(t *testing.T) {
	peers := []string{"192.0.2.2:9443", "192.0.2.3:9443", "192.0.2.4:9443"}
	snaps := []nodeSnapshot{
		{Status: json.RawMessage(`{"node_id":"n2","role":"core-2","version":"0.9.9.0"}`)},
		{Error: "connection refused"},
		{Status: json.RawMessage(`not json`)},
	}
	got := activationMembers("n1", "core-1", "0.9.9.0", peers, snaps)
	if len(got) != 4 {
		t.Fatalf("members = %d", len(got))
	}
	if got[0].Name != "n1" || !got[0].Reachable || got[0].Version != "0.9.9.0" {
		t.Errorf("self = %+v", got[0])
	}
	if got[1].Name != "n2" || got[1].Role != "core-2" || !got[1].Reachable {
		t.Errorf("peer 1 = %+v", got[1])
	}
	if got[2].Reachable || got[2].Name != peers[1] {
		t.Errorf("peer 2 = %+v", got[2])
	}
	if got[3].Reachable {
		t.Errorf("peer 3 with undecodable status counted reachable: %+v", got[3])
	}
	res := activation.Evaluate(activation.FeatureVersion, got)
	if res.Active || len(res.Blocking) != 2 {
		t.Errorf("result = %+v", res)
	}
}
