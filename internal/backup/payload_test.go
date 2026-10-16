// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package backup

import (
	"encoding/json"
	"testing"

	"dnshived/internal/config"
)

// TestPayload_OldFormatBackupStillUnmarshalsCleanly checks an old-format
// backup still unmarshals.
func TestPayload_OldFormatBackupStillUnmarshalsCleanly(t *testing.T) {
	old := config.Cluster{ClusterID: "old-cluster", PSK: "abc123"}
	data, err := json.Marshal(old)
	if err != nil {
		t.Fatalf("marshal old-format Cluster: %v", err)
	}

	var p Payload
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal old-format backup into Payload: %v", err)
	}
	if p.ClusterID != "old-cluster" || p.PSK != "abc123" {
		t.Fatalf("Payload after old-format unmarshal = %+v, want Cluster fields intact", p)
	}
	if p.DHCPLeases != nil {
		t.Fatalf("Payload.DHCPLeases = %+v, want nil for an old-format backup", p.DHCPLeases)
	}
}

func TestPayload_NewFormatRoundTripsWithLeaseData(t *testing.T) {
	p := Payload{
		Cluster: config.Cluster{ClusterID: "new-cluster"},
		DHCPLeases: &LeaseData{Leases: []LeaseEntry{
			{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 1234, Hostname: "host1"},
		}},
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got Payload
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ClusterID != "new-cluster" {
		t.Fatalf("got.ClusterID = %q, want new-cluster", got.ClusterID)
	}
	if got.DHCPLeases == nil || len(got.DHCPLeases.Leases) != 1 {
		t.Fatalf("got.DHCPLeases = %+v, want one lease entry", got.DHCPLeases)
	}
	le := got.DHCPLeases.Leases[0]
	if le.MAC != "aa:bb" || le.IP != "10.0.0.5" || le.ExpiresAt != 1234 || le.Hostname != "host1" {
		t.Fatalf("got.DHCPLeases.Leases[0] = %+v, want the original entry unchanged", le)
	}
}

func TestPayload_EmptyDHCPLeasesOmittedFromJSON(t *testing.T) {
	p := Payload{Cluster: config.Cluster{ClusterID: "x"}}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to raw map: %v", err)
	}
	if _, present := raw["dhcp_leases"]; present {
		t.Fatalf("dhcp_leases key present in JSON with DHCPLeases nil, want omitted")
	}
}
