// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"testing"

	"dnshived/internal/agent"
	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/identity"
)

// TestBackupPayloadFor_NilReliabilityWhenNothingObserved checks no empty
// reliability snapshot is embedded.
func TestBackupPayloadFor_NilReliabilityWhenNothingObserved(t *testing.T) {
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	observer := cluster.NewObserver(self, "self-addr", nil, "")
	ag := agent.New("core-1", "self", 1, "", t.TempDir(), nil, observer)
	cfg := &config.Cluster{ClusterID: "test-cluster"}
	payload := backupPayloadFor(cfg, ag, observer)
	if payload.Reliability != nil {
		t.Errorf("payload.Reliability = %+v, want nil (nothing observed yet)", payload.Reliability)
	}
}
