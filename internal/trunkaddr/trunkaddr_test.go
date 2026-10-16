// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package trunkaddr

import (
	"testing"

	"dnshived/internal/config"
)

func clusterWithWorkers(workers ...string) config.Cluster {
	return config.Cluster{Platform: &config.Platform{Workers: workers}}
}

func TestIndex_FirstWorkerGetsIndexOne(t *testing.T) {
	c := clusterWithWorkers("ens19", "ens20")
	idx, err := Index(c, "ens19")
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	if idx != 1 {
		t.Errorf("Index(ens19) = %d, want 1", idx)
	}
}

func TestIndex_SecondWorkerGetsIndexTwo(t *testing.T) {
	c := clusterWithWorkers("ens19", "ens20")
	idx, err := Index(c, "ens20")
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	if idx != 2 {
		t.Errorf("Index(ens20) = %d, want 2", idx)
	}
}

func TestIndex_NeverReturnsCoreIndex(t *testing.T) {
	c := clusterWithWorkers("ens19", "ens20", "ens21")
	for _, w := range []string{"ens19", "ens20", "ens21"} {
		idx, err := Index(c, w)
		if err != nil {
			t.Fatalf("Index(%s): %v", w, err)
		}
		if idx == CoreIndex {
			t.Errorf("Index(%s) = %d, must never equal CoreIndex (%d)", w, idx, CoreIndex)
		}
	}
}

func TestIndex_UnknownParentErrors(t *testing.T) {
	c := clusterWithWorkers("ens19")
	if _, err := Index(c, "ens99"); err == nil {
		t.Error("Index(ens99) = nil error, want an error for a parent absent from Platform.Workers")
	}
}

func TestIndex_NilPlatformErrors(t *testing.T) {
	c := config.Cluster{}
	if _, err := Index(c, "ens19"); err == nil {
		t.Error("Index() = nil error, want an error when Platform itself is nil")
	}
}

func TestIndex_StableAcrossAppendOnlyGrowth(t *testing.T) {
	before := clusterWithWorkers("ens19", "ens20")
	idxBefore, err := Index(before, "ens19")
	if err != nil {
		t.Fatalf("Index (before): %v", err)
	}

	after := clusterWithWorkers("ens19", "ens20", "ens21") // appended, not reordered
	idxAfter, err := Index(after, "ens19")
	if err != nil {
		t.Fatalf("Index (after): %v", err)
	}

	if idxBefore != idxAfter {
		t.Errorf("ens19's index changed from %d to %d after only an append -- append-only growth must never reassign an existing index", idxBefore, idxAfter)
	}
}

func TestDHCPAddress_CoreIndexMatchesExistingDefaultAddress(t *testing.T) {
	if got := DHCPAddress(CoreIndex); got != "127.0.0.21" {
		t.Errorf("DHCPAddress(CoreIndex) = %q, want \"127.0.0.21\" (must match dhcpcentralrender.DefaultAddress)", got)
	}
}

func TestDNSAddress_CoreIndexMatchesExistingDefaultAddress(t *testing.T) {
	if got := DNSAddress(CoreIndex); got != "127.0.0.42" {
		t.Errorf("DNSAddress(CoreIndex) = %q, want \"127.0.0.42\" (must match dnscentralrender.DefaultAddress)", got)
	}
}

func TestDHCPAddress_PerTrunkIndicesAreDistinct(t *testing.T) {
	a := DHCPAddress(1)
	b := DHCPAddress(2)
	if a == b {
		t.Errorf("DHCPAddress(1) and DHCPAddress(2) both returned %q, want distinct addresses", a)
	}
	if a != "127.0.1.21" {
		t.Errorf("DHCPAddress(1) = %q, want \"127.0.1.21\"", a)
	}
	if b != "127.0.2.21" {
		t.Errorf("DHCPAddress(2) = %q, want \"127.0.2.21\"", b)
	}
}

func TestDNSAddress_PerTrunkIndicesAreDistinct(t *testing.T) {
	if got := DNSAddress(1); got != "127.0.1.42" {
		t.Errorf("DNSAddress(1) = %q, want \"127.0.1.42\"", got)
	}
	if got := DNSAddress(2); got != "127.0.2.42" {
		t.Errorf("DNSAddress(2) = %q, want \"127.0.2.42\"", got)
	}
}

func TestDHCPAddress_DNSAddress_NeverCollideForSameIndex(t *testing.T) {
	for idx := 0; idx <= MaxIndex; idx++ {
		if DHCPAddress(idx) == DNSAddress(idx) {
			t.Fatalf("DHCPAddress(%d) and DNSAddress(%d) collide: %q", idx, idx, DHCPAddress(idx))
		}
	}
}

func TestIndex_PastMaxIndexErrors(t *testing.T) {
	workers := make([]string, MaxIndex+1) // one more than fits
	for i := range workers {
		workers[i] = "ens" + string(rune('a'+i%26)) + string(rune('0'+i/26))
	}
	c := clusterWithWorkers(workers...)
	// The last one is at position MaxIndex (0-based), so its index
	// would be MaxIndex+1 -- past the ceiling.
	if _, err := Index(c, workers[len(workers)-1]); err == nil {
		t.Error("Index() = nil error for a worker past MaxIndex, want an error")
	}
}
