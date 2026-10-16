// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"sync"
	"testing"
)

// TestConfigRef_LoadReturnsInitialValue confirms newConfigRef's own
// starting value round-trips through Load unchanged.
func TestConfigRef_LoadReturnsInitialValue(t *testing.T) {
	cfg := &WebConfig{ListenAddr: "127.0.0.1:8443"}
	ref := newConfigRef(cfg)
	if got := ref.Load(); got != cfg {
		t.Fatalf("Load() = %p, want the exact original *WebConfig %p", got, cfg)
	}
}

func TestConfigRef_StorePublishesForSubsequentLoads(t *testing.T) {
	original := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", DisplayName: ""}}}
	ref := newConfigRef(original)

	updated := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", DisplayName: "renamed"}}}
	ref.Store(updated)

	got := ref.Load()
	if got != updated {
		t.Fatalf("Load() after Store = %p, want the just-stored %p", got, updated)
	}
	if got.Nodes[0].DisplayName != "renamed" {
		t.Fatalf("Load().Nodes[0].DisplayName = %q, want %q", got.Nodes[0].DisplayName, "renamed")
	}
	if original.Nodes[0].DisplayName != "" {
		t.Fatalf("original *WebConfig mutated in place: DisplayName = %q, want empty", original.Nodes[0].DisplayName)
	}
}

// TestConfigRef_ConcurrentLoadDuringStore is a direct smoke test for the
// actual concurrency property this type exists to provide.
func TestConfigRef_ConcurrentLoadDuringStore(t *testing.T) {
	ref := newConfigRef(&WebConfig{Nodes: []NodeConfig{{Name: "v0"}}})

	var wg sync.WaitGroup
	const writes = 5000

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < writes; i++ {
			ref.Store(&WebConfig{Nodes: []NodeConfig{{Name: "v"}}})
		}
	}()

	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < writes; i++ {
				cfg := ref.Load()
				if len(cfg.Nodes) != 1 || cfg.Nodes[0].Name == "" {
					t.Errorf("Load() returned an inconsistent snapshot: %+v", cfg)
					return
				}
			}
		}()
	}

	wg.Wait()
}
