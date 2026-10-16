package main

import (
	"reflect"
	"strings"
	"testing"

	"dnshived/internal/config"
)

// The move itself comes first, ahead of every detail line.
func TestDiffScopeFields_PreferredCoreChangeIsFirst(t *testing.T) {
	old := config.ScopeConfig{Parent: "ens19", VLANID: 10, VIP: "10.0.0.254/24", PreferredWorker: "core-2", Color: "#111111"}
	nw := old
	nw.PreferredWorker = "core-1"
	nw.Color = "#222222"
	nw.NodeIPOverrides = map[string]string{"core-1": "10.0.0.22/24"}
	got := diffScopeFields(old, nw)
	if len(got) < 3 {
		t.Fatalf("diffs = %v, want the move plus details", got)
	}
	if !strings.HasPrefix(got[0], `preferred core: "core-2" → "core-1"`) {
		t.Errorf("first diff line = %q, want the preferred-core change on top", got[0])
	}
}

func TestDiffScopeFields_MoveOnlyIsOneLine(t *testing.T) {
	old := config.ScopeConfig{PreferredWorker: "core-3"}
	nw := old
	nw.PreferredWorker = "core-1"
	got := diffScopeFields(old, nw)
	if !reflect.DeepEqual(got, []string{`preferred core: "core-3" → "core-1"`}) {
		t.Errorf("diffs = %v", got)
	}
}

// Saving the edit form must not write derived node IPs back as overrides.
func TestNodeIPOverridesToPersist(t *testing.T) {
	derived := map[string]string{"core-1": "10.0.0.22/24", "core-2": "10.0.0.23/24", "core-3": "10.0.0.43/24"}

	// Form re-submits exactly what the page derived → nothing stored.
	if got := nodeIPOverridesToPersist(nil, map[string]string{"core-1": "10.0.0.22/24", "core-2": "10.0.0.23/24", "core-3": "10.0.0.43/24"}, derived); len(got) != 0 {
		t.Errorf("unchanged derived values were persisted as overrides: %v", got)
	}
	// A real choice (differs from derived) is stored; the rest are not.
	got := nodeIPOverridesToPersist(nil, map[string]string{"core-1": "10.0.0.99/24", "core-2": "10.0.0.23/24"}, derived)
	if !reflect.DeepEqual(got, map[string]string{"core-1": "10.0.0.99/24"}) {
		t.Errorf("got %v, want only core-1's real override", got)
	}
	// An existing override is kept even if it now equals the derived value.
	got = nodeIPOverridesToPersist(map[string]string{"core-2": "10.0.0.23/24"}, map[string]string{"core-2": "10.0.0.23/24"}, derived)
	if !reflect.DeepEqual(got, map[string]string{"core-2": "10.0.0.23/24"}) {
		t.Errorf("got %v, want the pre-existing override preserved", got)
	}
	// Blank means cleared (absent from submitted → not stored).
	if got := nodeIPOverridesToPersist(map[string]string{"core-1": "10.0.0.99/24"}, map[string]string{}, derived); len(got) != 0 {
		t.Errorf("got %v, want the override cleared", got)
	}
}
