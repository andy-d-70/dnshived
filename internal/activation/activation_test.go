// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package activation

import "testing"

func TestCompare(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int
		ok   bool
	}{
		{"equal", "0.9.8.8", "0.9.8.8", 0, true},
		{"older", "0.9.8.7", "0.9.8.8", -1, true},
		{"newer", "0.9.9.0", "0.9.8.8", 1, true},
		{"numeric not lexical", "0.9.10.0", "0.9.9.0", 1, true},
		{"missing part is zero", "0.9.9", "0.9.9.0", 0, true},
		{"leading v", "v0.9.9.0", "0.9.9.0", 0, true},
		{"tilde pre-release before release", "0.9.9.0~dev-3", "0.9.9.0", -1, true},
		{"pre-release after older release", "0.9.9.0~dev-3", "0.9.8.9", 1, true},
		{"dev numbers", "0.9.9.0~dev-10", "0.9.9.0~dev-9", 1, true},
		{"old dev suffix", "0.9.7-dev", "0.9.8.8", -1, true},
		{"empty", "", "0.9.9.0", 0, false},
		{"garbage", "unknown", "0.9.9.0", 0, false},
		{"negative part", "0.-1", "0.9", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Compare(tt.a, tt.b)
			if ok != tt.ok || got != tt.want {
				t.Errorf("Compare(%q, %q) = %d, %v; want %d, %v", tt.a, tt.b, got, ok, tt.want, tt.ok)
			}
			if tt.ok {
				rev, _ := Compare(tt.b, tt.a)
				if rev != -got {
					t.Errorf("not antisymmetric: %d vs %d", got, rev)
				}
			}
		})
	}
}

func TestEvaluate(t *testing.T) {
	const req = "0.9.9.0"
	up := func(name, v string) Member { return Member{Name: name, Role: "core-1", Version: v, Reachable: true} }
	tests := []struct {
		name    string
		members []Member
		active  bool
		blocked []string
	}{
		{"all at version", []Member{up("a", "0.9.9.0"), up("b", "0.9.9.1")}, true, nil},
		{"one older", []Member{up("a", "0.9.9.0"), up("b", "0.9.8.8")}, false, []string{"b"}},
		{"pre-release blocks", []Member{up("a", "0.9.9.0~dev-1")}, false, []string{"a"}},
		{"unreachable blocks", []Member{up("a", "0.9.9.0"), {Name: "b", Role: "core-2"}}, false, []string{"b"}},
		{"no version blocks", []Member{up("a", "")}, false, []string{"a"}},
		{"unreadable blocks", []Member{up("a", "weird")}, false, []string{"a"}},
		{"no members", nil, false, nil},
		{"blockers sorted", []Member{up("z", "0.1"), up("c", "0.1")}, false, []string{"c", "z"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Evaluate(req, tt.members)
			if res.Active != tt.active {
				t.Errorf("Active = %v, want %v", res.Active, tt.active)
			}
			var got []string
			for _, b := range res.Blocking {
				got = append(got, b.Name)
				if b.Reason == "" {
					t.Errorf("blocker %s has no reason", b.Name)
				}
			}
			if len(got) != len(tt.blocked) {
				t.Fatalf("blocking = %v, want %v", got, tt.blocked)
			}
			for i := range got {
				if got[i] != tt.blocked[i] {
					t.Errorf("blocking = %v, want %v", got, tt.blocked)
				}
			}
			if res.Required != req || res.Members != len(tt.members) {
				t.Errorf("Required=%q Members=%d", res.Required, res.Members)
			}
		})
	}
}
