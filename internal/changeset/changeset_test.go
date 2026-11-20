// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package changeset

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func tree(t *testing.T, c config.Cluster) any {
	t.Helper()
	v, err := Tree(c)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func back(t *testing.T, v any) config.Cluster {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var c config.Cluster
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func base() config.Cluster {
	return config.Cluster{
		LogLevel: "info",
		LocalDomains: []config.LocalDomain{
			{Name: "a.lan", TTL: 60, Records: []config.LocalDomainHost{
				{Host: "h1", Type: "A", Value: "10.0.0.1"},
				{Host: "h1", Type: "A", Value: "10.0.0.2"},
				{Host: "h2", Type: "A", Value: "10.0.0.3"},
			}},
			{Name: "b.lan"},
		},
		Scopes: map[string]config.ScopeConfig{
			"office": {Reservations: []config.Reservation{{MAC: "aa:aa:aa:aa:aa:01", IP: "10.1.0.5"}}},
		},
	}
}

func TestChangesIgnoresIdentityAndRevision(t *testing.T) {
	live, cand := base(), base()
	cand.ConfigRevision = 9
	cand.NodeID = "x"
	cand.Peers = []string{"p"}
	if got := Changes(tree(t, live), tree(t, cand)); len(got) != 0 {
		t.Fatalf("changes = %v", got)
	}
}

func TestChangesFieldLevel(t *testing.T) {
	live, cand := base(), base()
	cand.LogLevel = "debug"
	cand.LocalDomains[0].TTL = 120
	cand.LocalDomains[0].Records[2].Value = "10.0.0.9"
	cand.LocalDomains = append(cand.LocalDomains, config.LocalDomain{Name: "c.lan"})
	sc := cand.Scopes["office"]
	sc.Reservations = append(sc.Reservations, config.Reservation{MAC: "aa:aa:aa:aa:aa:02", IP: "10.1.0.6"})
	cand.Scopes["office"] = sc

	got := strings.Join(Changes(tree(t, live), tree(t, cand)), "\n")
	for _, want := range []string{
		"log_level",
		"local_domains/[a.lan]/ttl",
		"local_domains/[a.lan]/records/[h2|A]",
		"local_domains/[c.lan]",
		"scopes/office/reservations/[aa:aa:aa:aa:aa:02]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "h1|A") || strings.Contains(got, "[b.lan]") {
		t.Errorf("unchanged units reported:\n%s", got)
	}
}

func TestRRsetIsOneUnit(t *testing.T) {
	live, cand := base(), base()
	cand.LocalDomains[0].Records[1].Value = "10.0.0.8"
	got := Changes(tree(t, live), tree(t, cand))
	if len(got) != 1 || !strings.HasSuffix(got[0], "[h1|A]") {
		t.Fatalf("changes = %v", got)
	}
}

func TestMergeTakesOnlyPicked(t *testing.T) {
	live, cand := base(), base()
	cand.LogLevel = "debug"
	cand.LocalDomains[0].TTL = 120
	cand.LocalDomains[0].Records = cand.LocalDomains[0].Records[:2]
	cand.LocalDomains = append(cand.LocalDomains, config.LocalDomain{Name: "c.lan"})
	delete(cand.Scopes, "office")

	mine := map[string]bool{"local_domains/[a.lan]/ttl": true, "local_domains/[c.lan]": true}
	got := back(t, Merge(tree(t, live), tree(t, cand), func(p string) bool { return mine[p] }))

	if got.LogLevel != "info" {
		t.Errorf("log level taken: %q", got.LogLevel)
	}
	if got.LocalDomains[0].TTL != 120 {
		t.Errorf("ttl not taken")
	}
	if len(got.LocalDomains[0].Records) != 3 {
		t.Errorf("records changed: %d", len(got.LocalDomains[0].Records))
	}
	if len(got.LocalDomains) != 3 || got.LocalDomains[2].Name != "c.lan" {
		t.Errorf("domains = %+v", got.LocalDomains)
	}
	if _, ok := got.Scopes["office"]; !ok {
		t.Errorf("scope removed although not picked")
	}
}

func TestMergeAllEqualsCandidate(t *testing.T) {
	live, cand := base(), base()
	cand.LogLevel = "debug"
	cand.LocalDomains = cand.LocalDomains[1:]
	cand.LocalDomains[0].TTL = 5
	sc := cand.Scopes["office"]
	sc.Reservations = nil
	cand.Scopes["office"] = sc
	got := back(t, Merge(tree(t, live), tree(t, cand), func(string) bool { return true }))
	if !reflect.DeepEqual(got, cand) {
		t.Fatalf("got %+v\nwant %+v", got, cand)
	}
}

func TestMergeNonePickedEqualsLive(t *testing.T) {
	live, cand := base(), base()
	cand.LogLevel = "debug"
	cand.LocalDomains[0].Records = nil
	got := back(t, Merge(tree(t, live), tree(t, cand), func(string) bool { return false }))
	if !reflect.DeepEqual(got, live) {
		t.Fatalf("got %+v", got)
	}
}

func TestPathEscaping(t *testing.T) {
	live, cand := base(), base()
	cand.LocalDomains = append(cand.LocalDomains, config.LocalDomain{Name: "x/[y].lan"})
	got := Changes(tree(t, live), tree(t, cand))
	if len(got) != 1 || strings.Count(got[0], "/") != 1 {
		t.Fatalf("changes = %v", got)
	}
}

func BenchmarkChangesLarge(b *testing.B) {
	c := config.Cluster{}
	for d := 0; d < 500; d++ {
		ld := config.LocalDomain{Name: "d" + string(rune('a'+d%26)) + strings.Repeat("x", d%7) + string(rune('0'+d/26%10)) + ".lan"}
		for h := 0; h < 250; h++ {
			ld.Records = append(ld.Records, config.LocalDomainHost{Host: "h" + strings.Repeat("a", h%9) + string(rune('0'+h%10)) + string(rune('a'+h/10%26)), Type: "A", Value: "10.0.0.1"})
		}
		c.LocalDomains = append(c.LocalDomains, ld)
	}
	l, _ := Tree(c)
	cc := c
	cc.LogLevel = "debug"
	n, _ := Tree(cc)
	b.ResetTimer()
	for b.Loop() {
		Changes(l, n)
	}
}

func TestAttributeKeepsAndOverwrites(t *testing.T) {
	live := base()
	a := base()
	a.LogLevel = "debug"
	a.LocalDomains[0].TTL = 120
	ja := Attribute(tree(t, live), tree(t, live), tree(t, a), "alice", nil)
	if ja["log_level"] != "alice" || ja["local_domains/[a.lan]/ttl"] != "alice" {
		t.Fatalf("journal = %v", ja)
	}

	b := a
	b.LocalDomains = append([]config.LocalDomain(nil), a.LocalDomains...)
	b.LocalDomains[1].TTL = 30
	jb := Attribute(tree(t, live), tree(t, a), tree(t, b), "bob", ja)
	if jb["log_level"] != "alice" || jb["local_domains/[b.lan]/ttl"] != "bob" {
		t.Fatalf("journal = %v", jb)
	}

	c := b
	c.LogLevel = "info"
	jc := Attribute(tree(t, live), tree(t, b), tree(t, c), "bob", jb)
	if _, ok := jc["log_level"]; ok {
		t.Fatalf("reverted field still listed: %v", jc)
	}
}

func TestAttributeSharedUnitIsMixed(t *testing.T) {
	live := base()
	a := base()
	a.LocalDomains = append(append([]config.LocalDomain(nil), a.LocalDomains...), config.LocalDomain{Name: "c.lan"})
	ja := Attribute(tree(t, live), tree(t, live), tree(t, a), "alice", nil)

	b := a
	b.LocalDomains = append([]config.LocalDomain(nil), a.LocalDomains...)
	b.LocalDomains[2].TTL = 9
	jb := Attribute(tree(t, live), tree(t, a), tree(t, b), "bob", ja)
	if jb["local_domains/[c.lan]"] != Mixed {
		t.Fatalf("journal = %v", jb)
	}
	if got := Mine(tree(t, live), tree(t, b), jb, "alice"); len(got) != 0 {
		t.Fatalf("mixed unit counted as mine: %v", got)
	}
}

func TestAttributeUnknownAuthorClears(t *testing.T) {
	live := base()
	a := base()
	a.LogLevel = "debug"
	ja := Attribute(tree(t, live), tree(t, live), tree(t, a), "alice", nil)
	b := a
	b.LogLevel = "warn"
	jb := Attribute(tree(t, live), tree(t, a), tree(t, b), "", ja)
	if _, ok := jb["log_level"]; ok {
		t.Fatalf("journal = %v", jb)
	}
}

func TestPruneAndMine(t *testing.T) {
	live := base()
	a := base()
	a.LogLevel = "debug"
	j := map[string]string{"log_level": "alice", "gone": "alice"}
	if got := Prune(tree(t, live), tree(t, a), j); len(got) != 1 {
		t.Fatalf("prune = %v", got)
	}
	if got := Mine(tree(t, live), tree(t, a), j, "alice"); len(got) != 1 || got[0] != "log_level" {
		t.Fatalf("mine = %v", got)
	}
	if got := Mine(tree(t, live), tree(t, a), j, ""); len(got) != 0 {
		t.Fatalf("mine for empty user = %v", got)
	}
}

func TestFirstScopesAreSeparateUnits(t *testing.T) {
	live := config.Cluster{}
	cand := config.Cluster{Scopes: map[string]config.ScopeConfig{"a": {}, "b": {}}}
	got := Changes(tree(t, live), tree(t, cand))
	if len(got) != 2 || got[0] != "scopes/a" || got[1] != "scopes/b" {
		t.Fatalf("changes = %v", got)
	}
	merged := back(t, Merge(tree(t, live), tree(t, cand), func(p string) bool { return p == "scopes/a" }))
	if _, ok := merged.Scopes["a"]; !ok || len(merged.Scopes) != 1 {
		t.Fatalf("scopes = %v", merged.Scopes)
	}
}

func TestNodeIPIsPerNodeAndIgnored(t *testing.T) {
	live := config.Cluster{Scopes: map[string]config.ScopeConfig{"a": {NodeIP: "10.0.0.2/24"}}}
	cand := config.Cluster{Scopes: map[string]config.ScopeConfig{"a": {NodeIP: "10.0.0.3/24"}}}
	if got := Changes(tree(t, live), tree(t, cand)); len(got) != 0 {
		t.Fatalf("changes = %v", got)
	}
}
