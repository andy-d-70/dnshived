// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package changeset

import (
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"dnshived/internal/config"
)

func TestGet_FindsFieldsElementsAndGroups(t *testing.T) {
	c := base()
	c.APITokens = []config.APIToken{{Name: "ops", Token: "x"}}
	tr := tree(t, c)
	tests := []struct {
		name string
		path string
		ok   bool
		want any
	}{
		{"top field", "log_level", true, "info"},
		{"domain field", "local_domains/[a.lan]/ttl", true, nil},
		{"atomic group of two records", "local_domains/[a.lan]/records/[h1|A]", true, nil},
		{"reservation by mac", "scopes/office/reservations/[aa:aa:aa:aa:aa:01]", true, nil},
		{"missing field", "nope", false, nil},
		{"missing element", "local_domains/[z.lan]", false, nil},
		{"below an atomic group", "local_domains/[a.lan]/records/[h1|A]/value", false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, ok := Get(tr, tt.path)
			if ok != tt.ok {
				t.Fatalf("ok %v, want %v (value %v)", ok, tt.ok, v)
			}
			if tt.want != nil && !reflect.DeepEqual(v, tt.want) {
				t.Fatalf("value %v, want %v", v, tt.want)
			}
		})
	}
	if g, _ := Get(tr, "local_domains/[a.lan]/records/[h1|A]"); len(g.([]any)) != 2 {
		t.Fatalf("the group holds both records: %v", g)
	}
}

func TestSet_RefusesPathsThatDoNotFit(t *testing.T) {
	tests := []struct{ name, path string }{
		{"empty", ""},
		{"empty segment", "a//b"},
		{"below an atomic group", "local_domains/[a.lan]/records/[h1|A]/value"},
		{"unknown element below", "local_domains/[z.lan]/ttl"},
		{"keyed segment on a field", "log_level/[x]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Set(tree(t, base()), tt.path, "v"); !errors.Is(err, ErrPath) {
				t.Fatalf("err %v, want ErrPath", err)
			}
		})
	}
	if _, err := Set(tree(t, base()), "local_domains/[a.lan]/records/[h2|A]", []any{map[string]any{"host": "h9", "type": "A"}}); !errors.Is(err, ErrPath) {
		t.Fatal("an element with another key must be refused")
	}
}

func TestSet_RemovesAndAppendsLikeMerge(t *testing.T) {
	live := base()
	cand := base()
	cand.LocalDomains[0].Records = append(cand.LocalDomains[0].Records[2:], config.LocalDomainHost{Host: "h3", Type: "AAAA", Value: "fd00::3"})
	cand.LocalDomains = append(cand.LocalDomains, config.LocalDomain{Name: "c.lan", TTL: 30})
	cand.Scopes["office"] = config.ScopeConfig{}
	lt, ct := tree(t, live), tree(t, cand)
	got := applyAll(t, lt, ct)
	want := Merge(tree(t, live), ct, func(string) bool { return true })
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Set differs from Merge:\n%v\n%v", got, want)
	}
}

func applyAll(t *testing.T, live, cand any) any {
	t.Helper()
	for _, p := range Changes(live, cand) {
		v, _ := Get(cand, p)
		var err error
		if live, err = Set(live, p, v); err != nil {
			t.Fatalf("set %s: %v", p, err)
		}
	}
	return live
}

func randomCluster(rng *rand.Rand) config.Cluster {
	c := config.Cluster{LogLevel: []string{"info", "debug"}[rng.Intn(2)], Scopes: map[string]config.ScopeConfig{}}
	for d := range rng.Intn(4) {
		ld := config.LocalDomain{Name: fmt.Sprintf("d%d.lan", d), TTL: rng.Intn(3) * 60}
		for range rng.Intn(6) {
			ld.Records = append(ld.Records, config.LocalDomainHost{Host: fmt.Sprintf("h%d", rng.Intn(4)), Type: []string{"A", "AAAA", "TXT"}[rng.Intn(3)], Value: fmt.Sprint(rng.Intn(9))})
		}
		c.LocalDomains = append(c.LocalDomains, ld)
	}
	for s := range rng.Intn(4) {
		sc := config.ScopeConfig{VLANID: 10 + s, Gateway: fmt.Sprintf("10.%d.0.1", rng.Intn(3))}
		for r := range rng.Intn(5) {
			sc.Reservations = append(sc.Reservations, config.Reservation{MAC: fmt.Sprintf("aa:aa:aa:aa:%02x:%02x", s, r+rng.Intn(3)*10), IP: fmt.Sprintf("10.%d.0.%d", s, 5+rng.Intn(20)), Hostname: fmt.Sprintf("r%d", rng.Intn(5))})
		}
		for range rng.Intn(3) {
			sc.DNSRecords = append(sc.DNSRecords, config.DNSRecord{Name: fmt.Sprintf("n%d.d0.lan", rng.Intn(3)), Type: "A", Value: fmt.Sprintf("10.9.0.%d", rng.Intn(9))})
		}
		c.Scopes[fmt.Sprintf("s%d", rng.Intn(5))] = sc
	}
	for range rng.Intn(3) {
		c.GlobalDNSRecords = append(c.GlobalDNSRecords, config.DNSRecord{Name: fmt.Sprintf("g%d.lan", rng.Intn(3)), Type: "TXT", Value: fmt.Sprint(rng.Intn(3))})
	}
	return c
}

func TestSet_AppliesEveryChangeOfRandomDocuments(t *testing.T) {
	seed := time.Now().UnixNano()
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewSource(seed))
	for i := range 2000 {
		live, cand := randomCluster(rng), randomCluster(rng)
		lt, ct := tree(t, live), tree(t, cand)
		got := applyAll(t, lt, ct)
		if rest := Changes(got, ct); len(rest) != 0 {
			t.Fatalf("pair %d: changes left after applying all: %v", i, rest)
		}
		for _, p := range Changes(tree(t, live), ct) {
			v, ok := Get(got, p)
			w, wok := Get(ct, p)
			if ok != wok || !reflect.DeepEqual(v, w) {
				t.Fatalf("pair %d: %s is %v (%v), want %v (%v)", i, p, v, ok, w, wok)
			}
		}
	}
}

func TestSetAll_EqualsSetOneByOne(t *testing.T) {
	seed := time.Now().UnixNano()
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewSource(seed))
	for i := range 2000 {
		live, cand := randomCluster(rng), randomCluster(rng)
		ct := tree(t, cand)
		var ups []Update
		Each(tree(t, live), ct, func(p string, _, c any) { ups = append(ups, Update{Path: p, Value: c}) })
		got, err := SetAll(tree(t, live), ups)
		if err != nil {
			t.Fatalf("pair %d: %v", i, err)
		}
		if want := applyAll(t, tree(t, live), ct); !reflect.DeepEqual(got, want) {
			t.Fatalf("pair %d: SetAll differs from Set one by one", i)
		}
	}
}

func TestSetAll_ChecksAndRefuses(t *testing.T) {
	refuse := errors.New("refused")
	_, err := SetAll(tree(t, base()), []Update{{Path: "log_level", Value: "debug", Check: func(have any, present bool) error {
		if have != "info" || !present {
			t.Errorf("check sees %v %v", have, present)
		}
		return refuse
	}}})
	if !errors.Is(err, refuse) {
		t.Fatalf("err %v", err)
	}
	for _, ups := range [][]Update{
		{{Path: "log_level", Value: "a"}, {Path: "log_level", Value: "b"}},
		{{Path: "scopes/office", Value: nil}, {Path: "scopes/office/vlan_id", Value: 3}},
	} {
		if _, err := SetAll(tree(t, base()), ups); !errors.Is(err, ErrPath) {
			t.Errorf("%v: err %v", ups, err)
		}
	}
}

func TestStrip_LeavesOnlyWhatChangesCompares(t *testing.T) {
	c := base()
	c.NodeID, c.Role, c.ConfigRevision = "n1", "core-1", 9
	sc := c.Scopes["office"]
	sc.NodeIP = "10.1.0.2/24"
	c.Scopes["office"] = sc
	tr := tree(t, c)
	Strip(tr)
	m := tr.(map[string]any)
	for _, k := range []string{"node_id", "role", "config_revision", "peers"} {
		if _, ok := m[k]; ok {
			t.Errorf("%s left in", k)
		}
	}
	if _, ok := m["scopes"].(map[string]any)["office"].(map[string]any)["node_ip"]; ok {
		t.Error("node_ip left in")
	}
	if m["log_level"] != "info" {
		t.Error("a cluster-wide field was removed")
	}
	other := base()
	other.NodeID = "n2"
	ot := tree(t, other)
	Strip(ot)
	if !reflect.DeepEqual(tr, ot) {
		t.Fatal("two nodes with the same cluster-wide data must strip to the same document")
	}
}

func FuzzSetPath(f *testing.F) {
	f.Add("local_domains/[a.lan]/records/[h1|A]")
	f.Add("scopes/office/reservations/[x]/ip")
	f.Add("a/~1b/[~2]")
	f.Fuzz(func(t *testing.T, path string) {
		tr, err := Tree(base())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = Get(tr, path)
		_, _ = Set(tr, path, nil)
	})
}
