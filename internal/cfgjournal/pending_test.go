// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package cfgjournal

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"dnshived/internal/changeset"
	"dnshived/internal/config"
)

func repl(t *testing.T, c config.Cluster) any {
	t.Helper()
	r, err := Replicated(&c)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func changesOn(t *testing.T, pd Pending, live any, edit func(c *config.Cluster)) []Entry {
	t.Helper()
	mat, err := pd.Materialize(live)
	if err != nil {
		t.Fatal(err)
	}
	var c config.Cluster
	b, _ := encodeTree(mat)
	if err := jsonUnmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	edit(&c)
	es, err := FromChange("cluster", mat, repl(t, c), 0)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

// applyPending applies pending-document entries the way the writer does and returns the new Pending.
func applyPending(t *testing.T, pd Pending, es []Entry) (Pending, error) {
	t.Helper()
	tr, err := pd.tree()
	if err != nil {
		t.Fatal(err)
	}
	recs := make([]Record, len(es))
	for i := range es {
		recs[i] = Record{Entry: es[i]}
	}
	out, err := Apply(tr, recs)
	if err != nil {
		return nil, err
	}
	return PendingFromTree(out)
}

func stage(t *testing.T, pd Pending, live any, who string, edit func(c *config.Cluster)) []Entry {
	t.Helper()
	es, err := pd.Stage(live, changesOn(t, pd, live, edit), who, 1)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

func TestPending_StageMaterialiseAndUnstage(t *testing.T) {
	live := repl(t, cluster(nil))
	pd, err := applyPending(t, Pending{}, stage(t, Pending{}, live, "ann", func(c *config.Cluster) { c.LogLevel = "debug" }))
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := pd["log_level"]; !ok || string(s.Base) != `"info"` || string(s.New) != `"debug"` || s.Author != "ann" || len(pd) != 1 {
		t.Fatalf("pending %+v", pd)
	}
	back, err := applyPending(t, pd, stage(t, pd, live, "ann", func(c *config.Cluster) { c.LogLevel = "info" }))
	if err != nil || len(back) != 0 {
		t.Fatalf("an item set back to its base leaves Pending: %+v %v", back, err)
	}
}

func TestPending_TwoOperatorsOnDifferentItemsBothStay(t *testing.T) {
	live := repl(t, cluster(nil))
	a := stage(t, Pending{}, live, "ann", func(c *config.Cluster) { c.LogLevel = "debug" })
	b := stage(t, Pending{}, live, "bob", func(c *config.Cluster) {
		c.GlobalDNSRecords = []config.DNSRecord{{Name: "ntp.lan", Type: "A", Value: "10.0.0.9"}}
	})
	pd, err := applyPending(t, Pending{}, a)
	if err != nil {
		t.Fatal(err)
	}
	if pd, err = applyPending(t, pd, b); err != nil {
		t.Fatalf("bob staged another item at the same moment: %v", err)
	}
	if pd["log_level"].Author != "ann" || len(pd) != 2 {
		t.Fatalf("both changes must stay: %+v", pd)
	}
}

func TestPending_TwoOperatorsOnTheSameItemCollide(t *testing.T) {
	live := repl(t, cluster(nil))
	a := stage(t, Pending{}, live, "ann", func(c *config.Cluster) { c.LogLevel = "debug" })
	b := stage(t, Pending{}, live, "bob", func(c *config.Cluster) { c.LogLevel = "warn" })
	pd, err := applyPending(t, Pending{}, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applyPending(t, pd, b); !errors.Is(err, ErrConflict) {
		t.Fatalf("the second change of the same item must collide: %v", err)
	}
}

func TestPending_AChangeOnAnOutdatedViewIsRefused(t *testing.T) {
	live := repl(t, cluster(nil))
	pd, _ := applyPending(t, Pending{}, stage(t, Pending{}, live, "ann", func(c *config.Cluster) { c.LogLevel = "debug" }))
	stale := []Entry{{Doc: "cluster", Path: "log_level", Old: []byte(`"info"`), New: []byte(`"warn"`)}}
	if _, err := pd.Stage(live, stale, "bob", 2); !errors.Is(err, ErrConflict) {
		t.Fatalf("bob's view still showed info: %v", err)
	}
}

func TestPending_CommitNeverRevertsAnotherCommit(t *testing.T) {
	live := repl(t, cluster(nil))
	pd, _ := applyPending(t, Pending{}, stage(t, Pending{}, live, "ann", func(c *config.Cluster) { c.LogLevel = "debug" }))
	other := cluster(func(c *config.Cluster) {
		c.GlobalDNSRecords = []config.DNSRecord{{Name: "x.lan", Type: "A", Value: "10.0.0.7"}}
	})
	liveAfter := repl(t, other)
	recs := []Record{}
	for _, e := range pd.Commit("cluster", func(string, Staged) bool { return true }) {
		recs = append(recs, Record{Entry: e})
	}
	got, err := Apply(deepCopy(liveAfter), recs)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := changeset.Get(got, "log_level"); v != "debug" {
		t.Fatalf("the staged change: %v", v)
	}
	if _, ok := changeset.Get(got, "global_dns_records/[x.lan|A]"); !ok {
		t.Fatal("the other commit's record must stay")
	}
	moved := repl(t, cluster(func(c *config.Cluster) { c.LogLevel = "error" }))
	if _, err := Apply(moved, recs); !errors.Is(err, ErrConflict) {
		t.Fatalf("a staged item that moved in the live configuration must collide: %v", err)
	}
}

func TestPending_EditInsideANewScopeStaysOneItem(t *testing.T) {
	live := repl(t, cluster(nil))
	pd, _ := applyPending(t, Pending{}, stage(t, Pending{}, live, "ann", func(c *config.Cluster) { c.Scopes["lab"] = config.ScopeConfig{VLANID: 30} }))
	pd, err := applyPending(t, pd, stage(t, pd, live, "bob", func(c *config.Cluster) {
		sc := c.Scopes["lab"]
		sc.Gateway = "10.30.0.1"
		c.Scopes["lab"] = sc
	}))
	if err != nil {
		t.Fatal(err)
	}
	s, ok := pd["scopes/lab"]
	if !ok || len(pd) != 1 || s.Base != nil {
		t.Fatalf("pending %+v", pd)
	}
	mat, _ := pd.Materialize(live)
	if v, _ := changeset.Get(mat, "scopes/lab/gateway"); v != "10.30.0.1" {
		t.Fatalf("materialised gateway %v", v)
	}
}

func TestPending_DiscardOnlyMine(t *testing.T) {
	live := repl(t, cluster(nil))
	pd, _ := applyPending(t, Pending{}, stage(t, Pending{}, live, "ann", func(c *config.Cluster) { c.LogLevel = "debug" }))
	pd, _ = applyPending(t, pd, stage(t, pd, live, "bob", func(c *config.Cluster) {
		c.GlobalDNSRecords = []config.DNSRecord{{Name: "y.lan", Type: "A", Value: "10.0.0.8"}}
	}))
	es, err := pd.Discard(func(_ string, s Staged) bool { return s.Author == "ann" })
	if err != nil {
		t.Fatal(err)
	}
	pd, err = applyPending(t, pd, es)
	if err != nil || len(pd) != 1 || pd["log_level"].Author != "" {
		t.Fatalf("after discarding ann's change: %+v %v", pd, err)
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func randomEdit(rng *rand.Rand) func(c *config.Cluster) {
	switch rng.Intn(5) {
	case 0:
		lvl := []string{"info", "debug", "warn", "error"}[rng.Intn(4)]
		return func(c *config.Cluster) { c.LogLevel = lvl }
	case 1:
		n := fmt.Sprintf("g%d.lan", rng.Intn(4))
		v := fmt.Sprintf("10.0.9.%d", rng.Intn(4))
		return func(c *config.Cluster) {
			c.GlobalDNSRecords = append(append([]config.DNSRecord(nil), c.GlobalDNSRecords...), config.DNSRecord{Name: n, Type: "TXT", Value: v})
		}
	case 2:
		return func(c *config.Cluster) {
			if len(c.GlobalDNSRecords) > 0 {
				c.GlobalDNSRecords = append([]config.DNSRecord(nil), c.GlobalDNSRecords[1:]...)
			}
		}
	case 3:
		name := fmt.Sprintf("s%d", rng.Intn(3))
		vlan := 10 + rng.Intn(5)
		return func(c *config.Cluster) {
			if c.Scopes == nil {
				c.Scopes = map[string]config.ScopeConfig{}
			}
			sc := c.Scopes[name]
			sc.VLANID = vlan
			c.Scopes[name] = sc
		}
	}
	name := fmt.Sprintf("s%d", rng.Intn(3))
	return func(c *config.Cluster) { delete(c.Scopes, name) }
}

func TestPending_RandomStagingKeepsMaterialisedAndBaseExact(t *testing.T) {
	seed := time.Now().UnixNano()
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewSource(seed))
	for round := range 300 {
		live := repl(t, cluster(nil))
		pd := Pending{}
		want := deepCopy(live)
		for step := range 1 + rng.Intn(8) {
			who := []string{"ann", "bob", "cy"}[rng.Intn(3)]
			changes := changesOn(t, pd, live, randomEdit(rng))
			es, err := pd.Stage(live, changes, who, int64(step))
			if err != nil {
				t.Fatalf("round %d step %d: stage: %v", round, step, err)
			}
			if pd, err = applyPending(t, pd, es); err != nil {
				t.Fatalf("round %d step %d: apply: %v", round, step, err)
			}
			recs := make([]Record, len(changes))
			for i := range changes {
				recs[i] = Record{Entry: changes[i]}
			}
			if want, err = Apply(want, recs); err != nil {
				t.Fatal(err)
			}
			mat, err := pd.Materialize(live)
			if err != nil {
				t.Fatal(err)
			}
			if rest := changeset.Changes(mat, want); len(rest) != 0 {
				t.Fatalf("round %d step %d: materialised differs at %v", round, step, rest)
			}
			for p, s := range pd {
				v, ok := changeset.Get(live, p)
				if same, _ := sameValue(v, ok, s.Base); !same {
					t.Fatalf("round %d: base of %s is %s, live holds %v", round, p, s.Base, v)
				}
			}
		}
	}
}
