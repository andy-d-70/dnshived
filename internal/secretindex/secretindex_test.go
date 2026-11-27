// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package secretindex

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"dnshived/internal/cfgjournal"
)

func emptyTree() any {
	return map[string]any{"users": map[string]any{}, "probe_hosts": map[string]any{}, "nodes": map[string]any{}}
}

func apply(t *testing.T, tree any, es []cfgjournal.Entry) (any, error) {
	t.Helper()
	recs := make([]cfgjournal.Record, len(es))
	for i := range es {
		recs[i] = cfgjournal.Record{Rev: 1, Entry: es[i]}
	}
	raw, _ := cfgjournal.DecodeTree(mustJSON(t, tree))
	return cfgjournal.Apply(raw, recs)
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := jsonMarshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var at = time.Date(2026, 11, 27, 10, 14, 0, 0, time.UTC)

func TestPlan_FirstWinsTheSecondOnTheSameBaseIsRefused(t *testing.T) {
	base := map[string][]byte{"user/bob": []byte(`{"name":"bob","role":"scopeadmin"}`)}
	ann := map[string][]byte{"user/bob": []byte(`{"name":"bob","role":"admin"}`)}
	adm := map[string][]byte{"user/bob": []byte(`{"name":"bob","role":"scopeadmin","disabled":true}`)}
	tree := emptyTree()

	first, err := Plan(tree, "users", base, ann, nil, "core1", at, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Plan(tree, "users", base, adm, nil, "core2", at, false)
	if err != nil {
		t.Fatal(err)
	}
	tree, err = apply(t, tree, first)
	if err != nil {
		t.Fatalf("the first change applies: %v", err)
	}
	if _, err := apply(t, tree, second); !errors.Is(err, cfgjournal.ErrConflict) {
		t.Fatalf("a second change from the same base is refused by the journal: %v", err)
	}
	if _, err := Plan(tree, "users", base, adm, nil, "core2", at, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("planned again on the newer index it is refused before sending: %v", err)
	}
	var ce *ConflictError
	_, err = Plan(tree, "users", base, adm, nil, "core2", at, false)
	if !errors.As(err, &ce) || ce.Entry.By != "core1" || ce.Key != "user/bob" {
		t.Fatalf("the refusal names the item and who changed it: %v", err)
	}
	if _, err := Plan(tree, "users", ann, adm, nil, "core2", at, false); err != nil {
		t.Fatalf("a change based on the current version is fine: %v", err)
	}
}

func TestPlan_DifferentItemsDoNotCollide(t *testing.T) {
	base := map[string][]byte{"user/bob": []byte(`{"name":"bob"}`), "user/eve": []byte(`{"name":"eve"}`)}
	a := map[string][]byte{"user/bob": []byte(`{"name":"bob","role":"admin"}`), "user/eve": base["user/eve"]}
	b := map[string][]byte{"user/bob": base["user/bob"], "user/eve": []byte(`{"name":"eve","role":"admin"}`)}
	tree := emptyTree()
	pa, _ := Plan(tree, "users", base, a, nil, "core1", at, false)
	pb, _ := Plan(tree, "users", base, b, nil, "core2", at, false)
	tree, err := apply(t, tree, pa)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apply(t, tree, pb); err != nil {
		t.Fatalf("changes of different users both apply: %v", err)
	}
}

func TestPlan_DeleteAgainstEditAndForce(t *testing.T) {
	base := map[string][]byte{"user/bob": []byte(`{"name":"bob"}`)}
	gone := map[string][]byte{}
	edit := map[string][]byte{"user/bob": []byte(`{"name":"bob","role":"admin"}`)}
	tree := emptyTree()
	del, _ := Plan(tree, "users", base, gone, nil, "core1", at, false)
	tree, err := apply(t, tree, del)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Plan(tree, "users", base, edit, nil, "core2", at, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("editing a user someone deleted is refused: %v", err)
	}
	forced, err := Plan(tree, "users", base, edit, nil, "console", at, true)
	if err != nil {
		t.Fatal(err)
	}
	if tree, err = apply(t, tree, forced); err != nil {
		t.Fatalf("a forced change applies on whatever the index holds: %v", err)
	}
	idx, _ := Parse(tree, "users")
	if idx["user/bob"].Hash != Hash(edit["user/bob"]) || idx["user/bob"].Deleted {
		t.Fatalf("index after force: %+v", idx["user/bob"])
	}
}

func TestReconcile_TakesWhatTheIndexNames(t *testing.T) {
	v1, v2, v3 := []byte(`{"v":1}`), []byte(`{"v":2}`), []byte(`{"v":3}`)
	idx := Index{
		"user/a": {Hash: Hash(v2)},
		"user/b": {Hash: Hash(v2)},
		"user/c": {Hash: Hash(v3)},
		"user/d": {Deleted: true},
	}
	local := map[string][]byte{"user/a": v1, "user/b": v2, "user/c": v1, "user/d": v1, "user/e": v1, "user/k": v1}
	incoming := map[string][]byte{"user/a": v2, "user/b": v1, "user/c": v2, "user/d": v1, "user/f": v1, "user/k": v2}
	out, refused, missing := Reconcile(idx, local, incoming, map[string]bool{"user/k": true})
	want := map[string][]byte{
		"user/a": v2,
		"user/b": v2,
		"user/c": v2,
		"user/f": v1,
		"user/k": v1,
	}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("reconciled:\n%q\nwant\n%q", out, want)
	}
	wantRefused := []string{"user/b", "user/d", "user/k"}
	if !reflect.DeepEqual(refused, wantRefused) {
		t.Fatalf("refused %v, want %v", refused, wantRefused)
	}
	if !reflect.DeepEqual(missing, []string{"user/c"}) {
		t.Fatalf("an indexed content neither side holds is reported, and the incoming copy followed so both converge: %v", missing)
	}
	back, refusedBack, _ := Reconcile(idx, incoming, out, nil)
	if len(refusedBack) != 0 && !reflect.DeepEqual(refusedBack, []string{"user/k"}) {
		t.Fatalf("the other side takes the result without refusing anything but the forced item: %v %q", refusedBack, back)
	}
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
