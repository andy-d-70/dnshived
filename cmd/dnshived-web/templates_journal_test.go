// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"dnshived/internal/cfgjournal"
)

// fakeShared is the daemon's shared document as two web instances see it, with the journal's apply rules.
type fakeShared struct {
	mu   sync.Mutex
	tree any
	rev  uint64
}

func newFakeShared() *fakeShared {
	return &fakeShared{tree: map[string]any{"templates": []any{}, "option_sets": []any{}, "scope_groups": []any{}}}
}

func (f *fakeShared) share() *templateShare {
	return &templateShare{
		active: func() bool { return true },
		get: func() (uint64, any, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			raw, _ := jsonRoundTrip(f.tree)
			return f.rev, raw, nil
		},
		post: func(_ string, changes []cfgjournal.Entry) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			cp, _ := jsonRoundTrip(f.tree)
			recs := make([]cfgjournal.Record, len(changes))
			for i := range changes {
				recs[i] = cfgjournal.Record{Entry: changes[i]}
			}
			out, err := cfgjournal.Apply(cp, recs)
			if err != nil {
				return err
			}
			f.tree, f.rev = out, f.rev+1
			return nil
		},
	}
}

func jsonRoundTrip(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return cfgjournal.DecodeTree(raw)
}

func storeWith(ts ...Template) *TemplateStore { return &TemplateStore{Templates: ts} }

func tplIDs(s *TemplateStore) string {
	var out []string
	for _, t := range s.Templates {
		out = append(out, t.ID+"="+t.Body)
	}
	return strings.Join(out, ",")
}

func TestTemplateShare_JoinMergesAndKeepsDifferingCopies(t *testing.T) {
	f := newFakeShared()
	w1, w2 := f.share(), f.share()
	s1 := storeWith(Template{ID: "cams", Name: "Cams", Kind: "dns", Body: "A"})
	s2 := storeWith(Template{ID: "mics", Name: "Mics", Kind: "dns", Body: "M"}, Template{ID: "cams", Name: "Cams", Kind: "dns", Body: "B"})
	w1.refresh(s1)
	w2.refresh(s2)
	w1.refresh(s1)
	for _, s := range []*TemplateStore{s1, s2} {
		got := tplIDs(s)
		if !strings.Contains(got, "cams=A") || !strings.Contains(got, "mics=M") || !strings.Contains(got, "cams-local-1=B") {
			t.Fatalf("every template survives the join, the differing one as a copy: %s", got)
		}
	}
}

func TestTemplateShare_EditsOnDifferentTemplatesBothStaySameOneCollides(t *testing.T) {
	f := newFakeShared()
	w1, w2 := f.share(), f.share()
	s1 := storeWith(Template{ID: "cams", Kind: "dns", Body: "A"}, Template{ID: "mics", Kind: "dns", Body: "M"})
	s2 := &TemplateStore{}
	w1.refresh(s1)
	w2.refresh(s2)
	s1.Upsert("cams", "", "", "dns", "A2")
	s2.Upsert("mics", "", "", "dns", "M2")
	if err := w1.save(s1, "ann"); err != nil {
		t.Fatal(err)
	}
	if err := w2.save(s2, "bob"); err != nil {
		t.Fatalf("bob changed another template: %v", err)
	}
	w1.refresh(s1)
	if got := tplIDs(s1); !strings.Contains(got, "cams=A2") || !strings.Contains(got, "mics=M2") {
		t.Fatalf("both edits: %s", got)
	}
	s1.Upsert("cams", "", "", "dns", "A3")
	s2.Upsert("cams", "", "", "dns", "B3")
	if err := w1.save(s1, "ann"); err != nil {
		t.Fatal(err)
	}
	if err := w2.save(s2, "bob"); !errors.Is(err, errTemplateConflict) {
		t.Fatalf("bob's change of the template ann just changed must collide: %v", err)
	}
	if got := tplIDs(s2); !strings.Contains(got, "cams=A3") {
		t.Fatalf("after the refusal bob's store shows the shared state: %s", got)
	}
}

func TestTemplateShare_RefreshNeverDropsAnUnsavedChange(t *testing.T) {
	f := newFakeShared()
	w1, w2 := f.share(), f.share()
	s1, s2 := storeWith(Template{ID: "cams", Kind: "dns", Body: "A"}), &TemplateStore{}
	w1.refresh(s1)
	w2.refresh(s2)
	s1.Upsert("", "new", "", "dns", "N")
	s2.Upsert("", "other", "", "dns", "O")
	if err := w2.save(s2, "bob"); err != nil {
		t.Fatal(err)
	}
	w1.refresh(s1)
	if got := tplIDs(s1); !strings.Contains(got, "new=N") {
		t.Fatalf("an unsaved change must survive a refresh: %s", got)
	}
	if err := w1.save(s1, "ann"); err != nil {
		t.Fatal(err)
	}
	w1.refresh(s1)
	if got := tplIDs(s1); !strings.Contains(got, "new=N") || !strings.Contains(got, "other=O") {
		t.Fatalf("both changes end up shared: %s", got)
	}
}
