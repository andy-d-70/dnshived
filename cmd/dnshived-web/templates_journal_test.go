// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"errors"
	"fmt"
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

func TestTemplateShare_AFailedJoinKeepsTheLocalTemplatesAndRetries(t *testing.T) {
	f := newFakeShared()
	w := f.share()
	fail := true
	post := w.post
	w.post = func(author string, changes []cfgjournal.Entry) error {
		if fail {
			return errors.New("the leading core does not know the templates document yet")
		}
		return post(author, changes)
	}
	s := storeWith(Template{ID: "cams", Name: "Cams", Kind: "dns", Body: "A"})
	w.refresh(s)
	if got := tplIDs(s); got != "cams=A" || w.joined {
		t.Fatalf("a failed join must keep the local templates and not join: %q joined=%v", got, w.joined)
	}
	if err := w.save(s, "ann"); err != nil {
		t.Fatal(err)
	}
	fail = false
	w.refresh(s)
	if got := tplIDs(s); got != "cams=A" || !w.joined {
		t.Fatalf("the next refresh joins with the local templates: %q joined=%v", got, w.joined)
	}
	if _, remote, _ := w.get(); !strings.Contains(fmt.Sprint(remote), "cams") {
		t.Fatalf("the shared document now holds the template: %v", remote)
	}
}

func sharedTpls(t *testing.T, w *templateShare) string {
	t.Helper()
	_, remote, err := w.get()
	if err != nil {
		t.Fatal(err)
	}
	s, err := parseTemplates(remote)
	if err != nil {
		t.Fatal(err)
	}
	return tplIDs(s)
}

func TestTemplateShare_EditDuringJoinIsKeptAndShared(t *testing.T) {
	f := newFakeShared()
	w := f.share()
	s := storeWith(Template{ID: "cams", Kind: "dns", Body: "A"})
	post := w.post
	once := true
	w.post = func(author string, changes []cfgjournal.Entry) error {
		if once {
			once = false
			s.Upsert("", "edit", "", "dns", "E")
		}
		return post(author, changes)
	}
	w.refresh(s)
	if got := tplIDs(s); !strings.Contains(got, "edit=E") {
		t.Fatalf("an edit made while joining must stay: %s", got)
	}
	w.refresh(s)
	if !w.joined {
		t.Fatal("the next refresh joins")
	}
	if got := sharedTpls(t, w); !strings.Contains(got, "edit=E") || !strings.Contains(got, "cams=A") {
		t.Fatalf("the edit reaches the shared document: %s", got)
	}
}

func TestTemplateShare_EditDuringFollowIsKeptAndShared(t *testing.T) {
	f := newFakeShared()
	w1, w2 := f.share(), f.share()
	s1, s2 := storeWith(Template{ID: "cams", Kind: "dns", Body: "A"}), &TemplateStore{}
	w1.refresh(s1)
	w2.refresh(s2)
	s2.Upsert("", "other", "", "dns", "O")
	if err := w2.save(s2, "bob"); err != nil {
		t.Fatal(err)
	}
	get := w1.get
	w1.get = func() (uint64, any, error) {
		rev, tree, err := get()
		s1.Upsert("", "edit", "", "dns", "E")
		return rev, tree, err
	}
	w1.refresh(s1)
	w1.get = get
	if got := tplIDs(s1); !strings.Contains(got, "edit=E") {
		t.Fatalf("an edit made while following must stay: %s", got)
	}
	if err := w1.save(s1, "ann"); err != nil {
		t.Fatal(err)
	}
	if got := sharedTpls(t, w1); !strings.Contains(got, "edit=E") || !strings.Contains(got, "other=O") {
		t.Fatalf("the next save delivers the edit: %s", got)
	}
}

func TestTemplateShare_RefusedSaveKeepsEveryChangeThatDoesNotCollide(t *testing.T) {
	f := newFakeShared()
	w1, w2 := f.share(), f.share()
	s1, s2 := storeWith(Template{ID: "cams", Kind: "dns", Body: "A"}), &TemplateStore{}
	w1.refresh(s1)
	w2.refresh(s2)
	s1.Upsert("cams", "", "", "dns", "A2")
	if err := w1.save(s1, "ann"); err != nil {
		t.Fatal(err)
	}
	s2.Upsert("cams", "", "", "dns", "B2")
	s2.Upsert("", "mine", "", "dns", "M")
	post := w2.post
	once := true
	w2.post = func(author string, changes []cfgjournal.Entry) error {
		if once {
			once = false
			s2.Upsert("", "late", "", "dns", "L")
		}
		return post(author, changes)
	}
	if err := w2.save(s2, "bob"); !errors.Is(err, errTemplateConflict) {
		t.Fatalf("bob's change of cams must collide: %v", err)
	}
	if got := tplIDs(s2); !strings.Contains(got, "late=L") || !strings.Contains(got, "mine=M") {
		t.Fatalf("an edit made during the refused save must stay: %s", got)
	}
	if err := w2.save(s2, "bob"); !errors.Is(err, errTemplateConflict) {
		t.Fatalf("cams still collides: %v", err)
	}
	if got := tplIDs(s2); !strings.Contains(got, "cams=A2") || !strings.Contains(got, "late=L") || !strings.Contains(got, "mine=M") {
		t.Fatalf("the reload shows the shared cams and keeps the other changes: %s", got)
	}
	if err := w2.save(s2, "bob"); err != nil {
		t.Fatal(err)
	}
	if got := sharedTpls(t, w2); !strings.Contains(got, "late=L") || !strings.Contains(got, "mine=M") || !strings.Contains(got, "cams=A2") {
		t.Fatalf("the changes that did not collide reach the shared document: %s", got)
	}
}
