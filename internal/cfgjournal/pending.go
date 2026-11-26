// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package cfgjournal

import (
	"encoding/json"
	"fmt"
	"sort"

	"dnshived/internal/changeset"
)

// PendingDoc is the journal document holding staged changes. It is a plain JSON file {"items": {path: Staged}}.
const PendingDoc = "pending"

// Staged is one staged item: the live value when it was first staged, the staged value, and who staged it last.
// Absent values are left out; JSON null counts as absent.
type Staged struct {
	Base   json.RawMessage `json:"base,omitempty"`
	New    json.RawMessage `json:"new,omitempty"`
	Author string          `json:"author,omitempty"`
	TimeMs int64           `json:"time_ms,omitempty"`
}

// Pending maps a configuration path (as changeset writes it) to its staged item. Staged paths never contain one
// another.
type Pending map[string]Staged

// EmptyPending is the pending document before anything was staged.
func EmptyPending() any { return map[string]any{"items": map[string]any{}} }

// PendingFromTree reads the pending document's tree.
func PendingFromTree(t any) (Pending, error) {
	m, _ := t.(map[string]any)
	raw, err := json.Marshal(m["items"])
	if err != nil {
		return nil, err
	}
	p := Pending{}
	if string(raw) == "null" {
		return p, nil
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("%w: pending document: %w", ErrJournal, err)
	}
	return p, nil
}

func (pd Pending) tree() (any, error) {
	raw, err := json.Marshal(map[string]any{"items": pd})
	if err != nil {
		return nil, err
	}
	return decodeTree(raw)
}

func rawValue(b []byte) (any, error) {
	if isAbsent(b) {
		return nil, nil
	}
	return decodeTree(b)
}

func (pd Pending) apply(live any, pick func(Staged) []byte) (any, error) {
	paths := make([]string, 0, len(pd))
	for p := range pd {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	ups := make([]changeset.Update, 0, len(paths))
	for _, p := range paths {
		v, err := rawValue(pick(pd[p]))
		if err != nil {
			return nil, fmt.Errorf("%w: staged value at %s: %w", ErrJournal, p, err)
		}
		ups = append(ups, changeset.Update{Path: p, Value: v})
	}
	return changeset.SetAll(deepCopy(live), ups)
}

// Materialize is live with every staged value: the configuration a commit of everything would produce.
func (pd Pending) Materialize(live any) (any, error) {
	return pd.apply(live, func(s Staged) []byte { return s.New })
}

// baseView is live with every staged item back at the value it had when it was first staged.
func (pd Pending) baseView(live any) (any, error) {
	return pd.apply(live, func(s Staged) []byte { return s.Base })
}

// Stage applies changes, made by author on a view of the materialised configuration, and returns the pending
// document's entries that record them. A change whose item no longer holds the value it was based on is refused with
// a ConflictError. An item set back to its base leaves Pending.
func (pd Pending) Stage(live any, changes []Entry, author string, now int64) ([]Entry, error) {
	mat, err := pd.Materialize(live)
	if err != nil {
		return nil, err
	}
	recs := make([]Record, len(changes))
	for i := range changes {
		recs[i] = Record{Entry: changes[i]}
	}
	want, err := Apply(mat, recs)
	if err != nil {
		return nil, err
	}
	base, err := pd.baseView(live)
	if err != nil {
		return nil, err
	}
	touched := map[string]bool{}
	for _, c := range changes {
		touched[c.Path] = true
	}
	next := Pending{}
	var bad error
	changeset.Each(base, want, func(p string, b, n any) {
		if bad != nil {
			return
		}
		s := Staged{Author: author, TimeMs: now}
		if old, ok := pd[p]; ok && !touchedWithin(touched, p) {
			s.Author, s.TimeMs = old.Author, old.TimeMs
		}
		if b != nil {
			s.Base, bad = json.Marshal(b)
		}
		if n != nil && bad == nil {
			s.New, bad = json.Marshal(n)
		}
		next[p] = s
	})
	if bad != nil {
		return nil, bad
	}
	return pd.entriesTo(next)
}

func touchedWithin(touched map[string]bool, p string) bool {
	for t := range touched {
		if t == p || len(t) > len(p) && t[:len(p)+1] == p+"/" || len(p) > len(t) && p[:len(t)+1] == t+"/" {
			return true
		}
	}
	return false
}

func (pd Pending) entriesTo(next Pending) ([]Entry, error) {
	from, err := pd.tree()
	if err != nil {
		return nil, err
	}
	to, err := next.tree()
	if err != nil {
		return nil, err
	}
	return FromChange(PendingDoc, from, to, 0)
}

// Discard returns the pending document's entries that drop the chosen staged items.
func (pd Pending) Discard(pick func(path string, s Staged) bool) ([]Entry, error) {
	next := Pending{}
	for p, s := range pd {
		if !pick(p, s) {
			next[p] = s
		}
	}
	return pd.entriesTo(next)
}

// Commit returns the configuration entries for the chosen staged items: each item from its base to its staged
// value, so an item that moved in the live configuration since it was staged is a conflict at the writer and nothing
// else is touched.
func (pd Pending) Commit(doc string, pick func(path string, s Staged) bool) []Entry {
	var out []Entry
	for p, s := range pd {
		if !pick(p, s) {
			continue
		}
		e := Entry{Doc: doc, Path: p}
		if !isAbsent(s.Base) {
			e.Old = s.Base
		}
		if !isAbsent(s.New) {
			e.New = s.New
		}
		if e.Old != nil || e.New != nil {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Committed picks the staged items whose value the live configuration already holds, so they can leave Pending after
// a commit.
func (pd Pending) Committed(live any) func(path string, s Staged) bool {
	return func(p string, s Staged) bool {
		v, ok := changeset.Get(live, p)
		same, err := sameValue(v, ok, s.New)
		return err == nil && same
	}
}
