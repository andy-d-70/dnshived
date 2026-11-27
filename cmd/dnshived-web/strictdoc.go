// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"dnshived/internal/cfgjournal"
	"dnshived/internal/secretindex"
)

// A change of a secret-bearing document (users, probe hosts) is ordered by the cores before it is applied here. It
// is written to a pending file first, with the exact request, so neither a crash nor a lost answer can lose it: the
// next pass applies it once the cores name it, sends the request again while they do not answer, and drops it only
// when they refused it because someone else changed the item first.

type pendingChange struct {
	Part    string                     `json:"part"`
	Keys    []string                   `json:"keys"`
	Items   map[string]json.RawMessage `json:"items"`
	Entries []cfgjournal.Entry         `json:"entries"`
}

var errNotConfirmed = errors.New("not confirmed by the cores yet")

// orderChange orders the change from before to after. applied is true when the cores accepted it now; err is a
// *secretindex.ConflictError when someone else changed an item first, wraps errNotConfirmed when the change is kept
// pending, and is any other error when nothing was sent.
func orderChange(s *usersStrict, pendingPath, part, by string, before, after map[string][]byte) (applied bool, err error) {
	keys := secretindex.Changed(before, after)
	if len(keys) == 0 {
		return true, nil
	}
	tree, err := s.getIndex()
	if err != nil {
		return false, fmt.Errorf("not saved: this change needs a majority of the cores, and their change order cannot be reached (%v)", err)
	}
	es, err := secretindex.Plan(tree, part, before, after, keys, by, s.now(), false)
	if err != nil {
		return false, err
	}
	p := pendingChange{Part: part, Keys: keys, Items: map[string]json.RawMessage{}, Entries: es}
	for _, k := range keys {
		if raw, ok := after[k]; ok {
			p.Items[k] = json.RawMessage(raw)
		}
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return false, err
	}
	if err := writeMarker(pendingPath, raw); err != nil {
		return false, fmt.Errorf("not saved: the change could not be kept on disk before sending it: %w", err)
	}
	perr := s.post(by, es)
	switch {
	case perr == nil:
		_ = os.Remove(pendingPath)
		return true, nil
	case errors.Is(perr, cfgjournal.ErrConflict):
		_ = os.Remove(pendingPath)
		if tree, err := s.getIndex(); err == nil {
			if _, err := secretindex.Plan(tree, part, before, after, keys, by, s.now(), false); err != nil {
				return false, err
			}
		}
		return false, &secretindex.ConflictError{Key: keys[0], Entry: secretindex.Entry{By: "another instance", At: "the same moment"}}
	}
	return false, fmt.Errorf("%w (%v): the change is kept and applied as soon as they confirm it, or dropped if they refuse it", errNotConfirmed, perr)
}

// settleOutcome says what became of a pending change.
type settleOutcome int

const (
	settleNone settleOutcome = iota
	settleKept
	settleApply
	settleDropped
)

// settlePendingChange decides about the pending change at path. With settleApply the caller applies p.Items for
// p.Keys (an absent item is a delete) and then removes the file.
func settlePendingChange(s *usersStrict, path string) (*pendingChange, settleOutcome, error) {
	var p pendingChange
	ok, err := readJSONFile(path, &p)
	if !ok {
		return nil, settleNone, nil
	}
	if err != nil {
		return nil, settleKept, fmt.Errorf("unreadable %s, kept for inspection: %w", path, err)
	}
	tree, err := s.getIndex()
	if err != nil {
		return &p, settleKept, nil
	}
	idx, err := secretindex.Parse(tree, p.Part)
	if err != nil {
		return &p, settleKept, err
	}
	if p.named(idx) {
		return &p, settleApply, nil
	}
	perr := s.post("", p.Entries)
	switch {
	case perr == nil:
		return &p, settleApply, nil
	case errors.Is(perr, cfgjournal.ErrConflict):
		_ = os.Remove(path)
		return &p, settleDropped, nil
	}
	return &p, settleKept, nil
}

func (p *pendingChange) named(idx secretindex.Index) bool {
	for _, k := range p.Keys {
		e := idx[k]
		raw, ok := p.Items[k]
		if !ok {
			if !e.Deleted {
				return false
			}
			continue
		}
		if e.Deleted || e.Hash != secretindex.Hash(raw) {
			return false
		}
	}
	return true
}

// applyItems sets p's items in cur: present ones replaced, absent ones deleted.
func (p *pendingChange) applyItems(cur map[string][]byte) {
	for _, k := range p.Keys {
		if raw, ok := p.Items[k]; ok {
			cur[k] = raw
		} else {
			delete(cur, k)
		}
	}
}
