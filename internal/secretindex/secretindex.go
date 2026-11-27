// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package secretindex orders changes of documents that hold secrets (web users, probe hosts, nodes) through the
// configuration journal without putting the secrets there: the journal holds, per item, only a sha256 of its
// content and who changed it when. A change names the version it was based on; the first one wins, a later one
// based on the same version is refused. A web instance accepts an item's content only when it matches the index.
package secretindex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"dnshived/internal/cfgjournal"
	"dnshived/internal/changeset"
)

// Doc is the journal document that holds the index.
const Doc = "secret-index"

// Entry is the index record of one item.
type Entry struct {
	Hash    string `json:"hash,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
	By      string `json:"by,omitempty"`
	At      string `json:"at,omitempty"`
}

// Index is one document's part of the index: item key -> entry.
type Index map[string]Entry

// Hash is the index hash of an item's content; "" for an absent item.
func Hash(raw []byte) string {
	if raw == nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ErrConflict is returned when the index names another version of an item than the change was based on.
var ErrConflict = errors.New("changed meanwhile")

// ConflictError names the item and who changed it last.
type ConflictError struct {
	Key   string
	Entry Entry
}

func (e *ConflictError) Error() string {
	what := "changed"
	if e.Entry.Deleted {
		what = "deleted"
	}
	return fmt.Sprintf("%s was %s meanwhile by %s at %s", e.Key, what, e.Entry.By, e.Entry.At)
}

func (e *ConflictError) Unwrap() error { return ErrConflict }

func path(part, key string) string { return changeset.Join(changeset.Join("", part), key) }

// Parse reads part ("users", "probe_hosts", "nodes") of the index tree.
func Parse(tree any, part string) (Index, error) {
	out := Index{}
	v, ok := changeset.Get(tree, changeset.Join("", part))
	if !ok || v == nil {
		return out, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("secret index %s: %w", part, err)
	}
	return out, nil
}

// Plan returns the journal entries that move part of the index from the items in before to those in after. It
// refuses with a ConflictError when the index names another version of a changed item than before holds. With
// force, the current index value is taken as the base whatever it is (an administrator's console reset).
func Plan(tree any, part string, before, after map[string][]byte, keys []string, by string, at time.Time, force bool) ([]cfgjournal.Entry, error) {
	if keys == nil {
		keys = Changed(before, after)
	}
	stamp := at.UTC().Format(time.RFC3339)
	var out []cfgjournal.Entry
	for _, key := range keys {
		p := path(part, key)
		cur, indexed := changeset.Get(tree, p)
		var old []byte
		if indexed && cur != nil {
			raw, err := json.Marshal(cur)
			if err != nil {
				return nil, err
			}
			old = raw
			if !force {
				var e Entry
				if err := json.Unmarshal(raw, &e); err != nil {
					return nil, fmt.Errorf("secret index %s: %w", p, err)
				}
				_, had := before[key]
				if e.Deleted && had || !e.Deleted && e.Hash != Hash(before[key]) {
					return nil, &ConflictError{Key: key, Entry: e}
				}
			}
		}
		next := Entry{By: by, At: stamp}
		if raw, ok := after[key]; ok {
			next.Hash = Hash(raw)
		} else {
			next.Deleted = true
		}
		nraw, err := json.Marshal(next)
		if err != nil {
			return nil, err
		}
		out = append(out, cfgjournal.Entry{Doc: Doc, Path: p, Old: old, New: nraw})
	}
	return out, nil
}

// Changed lists the keys whose content differs between a and b, sorted.
func Changed(a, b map[string][]byte) []string {
	var out []string
	for k, v := range a {
		if w, ok := b[k]; !ok || string(w) != string(v) {
			out = append(out, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Reconcile decides per item what a document holds when a newer copy arrives: the content the index names. An
// item the index does not know follows the incoming copy, as before the index existed. When neither copy holds the
// indexed content, the incoming copy is followed so instances converge, and the item is listed in missing. keep
// lists items that stay local whatever the index says (a forced change not yet ordered). refused lists the
// incoming items that were not taken.
func Reconcile(idx Index, local, incoming map[string][]byte, keep map[string]bool) (out map[string][]byte, refused, missing []string) {
	out = map[string][]byte{}
	keys := map[string]bool{}
	for k := range local {
		keys[k] = true
	}
	for k := range incoming {
		keys[k] = true
	}
	for k := range keys {
		lv, lok := local[k]
		iv, iok := incoming[k]
		e, indexed := idx[k]
		take := func(v []byte, ok bool) {
			if ok {
				out[k] = v
			}
		}
		switch {
		case keep[k]:
			take(lv, lok)
		case !indexed:
			take(iv, iok)
		case e.Deleted:
		case iok && Hash(iv) == e.Hash:
			take(iv, iok)
		case lok && Hash(lv) == e.Hash:
			take(lv, lok)
		default:
			take(iv, iok)
			if lok || iok {
				missing = append(missing, k)
			}
		}
		if got, ok := out[k]; ok != iok || ok && string(got) != string(iv) {
			refused = append(refused, k)
		}
	}
	sort.Strings(refused)
	sort.Strings(missing)
	return out, refused, missing
}
