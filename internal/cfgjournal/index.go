// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package cfgjournal

import (
	"sort"
	"strings"
)

// Index holds the journal revision of the last change of every item, so a change can be checked against the version
// it was based on without reading any file. It is not safe for concurrent use.
type Index struct {
	rev    map[string]uint64
	sorted []string
	dirty  bool
}

func NewIndex() *Index { return &Index{rev: map[string]uint64{}} }

func indexKey(doc, path string) string { return doc + "\x00" + path }

// Add records the records' revisions; they must come in journal order.
func (x *Index) Add(recs ...Record) {
	for _, r := range recs {
		k := indexKey(r.Doc, r.Path)
		if _, ok := x.rev[k]; !ok {
			x.dirty = true
		}
		x.rev[k] = max(x.rev[k], r.Rev)
	}
}

// Version is the revision of the last change that touched the item at path: the item itself, a containing item or
// an item inside it. 0 means it never changed in the journal.
func (x *Index) Version(doc, path string) uint64 {
	v := x.rev[indexKey(doc, path)]
	for p := path; ; {
		i := strings.LastIndexByte(p, '/')
		if i < 0 {
			break
		}
		p = p[:i]
		v = max(v, x.rev[indexKey(doc, p)])
	}
	if x.dirty {
		x.sorted = x.sorted[:0]
		for k := range x.rev {
			x.sorted = append(x.sorted, k)
		}
		sort.Strings(x.sorted)
		x.dirty = false
	}
	prefix := indexKey(doc, path) + "/"
	for i := sort.SearchStrings(x.sorted, prefix); i < len(x.sorted) && strings.HasPrefix(x.sorted[i], prefix); i++ {
		v = max(v, x.rev[x.sorted[i]])
	}
	return v
}

// Stale lists, sorted, the paths whose item changed after the revision the caller based its change on.
func (x *Index) Stale(doc string, bases map[string]uint64) []string {
	var out []string
	for p, b := range bases {
		if x.Version(doc, p) > b {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}
