// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package changeset

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrPath is returned for a path that does not fit the document.
var ErrPath = errors.New("changeset: path does not fit the document")

var unescaper = strings.NewReplacer("~1", "/", "~2", "[", "~3", "]", "~0", "~")

type segment struct {
	name  string
	keyed bool
}

func splitPath(path string) ([]segment, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty path", ErrPath)
	}
	parts := strings.Split(path, "/")
	segs := make([]segment, len(parts))
	for i, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("%w: empty segment in %q", ErrPath, path)
		}
		if strings.HasPrefix(p, "[") && strings.HasSuffix(p, "]") && len(p) >= 2 {
			segs[i] = segment{name: unescaper.Replace(p[1 : len(p)-1]), keyed: true}
			continue
		}
		segs[i] = segment{name: unescaper.Replace(p)}
	}
	return segs, nil
}

// Get returns the value at a path produced by Changes: a field, one element of a keyed list, or the group of elements
// that share a key in an atomic list. ok is false when nothing is there.
func Get(tree any, path string) (v any, ok bool) {
	segs, err := splitPath(path)
	if err != nil {
		return nil, false
	}
	cur, spath := tree, ""
	for i, s := range segs {
		if s.keyed {
			r, found := rules[spath]
			list, isList := cur.([]any)
			if !found || (cur != nil && !isList) {
				return nil, false
			}
			idx := keyIndexes(list, r.key, s.name)
			if len(idx) == 0 {
				return nil, false
			}
			if r.atomic {
				if i != len(segs)-1 {
					return nil, false
				}
				out := make([]any, len(idx))
				for j, k := range idx {
					out[j] = list[k]
				}
				return out, true
			}
			cur, spath = list[idx[0]], spath+"[]"
			continue
		}
		m, isMap := asMap(cur, spath)
		if !isMap {
			return nil, false
		}
		next, found := m[s.name]
		if !found {
			return nil, false
		}
		cur, spath = next, schemaChild(spath, s.name)
	}
	return cur, true
}

// Set returns tree with the value at path replaced by value; a nil value removes it. It is the single-path form of
// Merge: a new element of a keyed list is appended, an emptied list or a removed field disappears from its parent.
// Maps and lists inside tree are changed in place.
func Set(tree any, path string, value any) (any, error) {
	segs, err := splitPath(path)
	if err != nil {
		return nil, err
	}
	return set(tree, segs, "", value, path)
}

func keyIndexes(list []any, key func(map[string]any) string, want string) []int {
	var idx []int
	for i, e := range list {
		if m, ok := e.(map[string]any); ok && key(m) == want {
			idx = append(idx, i)
		}
	}
	return idx
}

func set(cur any, segs []segment, spath string, value any, full string) (any, error) {
	s := segs[0]
	last := len(segs) == 1
	if s.keyed {
		r, found := rules[spath]
		list, isList := cur.([]any)
		if !found || (cur != nil && !isList) {
			return nil, fmt.Errorf("%w: %q is not a keyed list at %q", ErrPath, spath, full)
		}
		for _, e := range list {
			if _, ok := e.(map[string]any); !ok {
				return nil, fmt.Errorf("%w: list at %q holds a non-object", ErrPath, full)
			}
		}
		idx := keyIndexes(list, r.key, s.name)
		if r.atomic {
			if !last {
				return nil, fmt.Errorf("%w: %q goes below an atomic group", ErrPath, full)
			}
			var repl []any
			if value != nil {
				vs, ok := value.([]any)
				if !ok {
					return nil, fmt.Errorf("%w: the group at %q must be a list", ErrPath, full)
				}
				for _, e := range vs {
					m, ok := e.(map[string]any)
					if !ok || r.key(m) != s.name {
						return nil, fmt.Errorf("%w: an element of the group at %q has another key", ErrPath, full)
					}
				}
				repl = vs
			}
			return emptyAsNil(replaceGroup(list, idx, repl)), nil
		}
		if len(idx) > 1 {
			return nil, fmt.Errorf("%w: key %q is not unique at %q", ErrPath, s.name, full)
		}
		if len(idx) == 0 {
			if !last {
				return nil, fmt.Errorf("%w: no element %q at %q", ErrPath, s.name, full)
			}
			if value == nil {
				return emptyAsNil(list), nil
			}
			m, ok := value.(map[string]any)
			if !ok || r.key(m) != s.name {
				return nil, fmt.Errorf("%w: the new element at %q has another key", ErrPath, full)
			}
			return append(list, value), nil
		}
		i := idx[0]
		nv := value
		if !last {
			nv, err := set(list[i], segs[1:], spath+"[]", value, full)
			if err != nil {
				return nil, err
			}
			return emptyAsNil(replaceAt(list, i, nv)), nil
		}
		if nv != nil {
			m, ok := nv.(map[string]any)
			if !ok || r.key(m) != s.name {
				return nil, fmt.Errorf("%w: the element at %q has another key", ErrPath, full)
			}
		}
		return emptyAsNil(replaceAt(list, i, nv)), nil
	}
	m, isMap := asMap(cur, spath)
	if !isMap {
		if cur != nil {
			return nil, fmt.Errorf("%w: %q is not an object", ErrPath, full)
		}
		m = map[string]any{}
	}
	if last {
		if value == nil {
			delete(m, s.name)
		} else {
			m[s.name] = value
		}
		return m, nil
	}
	child, found := m[s.name]
	if !found {
		cs := schemaChild(spath, s.name)
		_, nextMap := asMap(nil, cs)
		_, keyedList := rules[cs]
		if !nextMap && !(keyedList && segs[1].keyed) {
			return nil, fmt.Errorf("%w: no field %q at %q", ErrPath, s.name, full)
		}
	}
	nv, err := set(child, segs[1:], schemaChild(spath, s.name), value, full)
	if err != nil {
		return nil, err
	}
	if nv == nil {
		delete(m, s.name)
	} else {
		m[s.name] = nv
	}
	return m, nil
}

func replaceGroup(list []any, idx []int, repl []any) []any {
	out := make([]any, 0, len(list)-len(idx)+len(repl))
	placed := false
	drop := make(map[int]bool, len(idx))
	for _, i := range idx {
		drop[i] = true
	}
	for i, e := range list {
		if drop[i] {
			if !placed {
				out = append(out, repl...)
				placed = true
			}
			continue
		}
		out = append(out, e)
	}
	if !placed {
		out = append(out, repl...)
	}
	return out
}

func replaceAt(list []any, i int, v any) []any {
	if v != nil {
		list[i] = v
		return list
	}
	return append(list[:i:i], list[i+1:]...)
}

func emptyAsNil(list []any) any {
	if len(list) == 0 {
		return nil
	}
	return list
}

// Each calls fn for every path at which cand differs from live, with the value on each side (nil when absent), in
// one walk over both documents and in sorted path order, so every caller sees the same sequence.
func Each(live, cand any, fn func(path string, live, cand any)) {
	type diff struct {
		path       string
		live, cand any
	}
	var ds []diff
	walk(live, cand, "", "", func(p string, l, c any, _ bool) { ds = append(ds, diff{p, l, c}) })
	sort.Slice(ds, func(i, j int) bool { return ds[i].path < ds[j].path })
	for _, d := range ds {
		fn(d.path, d.live, d.cand)
	}
}

// Update is one change for SetAll. Check, when set, sees the current value first and can refuse the change.
type Update struct {
	Path  string
	Value any
	Check func(have any, present bool) error
}

type pending struct {
	segs []segment
	up   *Update
}

// SetAll applies several updates in one pass: every keyed list is indexed once, so the cost follows the size of the
// document plus the number of updates, not their product. The paths must be distinct and none may lie inside another.
// Maps and lists inside tree are changed in place; on an error tree must be discarded.
func SetAll(tree any, ups []Update) (any, error) {
	ps := make([]pending, len(ups))
	for i := range ups {
		segs, err := splitPath(ups[i].Path)
		if err != nil {
			return nil, err
		}
		ps[i] = pending{segs: segs, up: &ups[i]}
	}
	if len(ps) == 0 {
		return tree, nil
	}
	return setAll(tree, ps, 0, "")
}

func check(p pending, have any, present bool) error {
	if p.up.Check == nil {
		return nil
	}
	return p.up.Check(have, present)
}

type bucket struct {
	seg   segment
	last  *pending
	under []pending
}

func groupPending(ps []pending, depth int) ([]*bucket, error) {
	var order []*bucket
	byKey := map[segment]*bucket{}
	for _, p := range ps {
		s := p.segs[depth]
		b := byKey[s]
		if b == nil {
			b = &bucket{seg: s}
			byKey[s] = b
			order = append(order, b)
		}
		if depth == len(p.segs)-1 {
			if b.last != nil {
				return nil, fmt.Errorf("%w: %q appears twice", ErrPath, p.up.Path)
			}
			p := p
			b.last = &p
		} else {
			b.under = append(b.under, p)
		}
		if b.last != nil && len(b.under) > 0 {
			return nil, fmt.Errorf("%w: %q lies inside another update", ErrPath, p.up.Path)
		}
	}
	return order, nil
}

func setAll(cur any, ps []pending, depth int, spath string) (any, error) {
	buckets, err := groupPending(ps, depth)
	if err != nil {
		return nil, err
	}
	keyed := buckets[0].seg.keyed
	for _, b := range buckets {
		if b.seg.keyed != keyed {
			return nil, fmt.Errorf("%w: fields and keys mixed at %q", ErrPath, spath)
		}
	}
	if keyed {
		return setKeyed(cur, buckets, depth, spath)
	}
	m, isMap := asMap(cur, spath)
	if !isMap {
		if cur != nil {
			return nil, fmt.Errorf("%w: %q is not an object", ErrPath, spath)
		}
		m = map[string]any{}
	}
	for _, b := range buckets {
		name := b.seg.name
		have, present := m[name]
		if b.last != nil {
			if err := check(*b.last, have, present); err != nil {
				return nil, err
			}
			if b.last.up.Value == nil {
				delete(m, name)
			} else {
				m[name] = b.last.up.Value
			}
			continue
		}
		cs := schemaChild(spath, name)
		if !present {
			_, nextMap := asMap(nil, cs)
			_, keyedList := rules[cs]
			if !nextMap && !(keyedList && b.under[0].segs[depth+1].keyed) {
				return nil, fmt.Errorf("%w: no field %q at %q", ErrPath, name, b.under[0].up.Path)
			}
		}
		nv, err := setAll(have, b.under, depth+1, cs)
		if err != nil {
			return nil, err
		}
		if nv == nil {
			delete(m, name)
		} else {
			m[name] = nv
		}
	}
	return m, nil
}

func setKeyed(cur any, buckets []*bucket, depth int, spath string) (any, error) {
	r, found := rules[spath]
	list, isList := cur.([]any)
	if !found || (cur != nil && !isList) {
		return nil, fmt.Errorf("%w: %q is not a keyed list", ErrPath, spath)
	}
	keys := make([]string, len(list))
	idx := map[string][]int{}
	for i, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: list at %q holds a non-object", ErrPath, spath)
		}
		keys[i] = r.key(m)
		idx[keys[i]] = append(idx[keys[i]], i)
	}
	repl := map[string][]any{}
	var added []string
	for _, b := range buckets {
		k := b.seg.name
		at := idx[k]
		if r.atomic {
			if b.last == nil {
				return nil, fmt.Errorf("%w: %q goes below an atomic group", ErrPath, b.under[0].up.Path)
			}
			var have any
			if len(at) > 0 {
				g := make([]any, len(at))
				for j, i := range at {
					g[j] = list[i]
				}
				have = g
			}
			if err := check(*b.last, have, len(at) > 0); err != nil {
				return nil, err
			}
			var vs []any
			if v := b.last.up.Value; v != nil {
				var ok bool
				if vs, ok = v.([]any); !ok {
					return nil, fmt.Errorf("%w: the group at %q must be a list", ErrPath, b.last.up.Path)
				}
				for _, e := range vs {
					m, ok := e.(map[string]any)
					if !ok || r.key(m) != k {
						return nil, fmt.Errorf("%w: an element of the group at %q has another key", ErrPath, b.last.up.Path)
					}
				}
			}
			repl[k] = vs
			if len(at) == 0 {
				added = append(added, k)
			}
			continue
		}
		if len(at) > 1 {
			return nil, fmt.Errorf("%w: key %q is not unique at %q", ErrPath, k, spath)
		}
		if b.last != nil {
			var have any
			if len(at) == 1 {
				have = list[at[0]]
			}
			if err := check(*b.last, have, len(at) == 1); err != nil {
				return nil, err
			}
			v := b.last.up.Value
			if v != nil {
				if m, ok := v.(map[string]any); !ok || r.key(m) != k {
					return nil, fmt.Errorf("%w: the element at %q has another key", ErrPath, b.last.up.Path)
				}
				repl[k] = []any{v}
			} else {
				repl[k] = nil
			}
			if len(at) == 0 {
				added = append(added, k)
			}
			continue
		}
		if len(at) == 0 {
			return nil, fmt.Errorf("%w: no element %q at %q", ErrPath, k, b.under[0].up.Path)
		}
		nv, err := setAll(list[at[0]], b.under, depth+1, spath+"[]")
		if err != nil {
			return nil, err
		}
		if nv == nil {
			repl[k] = nil
		} else {
			repl[k] = []any{nv}
		}
	}
	out := make([]any, 0, len(list))
	placed := map[string]bool{}
	for i, e := range list {
		vs, changed := repl[keys[i]]
		if !changed {
			out = append(out, e)
			continue
		}
		if !placed[keys[i]] {
			out = append(out, vs...)
			placed[keys[i]] = true
		}
	}
	for _, k := range added {
		if !placed[k] {
			out = append(out, repl[k]...)
			placed[k] = true
		}
	}
	return emptyAsNil(out), nil
}

// Strip removes, in place, the fields that Changes ignores (identity, revision and per-node fields, a scope's node
// address), leaving the part of the document that is the same on every node.
func Strip(tree any) {
	strip(tree, "")
}

func strip(v any, spath string) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	for k, child := range m {
		if ignored(spath, k) {
			delete(m, k)
			continue
		}
		cs := schemaChild(spath, k)
		if cs == "scopes.{}" || cs == "parked_scopes.{}" {
			strip(child, cs)
			continue
		}
		if spath == "scopes" || spath == "parked_scopes" || spath == "" {
			strip(child, cs)
		}
	}
}

// IgnoredField reports whether Changes ignores field key at the top level (spath "") or inside a scope
// (spath "scopes.{}" or "parked_scopes.{}").
func IgnoredField(spath, key string) bool { return ignored(spath, key) }
