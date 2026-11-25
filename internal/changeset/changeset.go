// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package changeset finds the field-level differences between two
// configuration documents and applies a chosen subset of them.
package changeset

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
)

type rule struct {
	key    func(map[string]any) string
	atomic bool
}

var rules = map[string]rule{
	"local_domains":                 {key: field("name")},
	"local_domains[].records":       {key: field("host", "type"), atomic: true},
	"global_dns_records":            {key: field("name", "type"), atomic: true},
	"scopes.{}.dns_records":         {key: field("name", "type"), atomic: true},
	"scopes.{}.reservations":        {key: reservationKey, atomic: true},
	"parked_scopes.{}.dns_records":  {key: field("name", "type"), atomic: true},
	"parked_scopes.{}.reservations": {key: reservationKey, atomic: true},
	"api_tokens":                    {key: field("name"), atomic: true},
	"default_dns_checks":            {key: field("name", "type"), atomic: true},
	// The web's templates document (configuration journal): each entry is its own item.
	"templates":    {key: field("id")},
	"option_sets":  {key: field("id")},
	"scope_groups": {key: field("id")},
}

var ignoredTop = map[string]bool{
	"schema_version": true, "config_revision": true, "config_revision_at": true,
	"config_revision_origin": true, "membership_epoch": true, "outage_rules_active": true,
	"access_list_active": true, "cluster_id": true, "node_id": true, "role": true,
	"control_addr": true, "bind_addr": true, "data_dir": true, "peers": true,
}

// reservationKey identifies a reservation by its id when it has one, otherwise by its MAC address.
func reservationKey(m map[string]any) string {
	if id, _ := m["id"].(string); id != "" {
		return "id:" + id
	}
	mac, _ := m["mac"].(string)
	return mac
}

func field(names ...string) func(map[string]any) string {
	return func(m map[string]any) string {
		parts := make([]string, len(names))
		for i, n := range names {
			s, _ := m[n].(string)
			parts[i] = s
		}
		return strings.Join(parts, "|")
	}
}

var escaper = strings.NewReplacer("~", "~0", "/", "~1", "[", "~2", "]", "~3")

// MaxDocBytes bounds the documents that are compared field by field; a larger
// one is left to whole-document handling.
const MaxDocBytes = 8 << 20

// ErrTooLarge is returned for a document above MaxDocBytes.
var ErrTooLarge = errors.New("document too large for a field-level comparison")

// Tree converts a value into the generic form the other functions work on.
func Tree(v any) (any, error) {
	return TreeMax(v, 0)
}

// TreeMax is Tree with a size limit in bytes of the JSON form; 0 means none.
func TreeMax(v any, max int) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if max > 0 && len(raw) > max {
		return nil, ErrTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// Changes lists the paths at which cand differs from live, sorted.
func Changes(live, cand any) []string {
	var out []string
	walk(live, cand, "", "", func(path string, _, _ any, _ bool) { out = append(out, path) })
	sort.Strings(out)
	return out
}

// Merge returns live with the changes at the picked paths taken from cand.
func Merge(live, cand any, pick func(path string) bool) any {
	return merge(live, cand, "", "", pick)
}

func schemaChild(spath, key string) string {
	if spath == "scopes" || spath == "parked_scopes" {
		key = "{}"
	}
	if spath == "" {
		return key
	}
	return spath + "." + key
}

func joinKey(path, key string) string {
	seg := "[" + escaper.Replace(key) + "]"
	if path == "" {
		return seg
	}
	return path + "/" + seg
}

func join(path, seg string) string {
	if path == "" {
		return escaper.Replace(seg)
	}
	return path + "/" + escaper.Replace(seg)
}

type group struct {
	key   string
	elems []any
}

func groupBy(list []any, key func(map[string]any) string) ([]group, bool) {
	idx := map[string]int{}
	var out []group
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, false
		}
		k := key(m)
		i, seen := idx[k]
		if !seen {
			i = len(out)
			idx[k] = i
			out = append(out, group{key: k})
		}
		out[i].elems = append(out[i].elems, e)
	}
	return out, true
}

func keyedLists(live, cand any, spath string) (rule, []group, []group, bool) {
	r, ok := rules[spath]
	if !ok {
		return rule{}, nil, nil, false
	}
	l, lok := live.([]any)
	c, cok := cand.([]any)
	if (live != nil && !lok) || (cand != nil && !cok) {
		return rule{}, nil, nil, false
	}
	lg, ok1 := groupBy(l, r.key)
	cg, ok2 := groupBy(c, r.key)
	if !ok1 || !ok2 {
		return rule{}, nil, nil, false
	}
	if !r.atomic {
		for _, g := range append(append([]group{}, lg...), cg...) {
			if len(g.elems) != 1 {
				return rule{}, nil, nil, false
			}
		}
	}
	return r, lg, cg, true
}

func asAny(g *group) any {
	if g == nil {
		return nil
	}
	return g.elems
}

func byKey(gs []group) map[string]*group {
	m := make(map[string]*group, len(gs))
	for i := range gs {
		m[gs[i].key] = &gs[i]
	}
	return m
}

func ignored(spath, key string) bool {
	if spath == "" {
		return ignoredTop[key]
	}
	return key == "node_ip" && (spath == "scopes.{}" || spath == "parked_scopes.{}")
}

func asMap(v any, spath string) (map[string]any, bool) {
	if m, ok := v.(map[string]any); ok {
		return m, true
	}
	if v == nil && (spath == "scopes" || spath == "parked_scopes") {
		return map[string]any{}, true
	}
	return nil, false
}

func walk(live, cand any, path, spath string, emit func(path string, live, cand any, atomic bool)) {
	lm, lok := asMap(live, spath)
	cm, cok := asMap(cand, spath)
	if lok && cok {
		seen := map[string]bool{}
		for k, lv := range lm {
			seen[k] = true
			if ignored(spath, k) {
				continue
			}
			walk(lv, cm[k], join(path, k), schemaChild(spath, k), emit)
		}
		for k, cv := range cm {
			if seen[k] || ignored(spath, k) {
				continue
			}
			walk(nil, cv, join(path, k), schemaChild(spath, k), emit)
		}
		return
	}
	if r, lg, cg, ok := keyedLists(live, cand, spath); ok {
		li, ci := byKey(lg), byKey(cg)
		keys := make(map[string]bool, len(lg)+len(cg))
		for _, g := range lg {
			keys[g.key] = true
		}
		for _, g := range cg {
			keys[g.key] = true
		}
		for k := range keys {
			l, c := li[k], ci[k]
			p := joinKey(path, k)
			if r.atomic {
				if !reflect.DeepEqual(asAny(l), asAny(c)) {
					emit(p, asAny(l), asAny(c), true)
				}
				continue
			}
			var lv, cv any
			if l != nil {
				lv = l.elems[0]
			}
			if c != nil {
				cv = c.elems[0]
			}
			walk(lv, cv, p, spath+"[]", emit)
		}
		return
	}
	if !reflect.DeepEqual(live, cand) {
		emit(path, live, cand, false)
	}
}

func merge(live, cand any, path, spath string, pick func(string) bool) any {
	lm, lok := asMap(live, spath)
	cm, cok := asMap(cand, spath)
	if lok && cok {
		out := make(map[string]any, len(lm))
		for k, lv := range lm {
			out[k] = lv
		}
		for k := range union(lm, cm) {
			if ignored(spath, k) {
				continue
			}
			v := merge(lm[k], cm[k], join(path, k), schemaChild(spath, k), pick)
			if v == nil {
				delete(out, k)
			} else {
				out[k] = v
			}
		}
		return out
	}
	if r, lg, cg, ok := keyedLists(live, cand, spath); ok {
		return mergeKeyed(r, lg, cg, path, spath, pick)
	}
	if reflect.DeepEqual(live, cand) || !pick(path) {
		return live
	}
	return cand
}

func union(a, b map[string]any) map[string]bool {
	out := make(map[string]bool, len(a)+len(b))
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func mergeKeyed(r rule, lg, cg []group, path, spath string, pick func(string) bool) any {
	var out []any
	emit := func(k string, l, c *group) {
		p := joinKey(path, k)
		if r.atomic {
			chosen := asAny(l)
			if !reflect.DeepEqual(asAny(l), asAny(c)) && pick(p) {
				chosen = asAny(c)
			}
			if es, ok := chosen.([]any); ok {
				out = append(out, es...)
			}
			return
		}
		var lv, cv any
		if l != nil {
			lv = l.elems[0]
		}
		if c != nil {
			cv = c.elems[0]
		}
		if v := merge(lv, cv, p, spath+"[]", pick); v != nil {
			out = append(out, v)
		}
	}
	ci := byKey(cg)
	done := make(map[string]bool, len(lg))
	for i := range lg {
		done[lg[i].key] = true
		emit(lg[i].key, &lg[i], ci[lg[i].key])
	}
	for i := range cg {
		if !done[cg[i].key] {
			emit(cg[i].key, nil, &cg[i])
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
