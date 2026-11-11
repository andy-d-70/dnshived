// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"sync"
)

// removedKeys are keys older versions wrote that are dropped on purpose.
var removedKeys = map[string]bool{"dry_run": true}

var knownKeyCache sync.Map

// knownKeys returns the lower-cased JSON keys of struct type t, the same
// folding encoding/json uses when it matches input keys to fields.
func knownKeys(t reflect.Type) map[string]bool {
	if v, ok := knownKeyCache.Load(t); ok {
		return v.(map[string]bool)
	}
	keys := make(map[string]bool, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := f.Name
		if tag, ok := f.Tag.Lookup("json"); ok {
			n, _, _ := strings.Cut(tag, ",")
			if n == "-" && tag == "-" {
				continue
			}
			if n != "" {
				name = n
			}
		}
		keys[strings.ToLower(name)] = true
	}
	knownKeyCache.Store(t, keys)
	return keys
}

// unknownKeys returns the entries of the JSON object in data whose keys are
// not fields of t.
func unknownKeys(data []byte, t reflect.Type) map[string]json.RawMessage {
	var all map[string]json.RawMessage
	if json.Unmarshal(data, &all) != nil {
		return nil
	}
	known := knownKeys(t)
	var extra map[string]json.RawMessage
	for k, v := range all {
		lk := strings.ToLower(k)
		if known[lk] || removedKeys[lk] {
			continue
		}
		if extra == nil {
			extra = make(map[string]json.RawMessage)
		}
		extra[k] = append(json.RawMessage(nil), v...)
	}
	return extra
}

// mergeExtra returns old with the entries of add put on top, as
// encoding/json merges input into a value that already holds data. The
// result never shares a map with old.
func mergeExtra(old, add map[string]json.RawMessage) map[string]json.RawMessage {
	if len(old) == 0 && len(add) == 0 {
		return nil
	}
	out := make(map[string]json.RawMessage, len(old)+len(add))
	for k, v := range old {
		out[k] = v
	}
	for k, v := range add {
		out[k] = v
	}
	return out
}

// appendExtra adds extra to the JSON object in base. A key the struct
// already wrote wins.
func appendExtra(base []byte, extra map[string]json.RawMessage, t reflect.Type) ([]byte, error) {
	if len(extra) == 0 {
		return base, nil
	}
	known := knownKeys(t)
	names := make([]string, 0, len(extra))
	for k := range extra {
		if !known[strings.ToLower(k)] {
			names = append(names, k)
		}
	}
	if len(names) == 0 {
		return base, nil
	}
	sort.Strings(names)
	base = bytes.TrimRight(base, " \t\r\n")
	if len(base) < 2 || base[len(base)-1] != '}' {
		return base, nil
	}
	var out bytes.Buffer
	out.Write(base[:len(base)-1])
	empty := len(base) == 2
	for _, k := range names {
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		if !empty {
			out.WriteByte(',')
		}
		empty = false
		out.Write(kb)
		out.WriteByte(':')
		out.Write(extra[k])
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

// decodeKeepingExtras decodes data into v, a pointer to the plain twin of
// struct type t, and returns the keys t has no field for. The document is
// decoded once; a light scan of its top-level keys (no value is decoded)
// finds out whether any key is unknown, which is rarely the case, and only
// then are the keys collected with the full decoder.
func decodeKeepingExtras(data []byte, v any, t reflect.Type) (map[string]json.RawMessage, error) {
	if err := json.Unmarshal(data, v); err != nil {
		return nil, err
	}
	if keys, ok := topLevelKeys(data); ok && allKnown(keys, knownKeys(t)) {
		return nil, nil
	}
	return unknownKeys(data, t), nil
}

// allKnown reports whether every key is a field of the type and none is a key
// that is dropped on purpose, folding case as encoding/json does.
func allKnown(keys [][]byte, known map[string]bool) bool {
	for _, k := range keys {
		if known[string(k)] {
			if removedKeys[string(k)] {
				return false
			}
			continue
		}
		lk := strings.ToLower(string(k))
		if !known[lk] || removedKeys[lk] {
			return false
		}
	}
	return true
}

// topLevelKeys returns the keys of the JSON object in data as written, without
// decoding any value. ok is false when data is not an object it can walk or a
// key holds an escape; the caller then uses the full decoder. data must
// already be valid JSON: the scan only finds the keys.
func topLevelKeys(data []byte) (keys [][]byte, ok bool) {
	i := skipSpace(data, 0)
	if i >= len(data) || data[i] != '{' {
		return nil, false
	}
	i = skipSpace(data, i+1)
	if i < len(data) && data[i] == '}' {
		return nil, skipSpace(data, i+1) == len(data)
	}
	for {
		i = skipSpace(data, i)
		if i >= len(data) || data[i] != '"' {
			return nil, false
		}
		j := i + 1
		for j < len(data) && data[j] != '"' {
			if data[j] == '\\' {
				return nil, false
			}
			j++
		}
		if j >= len(data) {
			return nil, false
		}
		keys = append(keys, data[i+1:j])
		i = skipSpace(data, j+1)
		if i >= len(data) || data[i] != ':' {
			return nil, false
		}
		var good bool
		if i, good = skipValue(data, skipSpace(data, i+1)); !good {
			return nil, false
		}
		i = skipSpace(data, i)
		if i >= len(data) {
			return nil, false
		}
		switch data[i] {
		case ',':
			i++
		case '}':
			return keys, skipSpace(data, i+1) == len(data)
		default:
			return nil, false
		}
	}
}

func skipSpace(data []byte, i int) int {
	for i < len(data) && (data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r') {
		i++
	}
	return i
}

// skipValue returns the index just after the JSON value that starts at i.
func skipValue(data []byte, i int) (int, bool) {
	if i >= len(data) {
		return i, false
	}
	switch data[i] {
	case '"':
		return skipString(data, i)
	case '{', '[':
		depth := 0
		for i < len(data) {
			switch data[i] {
			case '"':
				var good bool
				if i, good = skipString(data, i); !good {
					return i, false
				}
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return i + 1, true
				}
			}
			i++
		}
		return i, false
	}
	for i < len(data) {
		switch data[i] {
		case ',', '}', ']', ' ', '\t', '\n', '\r':
			return i, true
		}
		i++
	}
	return i, true
}

// skipString returns the index just after the string that starts at i.
func skipString(data []byte, i int) (int, bool) {
	for i++; i < len(data); i++ {
		switch data[i] {
		case '\\':
			i++
		case '"':
			return i + 1, true
		}
	}
	return i, false
}

type clusterPlain Cluster

// UnmarshalJSON reads c and keeps the keys it has no field for in Extra.
func (c *Cluster) UnmarshalJSON(data []byte) error {
	p := clusterPlain(*c)
	extra, err := decodeKeepingExtras(data, &p, reflect.TypeOf(Cluster{}))
	if err != nil {
		return err
	}
	*c = Cluster(p)
	c.Extra = mergeExtra(c.Extra, extra)
	return nil
}

// MarshalJSON writes c followed by the keys kept in Extra.
func (c Cluster) MarshalJSON() ([]byte, error) {
	base, err := json.Marshal(clusterPlain(c))
	if err != nil {
		return nil, err
	}
	return appendExtra(base, c.Extra, reflect.TypeOf(Cluster{}))
}

type scopePlain ScopeConfig

// UnmarshalJSON reads s and keeps the keys it has no field for in Extra.
func (s *ScopeConfig) UnmarshalJSON(data []byte) error {
	p := scopePlain(*s)
	extra, err := decodeKeepingExtras(data, &p, reflect.TypeOf(ScopeConfig{}))
	if err != nil {
		return err
	}
	*s = ScopeConfig(p)
	s.Extra = mergeExtra(s.Extra, extra)
	return nil
}

// MarshalJSON writes s followed by the keys kept in Extra.
func (s ScopeConfig) MarshalJSON() ([]byte, error) {
	base, err := json.Marshal(scopePlain(s))
	if err != nil {
		return nil, err
	}
	return appendExtra(base, s.Extra, reflect.TypeOf(ScopeConfig{}))
}
