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

type clusterPlain Cluster

// UnmarshalJSON reads c and keeps the keys it has no field for in Extra.
func (c *Cluster) UnmarshalJSON(data []byte) error {
	p := clusterPlain(*c)
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*c = Cluster(p)
	c.Extra = mergeExtra(c.Extra, unknownKeys(data, reflect.TypeOf(Cluster{})))
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
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*s = ScopeConfig(p)
	s.Extra = mergeExtra(s.Extra, unknownKeys(data, reflect.TypeOf(ScopeConfig{})))
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
