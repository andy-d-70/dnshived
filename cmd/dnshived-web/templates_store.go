// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// TemplateKind distinguishes the two bodies of text this store holds.
type TemplateKind string

const (
	TemplateKindDHCP      TemplateKind = "dhcp"
	TemplateKindDNS       TemplateKind = "dns"
	TemplateKindClientDNS TemplateKind = "client-dns"
)

// Template is one named, colored, reusable text body.
type Template struct {
	ID    string       `json:"id"`
	Name  string       `json:"name"`
	Color string       `json:"color"`
	Kind  TemplateKind `json:"kind"`
	Body  string       `json:"body"`
}

// OptionSet is a named, colored bundle of Template REFERENCES.
type OptionSet struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
	// TemplateRefs maps a TemplateKind to the ID of the Template this set
	// references for that kind.
	TemplateRefs map[TemplateKind]string `json:"template_refs,omitempty"`
}

// TemplateStore is the on-disk shape (default /etc/dnshived/
// web-templates.json).
type TemplateStore struct {
	Templates   []Template   `json:"templates"`
	OptionSets  []OptionSet  `json:"option_sets,omitempty"`
	ScopeGroups []ScopeGroup `json:"scope_groups,omitempty"`

	// mu guards Templates/OptionSets/ScopeGroups against concurrent mutation
	// from this package's own HTTP handlers.
	mu sync.RWMutex
}

// ScopeGroup is a named, colored, many-to-many group of scopes with its
// own OptionSet/Template assignment.
type ScopeGroup struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Color          string   `json:"color"`
	Members        []string `json:"members,omitempty"`
	AssignedSource string   `json:"assigned_source,omitempty"`
}

// templateIDPattern bounds a generated ID to characters safe as both an
// HTML id/form-field-name fragment and a URL path segment ({id} route
// wildcard).
var templateIDPattern = regexp.MustCompile(`[^a-z0-9-]+`)

// slugify turns an operator-chosen Name into a stable ID, lowercased/
// dashed, collision-suffixed against already-taken IDs.
func slugify(name string, taken map[string]bool) string {
	base := templateIDPattern.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	base = strings.Trim(base, "-")
	if base == "" {
		base = "template"
	}
	id := base
	for n := 2; taken[id]; n++ {
		id = fmt.Sprintf("%s-%d", base, n)
	}
	return id
}

// seedTemplates returns the starting library a brand-new install gets.
func seedTemplates() []Template {
	return []Template{
		{ID: "ddm", Name: "ddm", Color: scopeColorPalette[0], Kind: TemplateKindDNS, Body: dnsTemplateDDM},
		{ID: "nmos", Name: "nmos", Color: scopeColorPalette[2], Kind: TemplateKindDNS, Body: dnsTemplateNMOS},
		{ID: "ndi", Name: "ndi", Color: scopeColorPalette[4], Kind: TemplateKindDNS, Body: dnsTemplateNDI},
	}
}

// LoadTemplates reads the persisted store.
func LoadTemplates(path string) (*TemplateStore, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &TemplateStore{Templates: seedTemplates()}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read templates file %s: %w", path, err)
	}
	var s TemplateStore
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse templates file: %w", err)
	}
	return &s, nil
}

func (s *TemplateStore) Save(path string) error {
	s.mu.RLock()
	data, err := json.MarshalIndent(s, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("marshal templates: %w", err)
	}
	if err := templatesAtomicWriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write templates file %s: %w", path, err)
	}
	return nil
}

func templatesAtomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// ByKind returns every template of the given kind, sorted by Name — the
// wizard's step 2/3 checkbox lists and the editor's grouped list both read
// this directly.
func (s *TemplateStore) ByKind(kind TemplateKind) []Template {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Template
	for _, t := range s.Templates {
		if t.Kind == kind {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns one template by ID.
func (s *TemplateStore) Get(id string) (Template, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.Templates {
		if t.ID == id {
			return t, true
		}
	}
	return Template{}, false
}

// Upsert adds a new template (empty id) or overwrites an existing one by
// ID.
func (s *TemplateStore) Upsert(id, name, color string, kind TemplateKind, body string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	taken := make(map[string]bool, len(s.Templates))
	idx := -1
	for i, t := range s.Templates {
		if t.ID == id && id != "" {
			idx = i
			continue // don't count this row's own current ID against itself
		}
		taken[t.ID] = true
	}
	if id == "" || idx == -1 {
		id = slugify(name, taken)
	}
	nt := Template{ID: id, Name: strings.TrimSpace(name), Color: color, Kind: kind, Body: body}
	if idx >= 0 {
		s.Templates[idx] = nt
	} else {
		s.Templates = append(s.Templates, nt)
	}
	return id
}

// Delete removes a template by ID.
func (s *TemplateStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, t := range s.Templates {
		if t.ID == id {
			s.Templates = append(s.Templates[:i], s.Templates[i+1:]...)
			return
		}
	}
}

// OptionSets mirrors ByKind's own role for Templates — every option set,
// sorted by Name for stable display.
func (s *TemplateStore) SortedOptionSets() []OptionSet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]OptionSet(nil), s.OptionSets...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// OptionSetByID mirrors Get's own role for Templates.
func (s *TemplateStore) OptionSetByID(id string) (OptionSet, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, o := range s.OptionSets {
		if o.ID == id {
			return o, true
		}
	}
	return OptionSet{}, false
}

// UpsertOptionSet mirrors Upsert's own role for Templates — adds a new
// option set (empty id) or overwrites an existing one by ID.
func (s *TemplateStore) UpsertOptionSet(id, name, color string, refs map[TemplateKind]string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	taken := make(map[string]bool, len(s.OptionSets))
	idx := -1
	for i, o := range s.OptionSets {
		if o.ID == id && id != "" {
			idx = i
			continue
		}
		taken[o.ID] = true
	}
	if id == "" || idx == -1 {
		id = slugify(name, taken)
	}
	no := OptionSet{ID: id, Name: strings.TrimSpace(name), Color: color, TemplateRefs: refs}
	if idx >= 0 {
		s.OptionSets[idx] = no
	} else {
		s.OptionSets = append(s.OptionSets, no)
	}
	return id
}

// DeleteOptionSet mirrors Delete's own role for Templates.
func (s *TemplateStore) DeleteOptionSet(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, o := range s.OptionSets {
		if o.ID == id {
			s.OptionSets = append(s.OptionSets[:i], s.OptionSets[i+1:]...)
			return
		}
	}
}

// SortedScopeGroups mirrors SortedOptionSets' own role.
func (s *TemplateStore) SortedScopeGroups() []ScopeGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]ScopeGroup(nil), s.ScopeGroups...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ScopeGroupByID mirrors OptionSetByID's own role.
func (s *TemplateStore) ScopeGroupByID(id string) (ScopeGroup, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, g := range s.ScopeGroups {
		if g.ID == id {
			return g, true
		}
	}
	return ScopeGroup{}, false
}

// UpsertScopeGroup mirrors UpsertOptionSet's own role — adds a new group
// (empty id) or overwrites an existing one by ID.
func (s *TemplateStore) UpsertScopeGroup(id, name, color string, members []string, assignedSource string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	taken := make(map[string]bool, len(s.ScopeGroups))
	idx := -1
	for i, g := range s.ScopeGroups {
		if g.ID == id && id != "" {
			idx = i
			continue
		}
		taken[g.ID] = true
	}
	if id == "" || idx == -1 {
		id = slugify(name, taken)
	}
	ng := ScopeGroup{ID: id, Name: strings.TrimSpace(name), Color: color, Members: append([]string(nil), members...), AssignedSource: assignedSource}
	if idx >= 0 {
		s.ScopeGroups[idx] = ng
	} else {
		s.ScopeGroups = append(s.ScopeGroups, ng)
	}
	return id
}

// DeleteScopeGroup mirrors DeleteOptionSet's own role.
func (s *TemplateStore) DeleteScopeGroup(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, g := range s.ScopeGroups {
		if g.ID == id {
			s.ScopeGroups = append(s.ScopeGroups[:i], s.ScopeGroups[i+1:]...)
			return
		}
	}
}
