// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package webauth

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"dnshived/internal/notify"
)

// Item keys of the users document: "user/<name>", "reset/<hash>", and one key per setting. Each item is the JSON of
// its value; an empty setting is no item.
const (
	itemUser      = "user/"
	itemReset     = "reset/"
	itemSession   = "session_key"
	itemSMTP      = "smtp"
	itemPublicURL = "public_url"
	itemMinLen    = "min_password_length"
	itemNotify    = "notify"
)

// Items returns the document's content split into items.
func (s *Store) Items() (map[string][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string][]byte{}
	put := func(key string, v any) error {
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("item %s: %w", key, err)
		}
		out[key] = raw
		return nil
	}
	for _, u := range s.Users {
		if err := put(itemUser+u.Name, u); err != nil {
			return nil, err
		}
	}
	for _, r := range s.Resets {
		if err := put(itemReset+r.Hash, r); err != nil {
			return nil, err
		}
	}
	if s.SessionKey != "" {
		if err := put(itemSession, s.SessionKey); err != nil {
			return nil, err
		}
	}
	if s.SMTP != nil {
		if err := put(itemSMTP, s.SMTP); err != nil {
			return nil, err
		}
	}
	if s.PublicURL != "" {
		if err := put(itemPublicURL, s.PublicURL); err != nil {
			return nil, err
		}
	}
	if s.MinPasswordLength != 0 {
		if err := put(itemMinLen, s.MinPasswordLength); err != nil {
			return nil, err
		}
	}
	if s.Notify != nil {
		if err := put(itemNotify, s.Notify); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// WithItems returns a copy of s whose content is items; users and reset tokens keep the order they have in s, new
// ones follow sorted. The revision stamp is s's.
func (s *Store) WithItems(items map[string][]byte) (*Store, error) {
	s.mu.RLock()
	n := &Store{Version: s.Version, UpdatedAt: s.UpdatedAt, Origin: s.Origin}
	var userOrder, resetOrder []string
	for _, u := range s.Users {
		userOrder = append(userOrder, u.Name)
	}
	for _, r := range s.Resets {
		resetOrder = append(resetOrder, r.Hash)
	}
	s.mu.RUnlock()
	users, resets := map[string][]byte{}, map[string][]byte{}
	for key, raw := range items {
		var err error
		switch {
		case strings.HasPrefix(key, itemUser):
			users[strings.TrimPrefix(key, itemUser)] = raw
		case strings.HasPrefix(key, itemReset):
			resets[strings.TrimPrefix(key, itemReset)] = raw
		case key == itemSession:
			err = json.Unmarshal(raw, &n.SessionKey)
		case key == itemSMTP:
			n.SMTP = &SMTPSettings{}
			err = json.Unmarshal(raw, n.SMTP)
		case key == itemPublicURL:
			err = json.Unmarshal(raw, &n.PublicURL)
		case key == itemMinLen:
			err = json.Unmarshal(raw, &n.MinPasswordLength)
		case key == itemNotify:
			n.Notify = &notify.Settings{}
			err = json.Unmarshal(raw, n.Notify)
		default:
			err = fmt.Errorf("unknown item")
		}
		if err != nil {
			return nil, fmt.Errorf("users document item %q: %w", key, err)
		}
	}
	for _, name := range ordered(userOrder, users) {
		var u User
		if err := json.Unmarshal(users[name], &u); err != nil || u.Name != name {
			return nil, fmt.Errorf("users document item %q: not a user of that name", itemUser+name)
		}
		n.Users = append(n.Users, u)
	}
	for _, h := range ordered(resetOrder, resets) {
		var r ResetToken
		if err := json.Unmarshal(resets[h], &r); err != nil || r.Hash != h {
			return nil, fmt.Errorf("users document item %q: not a reset token of that hash", itemReset+h)
		}
		n.Resets = append(n.Resets, r)
	}
	if n.Users == nil {
		n.Users = []User{}
	}
	return n, nil
}

func ordered(order []string, have map[string][]byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, k := range order {
		if _, ok := have[k]; ok && !seen[k] {
			out = append(out, k)
			seen[k] = true
		}
	}
	var rest []string
	for k := range have {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// Clone returns an independent copy of the document.
func (s *Store) Clone() (*Store, error) {
	raw, err := s.Marshal()
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Install replaces s's content and stamp with f's.
func (s *Store) Install(f *Store) { s.replaceWith(f) }

// Stamp gives s a new revision from origin.
func (s *Store) Stamp(origin string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stampLocked(origin)
}
