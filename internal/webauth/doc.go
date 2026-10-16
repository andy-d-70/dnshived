// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package webauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ResetToken is one pending password-reset link; only its SHA-256 is kept.
type ResetToken struct {
	User    string `json:"user"`
	Hash    string `json:"hash"`
	Expires string `json:"expires"`
}

// SMTPSettings is the outgoing mail server for reset and notification mail.
type SMTPSettings struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Security string `json:"security"` // "starttls", "tls" or "none"
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	From     string `json:"from"`
	CAPEM    string `json:"ca_pem,omitempty"`
}

// Meta identifies one revision of the replicated document.
type Meta struct {
	Version   int64  `json:"version"`
	UpdatedAt string `json:"updated_at"`
	Origin    string `json:"origin"`
}

// Newer reports whether a is a later revision than b. Equal versions are
// ordered by timestamp, then origin, so every instance picks the same one.
func Newer(a, b Meta) bool {
	if a.Version != b.Version {
		return a.Version > b.Version
	}
	if a.UpdatedAt != b.UpdatedAt {
		return a.UpdatedAt > b.UpdatedAt
	}
	return a.Origin > b.Origin
}

func (s *Store) Meta() Meta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.metaLocked()
}

func (s *Store) metaLocked() Meta {
	return Meta{Version: s.Version, UpdatedAt: s.UpdatedAt, Origin: s.Origin}
}

// Marshal returns the whole document as JSON.
func (s *Store) Marshal() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.MarshalIndent(s, "", "  ")
}

// Parse decodes a document received from another instance.
func Parse(data []byte) (*Store, error) {
	var f Store
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse users document: %w", err)
	}
	return &f, nil
}

func (s *Store) replaceWith(f *Store) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Version, s.UpdatedAt, s.Origin = f.Version, f.UpdatedAt, f.Origin
	s.SessionKey = f.SessionKey
	s.Users = append([]User(nil), f.Users...)
	s.Resets = append([]ResetToken(nil), f.Resets...)
	s.SMTP = nil
	if f.SMTP != nil {
		smtp := *f.SMTP
		s.SMTP = &smtp
	}
	s.PublicURL = f.PublicURL
}

// Mutate runs fn on the document under the write lock and, if fn succeeds,
// stamps a new revision from origin. fn must not call other Store methods.
func (s *Store) Mutate(origin string, fn func(d *Store) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(s); err != nil {
		return err
	}
	s.stampLocked(origin)
	return nil
}

func (s *Store) stampLocked(origin string) {
	s.Version++
	s.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.Origin = origin
}

// Adopt replaces s with remote when remote is newer. A document that was
// never replicated (version 0) is merged instead: its users missing from
// remote are kept, and the merged result gets a new revision so it spreads.
func (s *Store) Adopt(remote *Store, origin string) (adopted bool, kept []string) {
	rm := remote.Meta()
	s.mu.RLock()
	local := s.metaLocked()
	var legacy []User
	if local.Version == 0 {
		legacy = append(legacy, s.Users...)
	}
	s.mu.RUnlock()
	if !Newer(rm, local) {
		return false, nil
	}
	remote.mu.Lock()
	for _, u := range legacy {
		found := false
		for _, r := range remote.Users {
			if r.Name == u.Name {
				found = true
				break
			}
		}
		if !found {
			remote.Users = append(remote.Users, u)
			kept = append(kept, u.Name)
		}
	}
	if len(kept) > 0 {
		remote.stampLocked(origin)
	}
	remote.mu.Unlock()
	s.replaceWith(remote)
	return true, kept
}

// EnsureSessionKey creates the session signing key once. A document that
// was never replicated keeps version 0, so the first replication still
// merges its users instead of competing with them.
func (s *Store) EnsureSessionKey(origin string) (created bool, err error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.SessionKey != "" {
		return false, nil
	}
	s.SessionKey = hex.EncodeToString(key)
	if s.Version > 0 {
		s.stampLocked(origin)
	}
	return true, nil
}

// SessionKeyBytes returns the decoded session signing key.
func (s *Store) SessionKeyBytes() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, _ := hex.DecodeString(s.SessionKey)
	return k
}

// Lookup returns a copy of the named user.
func (s *Store) Lookup(name string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.Users {
		if u.Name == name {
			return u, true
		}
	}
	return User{}, false
}

// LookupLogin finds a user by name or, case-insensitively, by email.
func (s *Store) LookupLogin(nameOrEmail string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.Users {
		if u.Name == nameOrEmail {
			return u, true
		}
	}
	for _, u := range s.Users {
		if u.Email != "" && strings.EqualFold(u.Email, nameOrEmail) {
			return u, true
		}
	}
	return User{}, false
}

// List returns a copy of every user.
func (s *Store) List() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]User(nil), s.Users...)
}

// MailSettings returns a copy of the SMTP settings and the public URL.
func (s *Store) MailSettings() (SMTPSettings, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out SMTPSettings
	if s.SMTP != nil {
		out = *s.SMTP
	}
	return out, s.PublicURL
}

// ActiveAdmins counts enabled admins in d; call it inside Mutate.
func ActiveAdmins(d *Store) int {
	n := 0
	for _, u := range d.Users {
		if u.Role == RoleAdmin && !u.Disabled {
			n++
		}
	}
	return n
}

// HashToken returns the stored form of a reset token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// PruneResets drops expired reset tokens from d; call it inside Mutate.
func PruneResets(d *Store, now time.Time) {
	kept := d.Resets[:0]
	for _, r := range d.Resets {
		if exp, err := time.Parse(time.RFC3339, r.Expires); err == nil && now.Before(exp) {
			kept = append(kept, r)
		}
	}
	d.Resets = kept
}

// ResetUser returns the user a still-valid reset token belongs to.
func (s *Store) ResetUser(token string, now time.Time) (string, bool) {
	hash := HashToken(token)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.Resets {
		if r.Hash != hash {
			continue
		}
		exp, err := time.Parse(time.RFC3339, r.Expires)
		if err != nil || !now.Before(exp) {
			return "", false
		}
		return r.User, true
	}
	return "", false
}
