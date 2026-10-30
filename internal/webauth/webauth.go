// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package webauth loads and verifies credentials for cmd/dnshived-web.
package webauth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"dnshived/internal/ownership"
)

// Tuned for PBKDF2-HMAC-SHA256 per current guidance.
const (
	pbkdf2SaltBytes  = 16
	pbkdf2Iterations = 600_000
	pbkdf2KeyBytes   = 32
)

// User is one web-UI credential.
type User struct {
	Name         string `json:"name"`
	PasswordHash string `json:"password_hash"` // see HashPassword
	Role         string `json:"role"`
	Email        string `json:"email,omitempty"`
	Disabled     bool   `json:"disabled,omitempty"`
	// SessionEpoch invalidates every session cookie issued before it changed.
	SessionEpoch int64 `json:"session_epoch,omitempty"`
}

// Store is the on-disk credentials file shape (e.g.
// /etc/dnshived/webui-users.json), replicated whole between the web
// instances of a cluster (see doc.go).
type Store struct {
	Version    int64         `json:"version,omitempty"`
	UpdatedAt  string        `json:"updated_at,omitempty"`
	Origin     string        `json:"origin,omitempty"`
	SessionKey string        `json:"session_key,omitempty"`
	Users      []User        `json:"users"`
	Resets     []ResetToken  `json:"resets,omitempty"`
	SMTP       *SMTPSettings `json:"smtp,omitempty"`
	PublicURL  string        `json:"public_url,omitempty"`

	mu sync.RWMutex
}

// Load reads and parses a credentials file.
func Load(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read webui users file %s: %w", path, err)
	}
	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse webui users file: %w", err)
	}
	return &s, nil
}

// Verify looks up username and checks password against its stored hash.
func (s *Store) Verify(username, password string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.Users {
		if u.Name != username {
			continue
		}
		if verifyPassword(password, u.PasswordHash) && !u.Disabled {
			return u, true
		}
		return User{}, false
	}
	verifyPassword(password, dummyHash())
	return User{}, false
}

// PrepareTiming computes the unknown-user dummy hash ahead of the first
// login, so even that first check takes the usual time.
func PrepareTiming() { dummyHash() }

// verifyPassword is VerifyPassword, replaceable in tests.
var verifyPassword = VerifyPassword

// dummyHash makes a check for an unknown user cost the same as for a known
// one, so response time does not reveal which user names exist.
var dummyHash = sync.OnceValue(func() string {
	h, err := HashPassword("unknown-user-timing-equalizer")
	if err != nil {
		return ""
	}
	return h
})

// HashPassword derives a PBKDF2-HMAC-SHA256 hash for password with a fresh
// random salt, returning "salt:iterations:key" (all hex).
func HashPassword(password string) (string, error) {
	salt := make([]byte, pbkdf2SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, pbkdf2KeyBytes)
	if err != nil {
		return "", fmt.Errorf("derive key: %w", err)
	}
	return fmt.Sprintf("%s:%d:%s", hex.EncodeToString(salt), pbkdf2Iterations, hex.EncodeToString(key)), nil
}

func (s *Store) Save(path string) error {
	s.mu.RLock()
	data, err := json.MarshalIndent(s, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("marshal webui users: %w", err)
	}
	if err := atomicWriteFile(path, data, 0o640); err != nil {
		return fmt.Errorf("write webui users file %s: %w", path, err)
	}
	if err := chownToDnshivedGroup(path); err != nil {
		return fmt.Errorf("chown webui users file %s to dnshived group: %w", path, err)
	}
	return nil
}

// chownToDnshivedGroup sets path's group ownership to "dnshived" without
// touching its owner.
func chownToDnshivedGroup(path string) error {
	return ownership.Dnshived(path)
}

// atomicWriteFile writes data to path via temp file + fsync + rename,
// cleaning up the temp file on every failure path.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
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

// ReplaceFrom reloads the whole document from path into s in place.
func (s *Store) ReplaceFrom(path string) error {
	fresh, err := Load(path)
	if err != nil {
		return err
	}
	s.replaceWith(fresh)
	return nil
}

// Upsert adds a new user or overwrites an existing one by name, hashing
// password fresh each time.
func (s *Store) Upsert(name, password, role string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	s.UpsertHash(name, hash, role)
	return nil
}

// UpsertHash is Upsert's counterpart for an already-computed password
// hash.
func (s *Store) UpsertHash(name, hash, role string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.Users {
		if u.Name == name {
			s.Users[i].PasswordHash = hash
			s.Users[i].Role = role
			s.Users[i].SessionEpoch++
			return
		}
	}
	s.Users = append(s.Users, User{Name: name, PasswordHash: hash, Role: role})
}

func VerifyPassword(password, stored string) bool {
	parts := strings.SplitN(stored, ":", 3)
	if len(parts) != 3 {
		return false
	}
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations <= 0 {
		return false
	}
	wantKey, err := hex.DecodeString(parts[2])
	if err != nil || len(wantKey) == 0 {
		return false
	}
	gotKey, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(wantKey))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(gotKey, wantKey) == 1
}

// Permission is a named capability a role may grant.
type Permission string

const (
	PermViewStatus Permission = "view_status"
	PermViewAudit  Permission = "view_audit"
	// PermEditScopes covers everything served to clients: scopes, DHCP/DNS
	// settings, templates, local domains.
	PermEditScopes Permission = "edit_scopes"
	// PermEditConfig covers cluster settings, nodes, users, tokens, backups
	// and daemon restarts.
	PermEditConfig Permission = "edit_config"
)

const (
	RoleAdmin      = "admin"
	RoleScopeAdmin = "scopeadmin"
	RoleReadonly   = "readonly"
)

// Roles lists every assignable role, most privileged first.
var Roles = []string{RoleAdmin, RoleScopeAdmin, RoleReadonly}

// rolePermissions maps a role name to the permissions it grants.
var rolePermissions = map[string]map[Permission]bool{
	RoleReadonly: {
		PermViewStatus: true,
		PermViewAudit:  true,
	},
	RoleScopeAdmin: {
		PermViewStatus: true,
		PermViewAudit:  true,
		PermEditScopes: true,
	},
	RoleAdmin: {
		PermViewStatus: true,
		PermViewAudit:  true,
		PermEditScopes: true,
		PermEditConfig: true,
	},
}

// ValidRole reports whether role is assignable.
func ValidRole(role string) bool {
	_, ok := rolePermissions[role]
	return ok
}

// HasPermission reports whether u's role grants p.
func (u User) HasPermission(p Permission) bool {
	return rolePermissions[u.Role][p]
}
