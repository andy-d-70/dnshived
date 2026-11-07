// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package repldoc keeps one small document identical on every web instance
// of a cluster. A document carries a revision stamp; instances compare
// stamps, the newer document replaces the older one, and an instance that
// was away catches up on its next comparison.
package repldoc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Meta is the revision stamp of a document.
type Meta struct {
	Version   int64  `json:"version"`
	UpdatedAt string `json:"updated_at"`
	Origin    string `json:"origin"`
	// Hash is the hash of the document content without the stamp; empty
	// when the sender is too old to send one.
	Hash string `json:"hash,omitempty"`
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

// Conflict reports whether a and b are two different documents with the
// same version. A missing hash never counts as a conflict.
func Conflict(a, b Meta) bool {
	return a.Version == b.Version && a.Hash != "" && b.Hash != "" && a.Hash != b.Hash
}

// Limits on a stamp received from another instance.
const (
	maxVersion  = 1 << 53
	maxStampLen = 128
)

// ValidMeta refuses a stamp no instance would write: a negative or huge
// version (a huge one would block every later revision) or oversized text.
func ValidMeta(m Meta) error {
	if m.Version < 0 || m.Version > maxVersion {
		return fmt.Errorf("revision %d is out of range", m.Version)
	}
	if len(m.UpdatedAt) > maxStampLen || len(m.Origin) > maxStampLen || len(m.Hash) > maxStampLen {
		return errors.New("revision stamp has an oversized field")
	}
	return nil
}

// BodyHash returns the hash used in Meta.Hash for canonical content bytes.
func BodyHash(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// Doc is a replicated document as the Syncer sees it.
type Doc interface {
	Meta() Meta
	// Marshal returns the whole document as sent to a sibling.
	Marshal() ([]byte, error)
	// Adopt parses, validates and installs raw when it is newer than the
	// local document, saving it. spread is true when the result differs from
	// raw (a merge happened) and must be sent to the other instances.
	Adopt(raw []byte, from string) (adopted, spread bool, err error)
	// StartFirst begins revision 1 for a document that was never replicated.
	StartFirst(self string) error
}

// Drifter is implemented by documents whose content can change outside the
// document's own change path. Drift stamps a new revision when the content
// no longer matches the last stamp.
type Drifter interface {
	Drift(self string) (changed bool, err error)
}

// Peer is one other instance.
type Peer struct {
	Name string
	Data any
}

// Syncer runs the comparison for one document.
type Syncer struct {
	Name  string
	Path  string
	Doc   Doc
	Self  func() string
	Peers func() []Peer
	// Do sends one request to a peer and returns the response body.
	Do func(p Peer, method, path string, body []byte) ([]byte, error)
	// DecodeMeta decodes a peer's meta response.
	DecodeMeta func(raw []byte) (Meta, error)
	// OnConflict is called when a peer holds a different document with the same version.
	OnConflict func(local, remote Meta, peer string)
	// AfterPass is called after every comparison started by Run.
	AfterPass func()
	Logf      func(format string, args ...any)

	mu sync.Mutex
}

func (s *Syncer) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// PushTo sends the local document to p.
func (s *Syncer) PushTo(p Peer) error {
	data, err := s.Doc.Marshal()
	if err != nil {
		return err
	}
	_, err = s.Do(p, "POST", s.Path, data)
	return err
}

// PushAll sends the local document to every peer.
func (s *Syncer) PushAll() {
	for _, p := range s.Peers() {
		if err := s.PushTo(p); err != nil {
			s.logf("[%s] push to %s: %v (it catches up on the next comparison)", s.Name, p.Name, err)
		}
	}
}

// StartsFirstRevision reports whether self has the lowest name among itself
// and the peers that never replicated.
func StartsFirstRevision(self string, legacyPeers []string) bool {
	names := append([]string{self}, legacyPeers...)
	sort.Strings(names)
	return names[0] == self
}

// SyncOnce compares with every peer: pulls a newer document, pushes the
// local one to a peer that is behind, flags a same-version conflict. While
// no instance has replicated, the reachable one with the lowest name starts
// revision 1 and the others merge into it.
func (s *Syncer) SyncOnce() {
	s.mu.Lock()
	defer s.mu.Unlock()
	self := s.Self()
	if d, ok := s.Doc.(Drifter); ok {
		changed, err := d.Drift(self)
		if err != nil {
			s.logf("[%s] stamp local change: %v", s.Name, err)
		} else if changed {
			go s.PushAll()
		}
	}
	local := s.Doc.Meta()
	var legacyPeers []string
	newerSeen := false
	for _, p := range s.Peers() {
		raw, err := s.Do(p, "GET", s.Path+"/meta", nil)
		if err != nil {
			continue
		}
		m, err := s.DecodeMeta(raw)
		if err != nil {
			continue
		}
		if Conflict(local, m) && s.OnConflict != nil {
			s.OnConflict(local, m, p.Name)
		}
		switch {
		case Newer(m, local):
			newerSeen = true
			doc, err := s.Do(p, "GET", s.Path, nil)
			if err != nil {
				s.logf("[%s] fetch from %s: %v", s.Name, p.Name, err)
				continue
			}
			adopted, spread, err := s.Doc.Adopt(doc, p.Name)
			if err != nil {
				s.logf("[%s] adopt from %s: %v", s.Name, p.Name, err)
			} else if adopted && spread {
				go s.PushAll()
			}
			local = s.Doc.Meta()
		case Newer(local, m):
			if err := s.PushTo(p); err != nil {
				s.logf("[%s] push to %s: %v", s.Name, p.Name, err)
			}
		}
		if m.Version == 0 {
			legacyPeers = append(legacyPeers, p.Name)
		}
	}
	if local.Version == 0 && !newerSeen && StartsFirstRevision(self, legacyPeers) {
		if err := s.Doc.StartFirst(self); err != nil {
			s.logf("[%s] start the replicated document: %v", s.Name, err)
			return
		}
		s.logf("[%s] started the replicated document (revision 1); the other instances merge into it", s.Name)
		go s.PushAll()
	}
}

// Run compares after delay and then every interval until ctx ends.
func (s *Syncer) Run(ctx context.Context, delay, interval time.Duration) {
	go func() {
		t := time.NewTimer(delay)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.SyncOnce()
				if s.AfterPass != nil {
					s.AfterPass()
				}
				t.Reset(interval)
			}
		}
	}()
}
