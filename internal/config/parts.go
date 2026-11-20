// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	SplitFormatVersion = 1
	SplitDirSuffix     = ".d"
	manifestFileName   = "manifest.json"
	baseFileName       = "base.json"
	maxPartBytes       = 256 << 20
	maxManifestBytes   = 32 << 20
)

const (
	PartBase   = "base"
	PartScope  = "scope"
	PartDomain = "domain"
	PartParked = "parked"
)

type PartRef struct {
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
	Hash string `json:"hash"`
	Size int    `json:"size"`
}

type Manifest struct {
	Format   int       `json:"format"`
	Revision int64     `json:"revision,omitempty"`
	Parts    []PartRef `json:"parts"`
}

// Hash covers every part's kind, name and content hash, in manifest order, so
// a change to any part, known kind or not, changes it. Revision and sizes are left out.
func (m Manifest) Hash() string {
	var b strings.Builder
	for _, p := range m.Parts {
		b.WriteString(p.Kind)
		b.WriteByte(0)
		b.WriteString(p.Name)
		b.WriteByte(0)
		b.WriteString(p.Hash)
		b.WriteByte('\n')
	}
	return shortHash([]byte(b.String()))
}

// PartPath is where a part lives below the split directory. Names are checked
// against the same patterns the configuration validates, so a part can never
// point outside the directory.
func PartPath(kind, name string) (string, error) {
	switch kind {
	case PartBase:
		return baseFileName, nil
	case PartScope:
		if !ValidScopeName(name) {
			return "", fmt.Errorf("part scope %q: not a valid scope name", name)
		}
		return "scopes/" + name + ".json", nil
	case PartParked:
		if !ValidScopeName(name) {
			return "", fmt.Errorf("part parked scope %q: not a valid scope name", name)
		}
		return "parked/" + name + ".json", nil
	case PartDomain:
		if !domainNamePattern.MatchString(name) {
			return "", fmt.Errorf("part domain %q: not a valid domain name", name)
		}
		return "domains/" + strings.ToLower(name) + ".json", nil
	}
	return "", fmt.Errorf("part kind %q is not known", kind)
}

func knownPartKind(kind string) bool {
	return kind == PartBase || kind == PartScope || kind == PartDomain || kind == PartParked
}

func baseReplicated(c *Cluster) []byte {
	doc, err := c.documentJSONWithout()
	if err != nil {
		return nil
	}
	x := c.v2Extra()
	x.ParkedScopes = nil
	extra, err := json.Marshal(x)
	if err != nil {
		return nil
	}
	return append(doc, extra...)
}

func scopeReplicated(sc ScopeConfig) []byte {
	sc.NodeIP = ""
	b, _ := json.Marshal(sc)
	return b
}

func domainReplicated(d LocalDomain) []byte {
	b, _ := json.Marshal(d)
	return b
}

func (c *Cluster) documentJSONWithout() ([]byte, error) {
	cp := *c
	cp.Scopes = nil
	cp.LocalDomains = nil
	return cp.documentJSON()
}

func (c *Cluster) v2Extra() documentV2Extra {
	return documentV2Extra{
		SanityCheckDisabled: c.SanityCheckDisabled, BackupEnabled: c.BackupEnabled,
		BackupIntervalHours: c.BackupIntervalHours, BackupRetentionCount: c.BackupRetentionCount,
		BackupPassword: c.BackupPassword, BackupReplicateToPeers: c.BackupReplicateToPeers,
		Access: c.Access, ParkedScopes: normalizedParked(c.ParkedScopes),
	}
}

// Split cuts the configuration into a manifest and its parts. The map holds
// each part's stored bytes by path below the split directory.
func (c *Cluster) Split() (Manifest, map[string][]byte, error) {
	files := make(map[string][]byte, 1+len(c.Scopes)+len(c.LocalDomains))
	m := Manifest{Format: SplitFormatVersion, Revision: c.ConfigRevision}

	base := *c
	base.Scopes = nil
	base.LocalDomains = nil
	base.ParkedScopes = nil
	stored, err := json.MarshalIndent(&base, "", "  ")
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("marshal base part: %w", err)
	}
	files[baseFileName] = stored
	m.Parts = append(m.Parts, PartRef{Kind: PartBase, Hash: shortHash(baseReplicated(c)), Size: len(stored)})

	names := make([]string, 0, len(c.Scopes))
	for name := range c.Scopes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p, err := PartPath(PartScope, name)
		if err != nil {
			return Manifest{}, nil, err
		}
		sc := c.Scopes[name]
		stored, err := json.MarshalIndent(sc, "", "  ")
		if err != nil {
			return Manifest{}, nil, fmt.Errorf("marshal scope %s: %w", name, err)
		}
		files[p] = stored
		m.Parts = append(m.Parts, PartRef{Kind: PartScope, Name: name, Hash: shortHash(scopeReplicated(sc)), Size: len(stored)})
	}

	parkedNames := make([]string, 0, len(c.ParkedScopes))
	for name := range c.ParkedScopes {
		parkedNames = append(parkedNames, name)
	}
	sort.Strings(parkedNames)
	for _, name := range parkedNames {
		p, err := PartPath(PartParked, name)
		if err != nil {
			return Manifest{}, nil, err
		}
		sc := c.ParkedScopes[name]
		stored, err := json.MarshalIndent(sc, "", "  ")
		if err != nil {
			return Manifest{}, nil, fmt.Errorf("marshal parked scope %s: %w", name, err)
		}
		files[p] = stored
		m.Parts = append(m.Parts, PartRef{Kind: PartParked, Name: name, Hash: shortHash(scopeReplicated(sc)), Size: len(stored)})
	}

	for _, d := range c.LocalDomains {
		p, err := PartPath(PartDomain, d.Name)
		if err != nil {
			return Manifest{}, nil, err
		}
		if _, dup := files[p]; dup {
			return Manifest{}, nil, fmt.Errorf("domain %q is configured more than once", d.Name)
		}
		stored, err := json.MarshalIndent(d, "", "  ")
		if err != nil {
			return Manifest{}, nil, fmt.Errorf("marshal domain %s: %w", d.Name, err)
		}
		files[p] = stored
		m.Parts = append(m.Parts, PartRef{Kind: PartDomain, Name: d.Name, Hash: shortHash(domainReplicated(d)), Size: len(stored)})
	}
	return m, files, nil
}

// Assemble rebuilds the configuration from a manifest and a reader for its
// parts. Every known part is checked against its manifest hash; parts of an
// unknown kind are skipped, so a manifest from a newer version still loads.
func Assemble(m Manifest, read func(path string) ([]byte, error)) (*Cluster, error) {
	if m.Format < 1 || m.Format > SplitFormatVersion {
		return nil, fmt.Errorf("split config format %d is not supported", m.Format)
	}
	var c *Cluster
	seen := make(map[string]bool, len(m.Parts))
	var scopes, parked map[string]ScopeConfig
	var domains []LocalDomain
	for _, ref := range m.Parts {
		if !knownPartKind(ref.Kind) {
			continue
		}
		path, err := PartPath(ref.Kind, ref.Name)
		if err != nil {
			return nil, err
		}
		if seen[path] {
			return nil, fmt.Errorf("part %s is listed twice", path)
		}
		seen[path] = true
		data, err := read(path)
		if err != nil {
			return nil, fmt.Errorf("read part %s: %w", path, err)
		}
		var got string
		switch ref.Kind {
		case PartBase:
			var b Cluster
			if err := json.Unmarshal(data, &b); err != nil {
				return nil, fmt.Errorf("parse part %s: %w", path, err)
			}
			c = &b
		case PartScope:
			var sc ScopeConfig
			if err := json.Unmarshal(data, &sc); err != nil {
				return nil, fmt.Errorf("parse part %s: %w", path, err)
			}
			if scopes == nil {
				scopes = map[string]ScopeConfig{}
			}
			scopes[ref.Name] = sc
			got = shortHash(scopeReplicated(sc))
		case PartParked:
			var sc ScopeConfig
			if err := json.Unmarshal(data, &sc); err != nil {
				return nil, fmt.Errorf("parse part %s: %w", path, err)
			}
			if parked == nil {
				parked = map[string]ScopeConfig{}
			}
			parked[ref.Name] = sc
			got = shortHash(scopeReplicated(sc))
		case PartDomain:
			var d LocalDomain
			if err := json.Unmarshal(data, &d); err != nil {
				return nil, fmt.Errorf("parse part %s: %w", path, err)
			}
			if d.Name != ref.Name {
				return nil, fmt.Errorf("part %s holds domain %q", path, d.Name)
			}
			domains = append(domains, d)
			got = shortHash(domainReplicated(d))
		}
		if got != "" && got != ref.Hash {
			return nil, fmt.Errorf("part %s does not match the manifest (hash %s, want %s)", path, got, ref.Hash)
		}
	}
	if c == nil {
		return nil, errors.New("split config has no base part")
	}
	c.Scopes = scopes
	c.ParkedScopes = parked
	c.LocalDomains = domains
	// The manifest carries the revision of the last save; a base part written
	// before it must not hold the revision back.
	if m.Revision > c.ConfigRevision {
		c.ConfigRevision = m.Revision
	}
	for _, ref := range m.Parts {
		if ref.Kind == PartBase && shortHash(baseReplicated(c)) != ref.Hash {
			return nil, errors.New("base part does not match the manifest")
		}
	}
	return c, nil
}

func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}

// SplitDir is the directory a split configuration lives in for a given
// single-file path.
func SplitDir(path string) string { return path + SplitDirSuffix }

// LoadSplit reads and validates a split configuration directory.
func LoadSplit(dir string) (*Cluster, error) {
	raw, err := readCapped(filepath.Join(dir, manifestFileName), maxManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("read split config manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse split config manifest: %w", err)
	}
	c, err := Assemble(m, func(p string) ([]byte, error) {
		return readCapped(filepath.Join(dir, filepath.FromSlash(p)), maxPartBytes)
	})
	if err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(tmp)
		return werr
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// SaveSplit writes the parts that differ from what the directory holds, then
// the manifest last, and removes part files the manifest no longer lists. An
// unchanged part is recognised by the hash the old manifest holds for it, so
// the unchanged parts are not even read.
func SaveSplit(dir string, c *Cluster) error {
	if err := c.validate(); err != nil {
		return err
	}
	m, files, err := c.Split()
	if err != nil {
		return err
	}
	known := map[string]string{}
	if raw, err := readCapped(filepath.Join(dir, manifestFileName), maxManifestBytes); err == nil {
		var old Manifest
		if json.Unmarshal(raw, &old) == nil {
			for _, ref := range old.Parts {
				if rel, err := PartPath(ref.Kind, ref.Name); err == nil {
					known[rel] = ref.Hash
				}
			}
		}
	}
	// Only a domain part's stored bytes are fully covered by its hash. The base
	// part also holds the revision and the node's own fields, a scope part its node
	// address, and neither is hashed, so those parts are compared byte for byte.
	isDomainPart := func(rel string) bool { return strings.HasPrefix(rel, "domains/") }
	newHash := map[string]string{}
	for _, ref := range m.Parts {
		if rel, err := PartPath(ref.Kind, ref.Name); err == nil {
			newHash[rel] = ref.Hash
		}
	}
	for p, data := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if isDomainPart(p) && known[p] != "" && known[p] == newHash[p] && fileExists(full) {
			continue
		}
		if old, err := readCapped(full, maxPartBytes); err == nil && string(old) == string(data) {
			continue
		}
		if err := writeAtomic(full, data); err != nil {
			return fmt.Errorf("write part %s: %w", p, err)
		}
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	if err := writeAtomic(filepath.Join(dir, manifestFileName), raw); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	for _, sub := range []string{"scopes", "domains", "parked"} {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		if err != nil {
			continue
		}
		for _, e := range entries {
			rel := sub + "/" + e.Name()
			if _, keep := files[rel]; !keep && strings.HasSuffix(e.Name(), ".json") {
				os.Remove(filepath.Join(dir, sub, e.Name()))
			}
		}
	}
	return nil
}

// ConfigFormats lists the configuration formats this build reads.
func ConfigFormats() []string { return []string{"single", "split"} }
