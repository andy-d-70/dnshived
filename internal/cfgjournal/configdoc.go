// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package cfgjournal

import (
	"encoding/json"
	"fmt"

	"dnshived/internal/changeset"
	"dnshived/internal/config"
	"dnshived/internal/dnsstore/vfs"
)

// Excluded holds the top-level fields of cluster.json the journal never records: secrets (their history must not be
// kept) and the cluster's identity, whose change needs a restart. They keep their own replication path.
var Excluded = map[string]bool{
	"psk": true, "api_tokens": true, "tls_cert": true, "tls_key": true, "backup_password": true, "platform": true,
	"trusted_hosts": true,
}

// ConfigDoc is the cluster configuration as a journal target. It covers the part that is the same on every core;
// per-node fields, identity and secrets stay as they are in each core's file. It reads and writes through the config
// package, so both storage formats and their durable save are used.
type ConfigDoc struct {
	Name string
	Path string
}

func (d *ConfigDoc) DocName() string { return d.Name }

func (d *ConfigDoc) stampPath() string { return d.Path + ".journal" }

// Replicated returns the part of c the journal keeps: the configuration without per-node fields, identity and secrets.
func Replicated(c *config.Cluster) (any, error) {
	t, err := changeset.Tree(c)
	if err != nil {
		return nil, err
	}
	changeset.Strip(t)
	if m, ok := t.(map[string]any); ok {
		for k := range Excluded {
			delete(m, k)
		}
	}
	return t, nil
}

func sumTree(t any) (string, error) {
	b, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return sum(b), nil
}

func (d *ConfigDoc) Load() (tree any, rev uint64, contentSum string, err error) {
	c, err := config.Load(d.Path)
	if err != nil {
		return nil, 0, "", fmt.Errorf("%w: %w", ErrJournal, err)
	}
	if tree, err = Replicated(c); err != nil {
		return nil, 0, "", err
	}
	if contentSum, err = sumTree(tree); err != nil {
		return nil, 0, "", err
	}
	if rev, _, err = stampRev(vfs.OS{}, d.stampPath(), contentSum); err != nil {
		return nil, 0, "", fmt.Errorf("%s: %w", d.Path, err)
	}
	return tree, rev, contentSum, nil
}

// merged builds the configuration this core will hold: the replicated tree with this core's own fields (identity,
// per-node fields, secrets, a scope's node address) taken from its current file, and the revision advanced by the
// number of change sets.
func merged(cur *config.Cluster, tree any, sets int) (*config.Cluster, error) {
	full, err := changeset.Tree(cur)
	if err != nil {
		return nil, err
	}
	fm, _ := full.(map[string]any)
	out, ok := tree.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: the configuration is not an object", ErrJournal)
	}
	for k, v := range fm {
		if Excluded[k] || changeset.IgnoredField("", k) {
			out[k] = v
		}
	}
	for _, group := range []string{"scopes", "parked_scopes"} {
		have, _ := fm[group].(map[string]any)
		next, _ := out[group].(map[string]any)
		for name, sc := range next {
			cm, _ := have[name].(map[string]any)
			nm, ok := sc.(map[string]any)
			if !ok || cm == nil {
				continue
			}
			for k, v := range cm {
				if changeset.IgnoredField(group+".{}", k) {
					nm[k] = v
				}
			}
		}
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	var c config.Cluster
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%w: the merged configuration: %w", ErrJournal, err)
	}
	c.ConfigRevision = cur.ConfigRevision + int64(sets)
	return &c, nil
}

// Candidate is the configuration this core would hold with tree as its replicated part, for validation before a
// change is committed.
func (d *ConfigDoc) Candidate(tree any) (*config.Cluster, error) {
	cur, err := config.Load(d.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJournal, err)
	}
	return merged(cur, deepCopy(tree), 1)
}

func deepCopy(t any) any {
	switch v := t.(type) {
	case map[string]any:
		m := make(map[string]any, len(v))
		for k, x := range v {
			m[k] = deepCopy(x)
		}
		return m
	case []any:
		l := make([]any, len(v))
		for i, x := range v {
			l[i] = deepCopy(x)
		}
		return l
	}
	return t
}

// WithOwnFields returns dst with this core's own fields (identity, per-node fields, secrets, a scope's node address)
// taken from src, and dst's replicated part unchanged. It is how a change to own fields is saved next to the journal.
func WithOwnFields(dst, src *config.Cluster) (*config.Cluster, error) {
	rt, err := Replicated(dst)
	if err != nil {
		return nil, err
	}
	out, err := merged(src, rt, 0)
	if err != nil {
		return nil, err
	}
	out.ConfigRevision = dst.ConfigRevision
	return out, nil
}

func (d *ConfigDoc) Write(tree any, from, to uint64, prevSum string, sets int) error {
	cur, err := config.Load(d.Path)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrJournal, err)
	}
	next, err := merged(cur, tree, sets)
	if err != nil {
		return err
	}
	rt, err := Replicated(next)
	if err != nil {
		return err
	}
	nextSum, err := sumTree(rt)
	if err != nil {
		return err
	}
	return writeStamped(vfs.OS{}, d.stampPath(), from, to, prevSum, nextSum, func() error {
		if err := config.Save(d.Path, next); err != nil {
			return fmt.Errorf("%w: save %s: %w", ErrJournal, d.Path, err)
		}
		return nil
	})
}
