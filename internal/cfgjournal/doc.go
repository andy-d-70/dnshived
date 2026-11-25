// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package cfgjournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"

	"dnshived/internal/changeset"
	"dnshived/internal/dnsstore"
	"dnshived/internal/dnsstore/vfs"
)

const maxDocBytes = 256 << 20

var (
	// ErrConflict means an item does not hold the value a change was based on; the change is not applied.
	ErrConflict = errors.New("cfgjournal: conflict")
	// ErrOutside means the document file is neither at its recorded revision nor at the one being written: it was
	// changed outside the journal. Nothing is overwritten.
	ErrOutside = errors.New("cfgjournal: document changed outside the journal")
)

type ConflictError struct {
	Rev  uint64
	Path string
	Have []byte
	Old  []byte
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("cfgjournal: conflict at %s (revision %d): the item holds %s, the change expected %s", e.Path, e.Rev, short(e.Have), short(e.Old))
}

func (e *ConflictError) Unwrap() error { return ErrConflict }

func short(b []byte) string {
	if b == nil {
		return "nothing"
	}
	if len(b) > 80 {
		return string(b[:80]) + "…"
	}
	return string(b)
}

// Target is a document the journal keeps up to date: a plain file (Document) or the cluster configuration
// (ConfigDoc). Load reports the revision the stored content belongs to; Write moves it from one revision to another so
// that a crash at any point leaves a state Load identifies exactly. sets is the number of change sets applied.
type Target interface {
	DocName() string
	Load() (tree any, rev uint64, contentSum string, err error)
	Write(tree any, from, to uint64, prevSum string, sets int) error
}

// Document is one configuration file kept by the journal, with a stamp file next to it that records which journal
// revision the file holds and the hash of its content.
type Document struct {
	FS   vfs.FS
	Name string
	Path string
	Mode os.FileMode
}

type stamp struct {
	Rev     uint64 `json:"rev"`
	Sum     string `json:"sha256"`
	NextRev uint64 `json:"next_rev,omitempty"`
	NextSum string `json:"next_sha256,omitempty"`
}

func (d *Document) stampPath() string { return d.Path + ".journal" }

func (d *Document) DocName() string { return d.Name }

// stampRev reports the revision a content hash belongs to according to the stamp file; ok is false when there is no
// stamp (the content is adopted at revision 0).
func stampRev(fsys vfs.FS, path, contentSum string) (rev uint64, ok bool, err error) {
	st, err := readFile(fsys, path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("%w: read stamp: %w", ErrJournal, err)
	}
	var s stamp
	if err := json.Unmarshal(st, &s); err != nil {
		return 0, false, fmt.Errorf("%w: stamp %s: %w", ErrJournal, path, err)
	}
	switch {
	case contentSum == s.Sum:
		return s.Rev, true, nil
	case s.NextSum != "" && contentSum == s.NextSum:
		return s.NextRev, true, nil
	}
	return 0, true, fmt.Errorf("%w: content %s, recorded %s", ErrOutside, contentSum[:min(12, len(contentSum))], s.Sum[:min(12, len(s.Sum))])
}

// writeStamped announces the next content in the stamp, runs store, then settles the stamp.
func writeStamped(fsys vfs.FS, path string, from, to uint64, prevSum, nextSum string, store func() error) error {
	intent, _ := json.Marshal(stamp{Rev: from, Sum: prevSum, NextRev: to, NextSum: nextSum})
	if err := writeAtomic(fsys, path, intent, 0o600); err != nil {
		return fmt.Errorf("%w: stamp: %w", ErrJournal, err)
	}
	if err := store(); err != nil {
		return err
	}
	done, _ := json.Marshal(stamp{Rev: to, Sum: nextSum})
	if err := writeAtomic(fsys, path, done, 0o600); err != nil {
		return fmt.Errorf("%w: stamp: %w", ErrJournal, err)
	}
	return nil
}

func readFile(fsys vfs.FS, path string) ([]byte, error) {
	f, err := fsys.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	n, err := f.Size()
	if err != nil {
		return nil, err
	}
	if n > maxDocBytes {
		return nil, fmt.Errorf("%s: %d bytes is above the limit", path, n)
	}
	b := make([]byte, n)
	if _, err := f.ReadAt(b, 0); err != nil && n > 0 {
		return nil, err
	}
	return b, nil
}

// writeAtomic replaces path with data: temporary file in the same directory, sync, rename, sync of the directory.
func writeAtomic(fsys vfs.FS, path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := fsys.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(data, 0); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := fsys.Rename(tmp, path); err != nil {
		return err
	}
	return fsys.SyncDir(filepath.Dir(path))
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func decodeTree(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after the document")
	}
	return v, nil
}

func encodeTree(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Load reads the document and the revision it holds. A file without a stamp is adopted at revision 0 as it is. A file
// that matches neither the recorded content nor the content being written was changed outside the journal.
func (d *Document) Load() (tree any, rev uint64, contentSum string, err error) {
	raw, err := readFile(d.FS, d.Path)
	if errors.Is(err, fs.ErrNotExist) {
		if _, serr := readFile(d.FS, d.stampPath()); serr == nil {
			return nil, 0, "", fmt.Errorf("%w: %s is missing but its stamp exists", ErrOutside, d.Path)
		}
		return map[string]any{}, 0, "", nil
	}
	if err != nil {
		return nil, 0, "", fmt.Errorf("%w: read %s: %w", ErrJournal, d.Path, err)
	}
	h := sum(raw)
	if rev, _, err = stampRev(d.FS, d.stampPath(), h); err != nil {
		return nil, 0, "", fmt.Errorf("%s: %w", d.Path, err)
	}
	tree, err = decodeTree(raw)
	if err != nil {
		return nil, 0, "", fmt.Errorf("%w: parse %s: %w", ErrJournal, d.Path, err)
	}
	return tree, rev, h, nil
}

// Write moves the document from revision from (content prevSum) to revision to.
func (d *Document) Write(tree any, from, to uint64, prevSum string, _ int) error {
	data, err := encodeTree(tree)
	if err != nil {
		return err
	}
	return writeStamped(d.FS, d.stampPath(), from, to, prevSum, sum(data), func() error {
		if err := writeAtomic(d.FS, d.Path, data, d.Mode); err != nil {
			return fmt.Errorf("%w: write %s: %w", ErrJournal, d.Path, err)
		}
		return nil
	})
}

func isAbsent(raw []byte) bool {
	return raw == nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// sameValue compares an item with a recorded value; JSON null counts as absent, as it does for the configuration.
func sameValue(have any, present bool, want []byte) (bool, error) {
	if !present || have == nil {
		return isAbsent(want), nil
	}
	if isAbsent(want) {
		return false, nil
	}
	w, err := decodeTree(want)
	if err != nil {
		return false, err
	}
	return reflect.DeepEqual(have, w), nil
}

// Apply applies records to tree, one change set (revision) at a time in a single pass over the document. An item
// that already holds the new value is skipped (a replay); one that holds the old value is changed; anything else
// stops with a ConflictError and tree must be discarded.
func Apply(tree any, recs []Record) (any, error) {
	for start := 0; start < len(recs); {
		end := start
		for end < len(recs) && recs[end].Rev == recs[start].Rev {
			end++
		}
		var err error
		if tree, err = applySet(tree, recs[start:end]); err != nil {
			return nil, err
		}
		start = end
	}
	return tree, nil
}

func applySet(tree any, set []Record) (any, error) {
	ups := make([]changeset.Update, 0, len(set))
	for i := range set {
		r := &set[i]
		var nv any
		if !isAbsent(r.New) {
			var err error
			if nv, err = decodeTree(r.New); err != nil {
				return nil, fmt.Errorf("%w: new value at %s: %w", ErrJournal, r.Path, err)
			}
		}
		ups = append(ups, changeset.Update{Path: r.Path, Value: nv, Check: func(have any, present bool) error {
			if done, err := sameValue(have, present, r.New); err != nil || done {
				if err != nil {
					return fmt.Errorf("%w: new value at %s: %w", ErrJournal, r.Path, err)
				}
				return nil
			}
			ok, err := sameValue(have, present, r.Old)
			if err != nil {
				return fmt.Errorf("%w: old value at %s: %w", ErrJournal, r.Path, err)
			}
			if !ok {
				var cur []byte
				if present && have != nil {
					cur, _ = json.Marshal(have)
				}
				return &ConflictError{Rev: r.Rev, Path: r.Path, Have: cur, Old: r.Old}
			}
			return nil
		}})
	}
	out, err := changeset.SetAll(tree, ups)
	if err != nil {
		var ce *ConflictError
		if errors.As(err, &ce) || errors.Is(err, ErrJournal) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: revision %d: %w", ErrJournal, set[0].Rev, err)
	}
	return out, nil
}

// Replay brings the target up to the journal: it applies every entry for this document after the revision the target
// holds and writes it once. On a conflict the target is left as it was.
func Replay(v *dnsstore.View, t Target) (applied int, rev uint64, err error) {
	tree, rev, h, err := t.Load()
	if err != nil {
		return 0, 0, err
	}
	recs, err := Since(v, rev)
	if err != nil {
		return 0, rev, err
	}
	mine := recs[:0]
	sets := 0
	for _, r := range recs {
		if r.Doc == t.DocName() {
			if len(mine) == 0 || mine[len(mine)-1].Rev != r.Rev {
				sets++
			}
			mine = append(mine, r)
		}
	}
	if len(mine) == 0 {
		return 0, rev, nil
	}
	tree, err = Apply(tree, mine)
	if err != nil {
		return 0, rev, err
	}
	last := mine[len(mine)-1].Rev
	if h == "" {
		h = sum(nil)
	}
	if err := t.Write(tree, rev, last, h, sets); err != nil {
		return 0, rev, err
	}
	return len(mine), last, nil
}

// FromChange turns a change of a whole document into one entry per changed item, with the old and the new value of
// each, in path order, from one walk over both documents; Meta and Seq are filled by Append.
func FromChange(doc string, live, cand any, base uint64) ([]Entry, error) {
	var out []Entry
	var bad error
	changeset.Each(live, cand, func(p string, l, c any) {
		if bad != nil {
			return
		}
		e := Entry{Doc: doc, Path: p, Base: base}
		if l != nil {
			if e.Old, bad = json.Marshal(l); bad != nil {
				return
			}
		}
		if c != nil {
			if e.New, bad = json.Marshal(c); bad != nil {
				return
			}
		}
		if e.Old != nil || e.New != nil {
			out = append(out, e)
		}
	})
	return out, bad
}
