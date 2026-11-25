// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package cfgjournal

import (
	"errors"
	"fmt"
	"sync"

	"dnshived/internal/dnsstore"
)

// Writer is the single point where changes to one target are ordered: it runs on the core that leads the journal.
// Check, write and apply happen under one lock, so of two changes to the same item the first is committed and the
// second is refused, however close together they arrive.
type Writer struct {
	mu      sync.Mutex
	journal *Journal
	target  Target
	view    func() *dnsstore.View
	// Validate, when set, sees the whole document the change would produce and can refuse it.
	Validate func(tree any) error
}

func NewWriter(j *Journal, t Target, view func() *dnsstore.View) *Writer {
	return &Writer{journal: j, target: t, view: view}
}

// Result says what a proposal did. Noop means every item already held the proposed value. Kept is the revision at
// which a refused change was recorded in the conflict log.
type Result struct {
	Rev  uint64
	Noop bool
	Kept uint64
}

// ConflictDoc names the document under which refused changes of doc are kept; it is never applied to a file.
func ConflictDoc(doc string) string { return "conflicts:" + doc }

// Propose checks entries against the current document and commits them as one change set. An item that holds
// neither the change's old value nor its new value refuses the whole change with a ConflictError; nothing is written.
func (w *Writer) Propose(m Meta, entries []Entry) (Result, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, _, err := Replay(w.view(), w.target); err != nil {
		return Result{}, fmt.Errorf("bring the document up to date: %w", err)
	}
	tree, rev, _, err := w.target.Load()
	if err != nil {
		return Result{}, err
	}
	before, err := sumTree(tree)
	if err != nil {
		return Result{}, err
	}
	for i := range entries {
		if entries[i].Doc != w.target.DocName() {
			return Result{}, fmt.Errorf("%w: entry for %q sent to the writer of %q", ErrEntry, entries[i].Doc, w.target.DocName())
		}
	}
	recs := make([]Record, len(entries))
	for i := range entries {
		recs[i] = Record{Entry: entries[i]}
	}
	next, err := Apply(tree, recs)
	if err != nil {
		var ce *ConflictError
		if errors.As(err, &ce) {
			kept, kerr := w.keep(m, entries)
			if kerr != nil {
				return Result{}, fmt.Errorf("%w; keeping the refused change failed too: %w", err, kerr)
			}
			return Result{Kept: kept}, err
		}
		return Result{}, err
	}
	after, err := sumTree(next)
	if err != nil {
		return Result{}, err
	}
	if after == before {
		return Result{Rev: rev, Noop: true}, nil
	}
	if w.Validate != nil {
		if err := w.Validate(next); err != nil {
			return Result{}, err
		}
	}
	committed, err := w.journal.Append(m, entries)
	if err != nil {
		return Result{}, err
	}
	if _, _, err := Replay(w.view(), w.target); err != nil {
		return Result{Rev: committed}, fmt.Errorf("committed at revision %d but not applied here: %w", committed, err)
	}
	return Result{Rev: committed}, nil
}

// keep records a refused change in the conflict log with everything it tried to set (R5: the later entry is kept).
func (w *Writer) keep(m Meta, entries []Entry) (uint64, error) {
	kept := make([]Entry, len(entries))
	for i, e := range entries {
		e.Doc = ConflictDoc(e.Doc)
		kept[i] = e
	}
	return w.journal.Append(m, kept)
}

// Sync applies every committed change the document does not hold yet, under the same lock as Propose.
func (w *Writer) Sync() (applied int, rev uint64, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return Replay(w.view(), w.target)
}
