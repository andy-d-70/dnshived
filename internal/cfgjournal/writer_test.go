// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package cfgjournal

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"dnshived/internal/dnsstore/vfs/faultfs"
)

func writerOn(t *testing.T) (*Writer, *Document) {
	t.Helper()
	fs, s := faultfs.New(5), newStore(t)
	seed(t, fs, map[string]any{"log_level": "info", "n": 1})
	d := docOn(fs)
	return NewWriter(New(s.Commit), d, s.View), d
}

func set(path, old, new string) Entry {
	e := Entry{Doc: "cluster", Path: path, New: []byte(new)}
	if old != "" {
		e.Old = []byte(old)
	}
	return e
}

func TestWriter_CommitsRefusesAndRecognisesTheSameChangeAgain(t *testing.T) {
	w, d := writerOn(t)
	r, err := w.Propose(Meta{Author: "ann"}, []Entry{set("log_level", `"info"`, `"debug"`)})
	if err != nil || r.Noop || r.Rev == 0 {
		t.Fatalf("first: %+v %v", r, err)
	}
	if again, err := w.Propose(Meta{Author: "ann"}, []Entry{set("log_level", `"info"`, `"debug"`)}); err != nil || !again.Noop {
		t.Fatalf("the same change again (another core forwarded it) is a no-op: %+v %v", again, err)
	}
	_, err = w.Propose(Meta{Author: "bob"}, []Entry{set("log_level", `"info"`, `"warn"`)})
	var ce *ConflictError
	if !errors.As(err, &ce) || ce.Path != "log_level" {
		t.Fatalf("a change based on the old value after someone else changed it: %v", err)
	}
	tree, rev, _, _ := d.Load()
	if tree.(map[string]any)["log_level"] != "debug" || rev != r.Rev {
		t.Fatalf("the first change stays: %v at %d", tree, rev)
	}
	recs, err := Since(w.view(), rev)
	if err != nil || len(recs) != 1 || recs[0].Doc != ConflictDoc("cluster") || recs[0].Author != "bob" || string(recs[0].New) != `"warn"` {
		t.Fatalf("the refused change must be kept with its author and value: %+v %v", recs, err)
	}
	if _, again, err := Replay(w.view(), d); err != nil || again != rev {
		t.Fatalf("a kept conflict never reaches the document: %d %v", again, err)
	}
}

func TestWriter_ValidateCanRefuse(t *testing.T) {
	w, d := writerOn(t)
	bad := errors.New("not allowed")
	w.Validate = func(any) error { return bad }
	if _, err := w.Propose(Meta{}, []Entry{set("log_level", `"info"`, `"x"`)}); !errors.Is(err, bad) {
		t.Fatal(err)
	}
	if tree, _, _, _ := d.Load(); tree.(map[string]any)["log_level"] != "info" {
		t.Fatal("a refused change leaves the document as it was")
	}
}

func TestWriter_OfTwoChangesAtTheSameMomentExactlyOneWins(t *testing.T) {
	for round := range 20 {
		t.Run(fmt.Sprint(round), func(t *testing.T) {
			w, d := writerOn(t)
			var wg sync.WaitGroup
			errs := make([]error, 2)
			for i, v := range []string{`"a"`, `"b"`} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, errs[i] = w.Propose(Meta{}, []Entry{set("log_level", `"info"`, v)})
				}()
			}
			wg.Wait()
			won := 0
			for _, err := range errs {
				if err == nil {
					won++
				} else if !errors.Is(err, ErrConflict) {
					t.Fatalf("round %d: %v", round, err)
				}
			}
			if won != 1 {
				t.Fatalf("round %d: %d winners", round, won)
			}
			if tree, _, _, _ := d.Load(); tree.(map[string]any)["log_level"] == "info" {
				t.Fatalf("round %d: the winner was not applied", round)
			}
		})
	}
}
