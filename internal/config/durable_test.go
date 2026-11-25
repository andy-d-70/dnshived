// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var errCrash = errors.New("simulated crash")

func splitPair(t *testing.T) (a, b *Cluster) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cluster.json")
	c := splitFixture()
	if err := saveSingle(path, c); err != nil {
		t.Fatal(err)
	}
	a, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = Load(path)
	b.LogLevel = "debug"
	b.LocalDomains = append(b.LocalDomains, LocalDomain{Name: "new.lan", Records: []LocalDomainHost{{Host: "x", Type: "A", Value: "10.9.9.9"}}})
	for name := range b.Scopes {
		delete(b.Scopes, name)
		break
	}
	return a, b
}

func canon(t *testing.T, c *Cluster) []byte {
	t.Helper()
	b, err := canonical(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func countSteps(t *testing.T, a, b *Cluster) int {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cluster.json.d")
	if err := SaveSplit(dir, a); err != nil {
		t.Fatal(err)
	}
	n := 0
	splitStep = func(string) error { n++; return nil }
	defer func() { splitStep = nil }()
	if err := SaveSplit(dir, b); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSaveSplit_CrashAtEveryStepLoadsTheOldOrTheNewConfiguration(t *testing.T) {
	a, b := splitPair(t)
	wantA, wantB := canon(t, a), canon(t, b)
	steps := countSteps(t, a, b)
	if steps < 4 {
		t.Fatalf("only %d steps", steps)
	}
	for crash := 1; crash <= steps; crash++ {
		t.Run(fmt.Sprint(crash), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "cluster.json.d")
			if err := SaveSplit(dir, a); err != nil {
				t.Fatal(err)
			}
			n := 0
			splitStep = func(string) error {
				n++
				if n == crash {
					return errCrash
				}
				return nil
			}
			err := SaveSplit(dir, b)
			splitStep = nil
			if !errors.Is(err, errCrash) {
				t.Fatalf("save: %v", err)
			}
			got, err := LoadSplit(dir)
			if err != nil {
				t.Fatalf("load after the crash: %v", err)
			}
			g := canon(t, got)
			if !bytes.Equal(g, wantA) && !bytes.Equal(g, wantB) {
				t.Fatal("the configuration after the crash is neither the old nor the new one")
			}
			if _, err := os.Stat(filepath.Join(dir, intentFileName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("loading must finish the interrupted save")
			}
			if err := SaveSplit(dir, b); err != nil {
				t.Fatal(err)
			}
			if got, err := LoadSplit(dir); err != nil || !bytes.Equal(canon(t, got), wantB) {
				t.Fatalf("the next save: %v", err)
			}
		})
	}
}

func TestLoadSplit_IgnoresNewPartsWithoutAnIntent(t *testing.T) {
	a, _ := splitPair(t)
	dir := filepath.Join(t.TempDir(), "cluster.json.d")
	if err := SaveSplit(dir, a); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(dir, "base.json"+newSuffix)
	if err := os.WriteFile(stray, []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSplit(dir)
	if err != nil || !bytes.Equal(canon(t, got), canon(t, a)) {
		t.Fatalf("load: %v", err)
	}
	if err := SaveSplit(dir, a); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stray); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a part written before the intent belongs to no save and is removed by the next save")
	}
}

func TestLoadSplit_ReadsThroughTheIntentWhileAnotherProcessHoldsTheLock(t *testing.T) {
	a, b := splitPair(t)
	dir := filepath.Join(t.TempDir(), "cluster.json.d")
	if err := SaveSplit(dir, a); err != nil {
		t.Fatal(err)
	}
	splitStep = func(s string) error {
		if s == "intent" {
			return errCrash
		}
		return nil
	}
	err := SaveSplit(dir, b)
	splitStep = nil
	if !errors.Is(err, errCrash) {
		t.Fatal(err)
	}
	l, err := lockDir(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadSplit(dir)
	l.release()
	if err != nil || !bytes.Equal(canon(t, got), canon(t, b)) {
		t.Fatalf("a reader sees the saved state through the intent: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, intentFileName)); err != nil {
		t.Fatal("a reader that cannot take the lock leaves the intent for the writer")
	}
}

func TestReadIntent_RefusesPathsOutsideTheDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, intentFileName), []byte(`{"manifest":{},"parts":["../../etc/passwd"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readIntent(dir); err == nil {
		t.Fatal("an intent pointing outside the directory must be refused")
	}
}
