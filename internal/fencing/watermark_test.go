// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package fencing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewWatermark_MissingFileStartsAtZero(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWatermark(dir)
	if err != nil {
		t.Fatalf("unexpected error on first-ever start: %v", err)
	}
	if got := w.Current(); got != (Token{}) {
		t.Fatalf("expected zero token on missing file, got %s", got)
	}
}

func TestNewWatermark_EmptyDirDisablesPersistence(t *testing.T) {
	w, err := NewWatermark("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w.path != "" {
		t.Fatalf("expected persistence disabled, got path %q", w.path)
	}
	w.Advance(Token{Epoch: 5, Generation: 1})
	if got := w.Current(); got != (Token{Epoch: 5, Generation: 1}) {
		t.Fatalf("in-memory advance failed: got %s", got)
	}
}

func TestNewWatermark_CorruptFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fencing"), []byte("not json"), 0o640); err != nil {
		t.Fatal(err)
	}
	_, err := NewWatermark(dir)
	if err == nil {
		t.Fatal("expected an error on a corrupt watermark file, got nil — this would silently reset fencing memory to (0,0)")
	}
}

func TestNewWatermark_UnreadableFileFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — file permissions can't cause a read error")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fencing")
	if err := os.WriteFile(path, []byte(`{"epoch":3,"generation":2}`), 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0o640)
	_, err := NewWatermark(dir)
	if err == nil {
		t.Fatal("expected an error on an unreadable watermark file, got nil")
	}
}

func TestWatermark_AdvancePersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWatermark(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !w.Advance(Token{Epoch: 2, Generation: 7}) {
		t.Fatal("expected Advance to move the watermark forward")
	}

	reloaded, err := NewWatermark(dir)
	if err != nil {
		t.Fatalf("unexpected error reloading a valid watermark: %v", err)
	}
	if got := reloaded.Current(); got != (Token{Epoch: 2, Generation: 7}) {
		t.Fatalf("watermark did not survive restart: got %s", got)
	}
}

func TestWatermark_AdvanceNeverGoesBackward(t *testing.T) {
	w := &Watermark{current: Token{Epoch: 5, Generation: 3}}
	if w.Advance(Token{Epoch: 5, Generation: 1}) {
		t.Fatal("Advance must not move backward within the same epoch")
	}
	if w.Advance(Token{Epoch: 4, Generation: 99}) {
		t.Fatal("Advance must not move backward across a lower epoch, even with a higher generation")
	}
	if got := w.Current(); got != (Token{Epoch: 5, Generation: 3}) {
		t.Fatalf("watermark moved on a non-advancing candidate: got %s", got)
	}
}

func TestWatermark_Fenced(t *testing.T) {
	w := &Watermark{current: Token{Epoch: 5, Generation: 3}}
	if !w.Fenced(Token{Epoch: 5, Generation: 2}) {
		t.Fatal("a strictly-lower token must be fenced out")
	}
	if w.Fenced(Token{Epoch: 5, Generation: 3}) {
		t.Fatal("an equal token must not be fenced out")
	}
	if w.Fenced(Token{Epoch: 6, Generation: 0}) {
		t.Fatal("a higher token must not be fenced out")
	}
}
