// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package auditlog

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const importMarker = "IMPORTED.json"

// ImportFiles copies the lines of this node's audit files into the store. A line with an "id" keeps it; an older
// line gets an id derived from its bytes, so importing the same line again is a no-op. A file already imported at
// its current size and first line is skipped. The files are only read. It returns how many entries were new and
// how many lines could not be stored (too long), which stay in their file.
func ImportFiles(l *Logger, s *Store, dir string) (added, skipped int, err error) {
	l.mu.Lock()
	files, err := l.Files()
	l.mu.Unlock()
	if err != nil {
		return 0, 0, err
	}
	markerPath := filepath.Join(dir, importMarker)
	done := map[string]bool{}
	if raw, err := os.ReadFile(markerPath); err == nil {
		_ = json.Unmarshal(raw, &done)
	} else if !os.IsNotExist(err) {
		return 0, 0, fmt.Errorf("auditlog: read %s: %w", markerPath, err)
	}
	changed := false
	for _, p := range files {
		key, n, s2, err := importFile(p, s, done)
		added, skipped = added+n, skipped+s2
		if err != nil {
			return added, skipped, err
		}
		if key != "" {
			done[key], changed = true, true
		}
	}
	if !changed {
		return added, skipped, nil
	}
	raw, err := json.Marshal(done)
	if err != nil {
		return added, skipped, err
	}
	return added, skipped, writeFileAtomic(markerPath, raw)
}

func importFile(path string, s *Store, done map[string]bool) (key string, added, skipped int, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", 0, 0, nil
		}
		return "", 0, 0, fmt.Errorf("auditlog: read %s: %w", path, err)
	}
	first, _, _ := bytes.Cut(data, []byte{'\n'})
	sum := sha256.Sum256(first)
	key = fmt.Sprintf("%d:%x", len(data), sum[:8])
	if done[key] {
		return "", 0, 0, nil
	}
	var batch []StoredEntry
	flush := func() error {
		n, err := s.Append(batch)
		added += n
		batch = batch[:0]
		return err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), len(data)+1)
	for sc.Scan() {
		line := bytes.TrimRight(sc.Bytes(), "\r")
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if len(line) > MaxBody {
			skipped++
			continue
		}
		batch = append(batch, StoredEntry{ID: lineID(line), Body: append([]byte(nil), line...)})
		if len(batch) == 1000 {
			if err := flush(); err != nil {
				return "", added, skipped, err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return "", added, skipped, fmt.Errorf("auditlog: scan %s: %w", path, err)
	}
	if err := flush(); err != nil {
		return "", added, skipped, err
	}
	return key, added, skipped, nil
}

func lineID(line []byte) ID {
	var probe struct {
		ID string `json:"id"`
	}
	var id ID
	if json.Unmarshal(line, &probe) == nil && len(probe.ID) == 32 {
		if b, err := hex.DecodeString(probe.ID); err == nil {
			copy(id[:], b)
			return id
		}
	}
	h := sha256.New()
	h.Write([]byte("dnshived-audit-import-v1\n"))
	h.Write(line)
	copy(id[:], h.Sum(nil))
	return id
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}
