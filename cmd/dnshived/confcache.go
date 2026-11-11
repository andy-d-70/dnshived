// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	"dnshived/internal/config"
)

// configCacheMaxAge bounds how long an encoded answer is reused even when the
// file's identity has not changed.
const configCacheMaxAge = 30 * time.Second

// fileStamp identifies one version of a file. A commit replaces the file by a
// rename, which changes the inode; size, mtime and ctime cover a write in place.
type fileStamp struct {
	dev, ino     uint64
	size         int64
	mtime, ctime int64
}

func statStamp(path string) (fileStamp, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileStamp{}, fmt.Errorf("no stat data for %s", path)
	}
	return fileStamp{dev: uint64(st.Dev), ino: uint64(st.Ino), size: st.Size, mtime: st.Mtim.Nano(), ctime: st.Ctim.Nano()}, nil
}

// responseCache keeps the encoded answer built from one file. get returns it
// while the file is unchanged and the entry is younger than maxAge; otherwise it
// runs build and keeps the result under the stamp taken BEFORE build, so a file
// replaced during the build is noticed by the next call. Callers are serialised,
// so a burst of readers builds once.
type responseCache struct {
	mu    sync.Mutex
	stamp fileStamp
	at    time.Time
	body  []byte
	valid bool
}

func (c *responseCache) get(path string, maxAge time.Duration, now time.Time, build func() ([]byte, error)) ([]byte, error) {
	stamp, serr := statStamp(path)
	c.mu.Lock()
	defer c.mu.Unlock()
	if serr == nil && c.valid && c.stamp == stamp && now.Sub(c.at) < maxAge {
		return c.body, nil
	}
	body, err := build()
	if err != nil || serr != nil {
		c.valid = false
		return body, err
	}
	c.stamp, c.at, c.body, c.valid = stamp, now, body, true
	return body, nil
}

func (s fileStamp) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", s.dev, s.ino, s.size, s.mtime, s.ctime)
}

// configStampHandler answers GET /api/v1/config/stamp: one short token per
// document that changes whenever the configuration or the staged candidate
// is replaced or written, and is empty when the file does not exist. A client
// that already holds the documents asks this instead of fetching them again.
func configStampHandler(cfgPath, dir func() string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := map[string]string{"config_stamp": "", "candidate_stamp": ""}
		if s, err := statStamp(cfgPath()); err == nil {
			out["config_stamp"] = s.String()
		}
		if s, err := statStamp(candidatePath(dir())); err == nil {
			out["candidate_stamp"] = s.String()
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func encodeJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// configGetHandler answers GET /api/v1/config with the file's content as the
// current configuration, parsed and encoded once per version of the file.
func configGetHandler(cfgPath func() string, cache *responseCache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := cfgPath()
		body, err := cache.get(path, configCacheMaxAge, time.Now(), func() ([]byte, error) {
			current, err := config.Load(path)
			if err != nil {
				return nil, err
			}
			return encodeJSON(current)
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "load current config: " + err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}
}

// candidateGetHandler answers GET /api/v1/candidate the same way for the staged
// candidate; without a candidate file the answer is built each time, which is
// one failed open.
func candidateGetHandler(dir func() string, cache *responseCache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d := dir()
		body, err := cache.get(candidatePath(d), configCacheMaxAge, time.Now(), func() ([]byte, error) {
			cand, exists, err := loadCandidateConfig(d)
			if err != nil {
				return nil, err
			}
			return encodeJSON(map[string]interface{}{"exists": exists, "candidate": cand})
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "load candidate: " + err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}
}
