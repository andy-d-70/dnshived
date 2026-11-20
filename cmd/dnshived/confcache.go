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
	path = config.StampPath(path)
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
			resp := map[string]interface{}{"exists": exists, "candidate": cand}
			if exists {
				resp["authors"] = loadCandidateAuthors(d)
			}
			return encodeJSON(resp)
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

// parsedConfig keeps the configuration at one path, parsed once per version
// of its files, for handlers that only read it.
var parsedConfig struct {
	mu    sync.Mutex
	path  string
	stamp fileStamp
	cfg   *config.Cluster
}

// loadConfigShared returns the configuration at path like config.Load, without
// reading and parsing it again while the file (or the manifest of the split
// directory) is unchanged. The result is shared: callers must not modify it.
func loadConfigShared(path string) (*config.Cluster, error) {
	stamp, serr := statStamp(path)
	parsedConfig.mu.Lock()
	defer parsedConfig.mu.Unlock()
	if serr == nil && parsedConfig.cfg != nil && parsedConfig.path == path && parsedConfig.stamp == stamp {
		return parsedConfig.cfg, nil
	}
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if serr == nil {
		parsedConfig.path, parsedConfig.stamp, parsedConfig.cfg = path, stamp, c
	}
	return c, nil
}

// hashCache keeps the hashes the status answer reports for one configuration
// object. currentConfig is replaced as a whole and never modified in place, so
// the pointer identifies a version; hashing the whole document on every status
// call (the web UI and every peer ask every few seconds) grows with its size.
var hashCache struct {
	mu                   sync.Mutex
	cfg                  *config.Cluster
	scopes, hash1, hash2 string
}

func statusHashes(c *config.Cluster) (scopes, v1, v2 string) {
	hashCache.mu.Lock()
	defer hashCache.mu.Unlock()
	if hashCache.cfg == c && c != nil {
		return hashCache.scopes, hashCache.hash1, hashCache.hash2
	}
	scopes = c.ScopesHash()
	v1, v2 = c.ConfigDocumentHashes()
	hashCache.cfg, hashCache.scopes, hashCache.hash1, hashCache.hash2 = c, scopes, v1, v2
	return scopes, v1, v2
}
