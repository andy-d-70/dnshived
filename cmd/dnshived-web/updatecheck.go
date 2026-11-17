// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"dnshived/internal/activation"
)

const (
	updateRepo      = "andy-d-70/dnshived"
	updateAPIURL    = "https://api.github.com/repos/" + updateRepo + "/releases/latest"
	updateEvery     = 24 * time.Hour
	updateRetry     = time.Hour
	updateBodyMax   = 1 << 20
	updateURLPrefix = "https://github.com/" + updateRepo + "/releases/"
)

// updateInfo is what the footer shows about newer releases. State is one of
// off, pending, current, new and fail.
type updateInfo struct {
	State   string `json:"state"`
	Latest  string `json:"latest,omitempty"`
	URL     string `json:"url,omitempty"`
	Checked string `json:"checked,omitempty"`
}

// updateChecker asks GitHub once a day for the newest release and compares it
// with the running version. It only reads; it never downloads or installs.
type updateChecker struct {
	mu        sync.Mutex
	apiURL    string
	client    *http.Client
	latest    string
	url       string
	ok        bool
	checkedAt time.Time
	triedAt   time.Time
	kick      chan struct{}
}

func newUpdateChecker() *updateChecker {
	return &updateChecker{
		apiURL: updateAPIURL,
		client: &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		kick: make(chan struct{}, 1),
	}
}

// parseRelease reads GitHub's latest-release answer. It returns the version
// without a leading "v" and a release-notes link that is kept only when it
// points into this project's own releases.
func parseRelease(body []byte) (latest, link string, err error) {
	var rel struct {
		Tag        string `json:"tag_name"`
		HTMLURL    string `json:"html_url"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", "", fmt.Errorf("decode release: %w", err)
	}
	if rel.Draft || rel.Prerelease {
		return "", "", fmt.Errorf("latest release is a draft or pre-release")
	}
	latest = strings.TrimPrefix(strings.TrimSpace(rel.Tag), "v")
	if len(latest) == 0 || len(latest) > 64 {
		return "", "", fmt.Errorf("release has no usable tag")
	}
	if _, ok := activation.Compare(latest, latest); !ok {
		return "", "", fmt.Errorf("release tag %q is not a version", latest)
	}
	if strings.HasPrefix(rel.HTMLURL, updateURLPrefix) && len(rel.HTMLURL) <= 256 {
		link = rel.HTMLURL
	}
	return latest, link, nil
}

func (u *updateChecker) fetch(ctx context.Context) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.apiURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "dnshived-web-update-check")
	resp, err := u.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("update check: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("update check: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, updateBodyMax))
	if err != nil {
		return "", "", fmt.Errorf("update check: read: %w", err)
	}
	return parseRelease(body)
}

// due reports whether a check should run now.
func (u *updateChecker) due(now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if now.Sub(u.triedAt) < updateRetry {
		return false
	}
	return !u.ok || now.Sub(u.checkedAt) >= updateEvery
}

func (u *updateChecker) check(ctx context.Context, now time.Time) {
	u.mu.Lock()
	u.triedAt = now
	u.mu.Unlock()
	latest, link, err := u.fetch(ctx)
	u.mu.Lock()
	defer u.mu.Unlock()
	if err != nil {
		log.Printf("[UPDATE] %v", err)
		return
	}
	u.latest, u.url, u.ok, u.checkedAt = latest, link, true, now
}

// run checks once a day while the setting is on. It wakes every minute, which
// costs nothing while the check is off.
func (u *updateChecker) run(ref *configRef) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
		case <-u.kick:
		}
		if !ref.Load().UpdateCheck {
			continue
		}
		if now := time.Now(); u.due(now) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			u.check(ctx, now)
			cancel()
		}
	}
}

// poke asks run to look at the setting again right away.
func (u *updateChecker) poke() {
	select {
	case u.kick <- struct{}{}:
	default:
	}
}

// status is the footer's view of the checker for the running version.
func (u *updateChecker) status(enabled bool, current string) updateInfo {
	if !enabled {
		return updateInfo{State: "off"}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.ok {
		if u.triedAt.IsZero() {
			return updateInfo{State: "pending"}
		}
		return updateInfo{State: "fail"}
	}
	info := updateInfo{State: "current", Latest: u.latest, URL: u.url, Checked: u.checkedAt.UTC().Format(time.RFC3339)}
	if cmp, ok := activation.Compare(u.latest, current); ok && cmp > 0 {
		info.State = "new"
	}
	return info
}

var updates = newUpdateChecker()

// handleUpdateCheckToggle switches the daily check on or off. The setting lives
// in web.json; without it there is no outbound request at all.
func handleUpdateCheckToggle(cfgPath string, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		on := r.PostForm.Get("enabled") == "1"
		next := *ref.Load()
		next.UpdateCheck = on
		if err := saveWebConfig(cfgPath, &next); err != nil {
			http.Error(w, "save web config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		ref.Store(&next)
		footerInvalidate()
		if on {
			updates.poke()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}
}
