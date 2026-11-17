// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseRelease(t *testing.T) {
	good := `{"tag_name":"v0.9.9.1","html_url":"` + updateURLPrefix + `tag/v0.9.9.1","draft":false,"prerelease":false}`
	tests := []struct {
		name, body, wantLatest, wantLink string
		wantErr                          bool
	}{
		{"good", good, "0.9.9.1", updateURLPrefix + "tag/v0.9.9.1", false},
		{"foreign link is dropped", `{"tag_name":"v1.0.0","html_url":"https://evil.example/x"}`, "1.0.0", "", false},
		{"look-alike prefix is dropped", `{"tag_name":"v1.0.0","html_url":"https://github.com/andy-d-70/dnshived-evil/releases/x"}`, "1.0.0", "", false},
		{"draft refused", `{"tag_name":"v1.0.0","draft":true}`, "", "", true},
		{"pre-release refused", `{"tag_name":"v1.0.0","prerelease":true}`, "", "", true},
		{"no tag", `{"tag_name":""}`, "", "", true},
		{"tag is not a version", `{"tag_name":"nightly"}`, "", "", true},
		{"not json", `<html>`, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			latest, link, err := parseRelease([]byte(tt.body))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if latest != tt.wantLatest || link != tt.wantLink {
				t.Errorf("got %q %q, want %q %q", latest, link, tt.wantLatest, tt.wantLink)
			}
		})
	}
}

func TestUpdateStatus(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name    string
		enabled bool
		setup   func(u *updateChecker)
		current string
		want    string
	}{
		{"off", false, func(u *updateChecker) {}, "0.9.9", "off"},
		{"pending", true, func(u *updateChecker) {}, "0.9.9", "pending"},
		{"fail", true, func(u *updateChecker) { u.triedAt = now }, "0.9.9", "fail"},
		{"current", true, func(u *updateChecker) { u.ok, u.latest = true, "0.9.9" }, "0.9.9", "current"},
		{"new", true, func(u *updateChecker) { u.ok, u.latest = true, "0.9.10" }, "0.9.9", "new"},
		{"dev build of the same number is older", true, func(u *updateChecker) { u.ok, u.latest = true, "0.9.9" }, "0.9.9~dev-3", "new"},
		{"newer than the release is current", true, func(u *updateChecker) { u.ok, u.latest = true, "0.9.8" }, "0.9.9", "current"},
		{"build metadata ignored", true, func(u *updateChecker) { u.ok, u.latest = true, "0.9.9" }, "0.9.9+abc1234", "current"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := newUpdateChecker()
			tt.setup(u)
			if got := u.status(tt.enabled, tt.current).State; got != tt.want {
				t.Errorf("state = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUpdateDue(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name  string
		setup func(u *updateChecker)
		want  bool
	}{
		{"never tried", func(u *updateChecker) {}, true},
		{"failed a minute ago", func(u *updateChecker) { u.triedAt = now.Add(-time.Minute) }, false},
		{"failed over an hour ago", func(u *updateChecker) { u.triedAt = now.Add(-2 * time.Hour) }, true},
		{"fresh success", func(u *updateChecker) { u.ok, u.checkedAt, u.triedAt = true, now.Add(-time.Hour), now.Add(-time.Hour) }, false},
		{"day-old success", func(u *updateChecker) {
			u.ok, u.checkedAt, u.triedAt = true, now.Add(-25*time.Hour), now.Add(-25*time.Hour)
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := newUpdateChecker()
			tt.setup(u)
			if got := u.due(now); got != tt.want {
				t.Errorf("due = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUpdateFetch_RequestIsGenericAndAnswerBounded(t *testing.T) {
	var gotUA, gotAuth, gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA, gotAuth, gotCookie = r.Header.Get("User-Agent"), r.Header.Get("Authorization"), r.Header.Get("Cookie")
		_, _ = w.Write([]byte(`{"tag_name":"v2.0.0"}`))
	}))
	defer srv.Close()
	u := newUpdateChecker()
	u.apiURL = srv.URL
	latest, _, err := u.fetch(context.Background())
	if err != nil || latest != "2.0.0" {
		t.Fatalf("fetch = %q, %v", latest, err)
	}
	if gotUA != "dnshived-web-update-check" || gotAuth != "" || gotCookie != "" {
		t.Errorf("request must be generic: UA=%q auth=%q cookie=%q", gotUA, gotAuth, gotCookie)
	}

	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v2.0.0","pad":"` + strings.Repeat("x", 2*updateBodyMax) + `"}`))
	}))
	defer big.Close()
	u.apiURL = big.URL
	if _, _, err := u.fetch(context.Background()); err == nil {
		t.Error("an answer over the cap must not parse")
	}

	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/", http.StatusMovedPermanently)
	}))
	defer redir.Close()
	u.apiURL = redir.URL
	if _, _, err := u.fetch(context.Background()); err == nil {
		t.Error("a redirect must be an error, never followed")
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 403) }))
	defer bad.Close()
	u.apiURL = bad.URL
	if _, _, err := u.fetch(context.Background()); err == nil {
		t.Error("HTTP 403 must be an error")
	}
}

func TestUpdateCheckToggle_PersistsAndAnswers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "web.json")
	ref := &configRef{}
	ref.Store(&WebConfig{ListenAddr: ":0"})
	h := handleUpdateCheckToggle(path, ref)

	post := func(v string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/update-check", strings.NewReader(url.Values{"enabled": {v}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}
	if rec := post("1"); rec.Code != 200 || !ref.Load().UpdateCheck {
		t.Fatalf("turn on: code %d, enabled %v", rec.Code, ref.Load().UpdateCheck)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), `"update_check": true`) {
		t.Errorf("web.json must hold the switch: %s %v", data, err)
	}
	if rec := post("0"); rec.Code != 200 || ref.Load().UpdateCheck {
		t.Fatalf("turn off: code %d, enabled %v", rec.Code, ref.Load().UpdateCheck)
	}
	if data, _ := os.ReadFile(path); strings.Contains(string(data), "update_check") {
		t.Errorf("off is the absent key, got %s", data)
	}
	if rec := post("yes"); ref.Load().UpdateCheck || rec.Code != 200 {
		t.Error("anything but 1 means off")
	}
}
