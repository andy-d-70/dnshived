// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dnshived/internal/webauth"
)

func TestHandlePendingSummary_ReflectsCachedValue(t *testing.T) {
	h := handlePendingSummary()

	pendingHasChanges.Store(false)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/pending-summary", nil))
	if !strings.Contains(rec.Body.String(), `"hasChanges":false`) {
		t.Errorf("expected hasChanges:false, got %s", rec.Body.String())
	}

	pendingHasChanges.Store(true)
	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/pending-summary", nil))
	if !strings.Contains(rec.Body.String(), `"hasChanges":true`) {
		t.Errorf("expected hasChanges:true, got %s", rec.Body.String())
	}
	pendingHasChanges.Store(false) // leave clean for other tests
}

func newTestChecker(keys *[]string, oks *[]bool, fulls *int, answer *bool, clock *time.Time) *pendingChecker {
	i := 0
	return &pendingChecker{
		stamps: func([]NodeConfig) (string, bool) {
			k, ok := (*keys)[min(i, len(*keys)-1)], (*oks)[min(i, len(*oks)-1)]
			i++
			return k, ok
		},
		full: func([]NodeConfig) (bool, error) { *fulls++; return *answer, nil },
		now:  func() time.Time { return *clock },
	}
}

func TestPendingChecker_FetchesDocumentsOnlyWhenAStampChanged(t *testing.T) {
	keys := []string{"a", "a", "a", "b", "b"}
	oks := []bool{true}
	fulls, answer := 0, false
	clock := time.Unix(1000, 0)
	p := newTestChecker(&keys, &oks, &fulls, &answer, &clock)

	if got, re := p.refresh(nil); got || !re || fulls != 1 {
		t.Fatalf("first call computes: %v %v %d", got, re, fulls)
	}
	for i := 0; i < 2; i++ {
		if _, re := p.refresh(nil); re {
			t.Fatalf("an unchanged stamp must not fetch the documents (call %d)", i)
		}
	}
	answer = true
	if got, re := p.refresh(nil); !got || !re || fulls != 2 {
		t.Fatalf("a changed stamp recomputes: %v %v %d", got, re, fulls)
	}
	if got, re := p.refresh(nil); !got || re {
		t.Errorf("unchanged again: the cached answer is returned without work, got %v %v", got, re)
	}
	clock = clock.Add(pendingFullEvery + time.Second)
	if _, re := p.refresh(nil); !re || fulls != 3 {
		t.Errorf("after %v the documents are fetched anyway as a safety net, fulls = %d", pendingFullEvery, fulls)
	}
}

func TestPendingChecker_WithoutStampsItBehavesAsBefore(t *testing.T) {
	keys, oks := []string{""}, []bool{false}
	fulls, answer := 0, false
	clock := time.Unix(1000, 0)
	p := newTestChecker(&keys, &oks, &fulls, &answer, &clock)
	for i := 0; i < 4; i++ {
		p.refresh(nil)
	}
	if fulls != 4 {
		t.Errorf("a node without a stamp endpoint (older daemon) means a full check every time, got %d", fulls)
	}
}

func TestPendingChecker_AFailedFetchKeepsTheLastAnswerAndRetries(t *testing.T) {
	calls := 0
	p := &pendingChecker{
		stamps: func([]NodeConfig) (string, bool) { return "k", true },
		full: func([]NodeConfig) (bool, error) {
			calls++
			if calls == 1 {
				return true, nil
			}
			if calls == 2 {
				return false, errors.New("no node reachable")
			}
			return false, nil
		},
		now: func() time.Time { return time.Unix(1, 0) },
	}
	p.refresh(nil) // answer true
	p.key = "different"
	if got, re := p.refresh(nil); !got || re {
		t.Errorf("a failed fetch keeps the last answer and reports no change: %v %v", got, re)
	}
	if got, re := p.refresh(nil); got || !re {
		t.Errorf("the next call retries (state was not marked as fetched): %v %v", got, re)
	}
}

func TestPendingRunDue(t *testing.T) {
	for _, tt := range []struct {
		active bool
		since  time.Duration
		want   bool
	}{
		{true, time.Second, true},
		{true, 0, true},
		{false, time.Second, false},
		{false, pendingIdleEvery - time.Second, false},
		{false, pendingIdleEvery, true},
	} {
		if got := pendingRunDue(tt.active, tt.since); got != tt.want {
			t.Errorf("pendingRunDue(%v, %v) = %v, want %v", tt.active, tt.since, got, tt.want)
		}
	}
}

func TestFetchStampKey(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/config/stamp" {
			t.Errorf("path %q", r.URL.Path)
		}
		fmt.Fprint(w, `{"config_stamp":"c1","candidate_stamp":""}`)
	}))
	defer good.Close()
	old := httptest.NewServer(http.NotFoundHandler())
	defer old.Close()
	addr := func(s *httptest.Server) string { return strings.TrimPrefix(s.URL, "http://") }

	key, ok := fetchStampKey([]NodeConfig{{Name: "a", Addr: addr(good)}})
	if !ok || !strings.Contains(key, "=c1,") {
		t.Errorf("key = %q ok = %v", key, ok)
	}
	if _, ok := fetchStampKey([]NodeConfig{{Name: "a", Addr: addr(good)}, {Name: "b", Addr: addr(old)}}); ok {
		t.Error("a node that answers 404 (older daemon) means no stamps: full check")
	}
	down := httptest.NewServer(http.NotFoundHandler())
	downAddr := addr(down)
	down.Close()
	key2, ok := fetchStampKey([]NodeConfig{{Name: "a", Addr: addr(good)}, {Name: "b", Addr: downAddr}})
	if !ok || !strings.Contains(key2, downAddr+"=down;") || key2 == key {
		t.Errorf("a node that is down changes the key and still allows stamps: %q %v", key2, ok)
	}
}

func TestPermitted_ActivityOnlyForRealRequests(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	user := webauth.User{Name: "viewer", Role: "admin"}
	run := func(activity bool) int {
		lastUIActivity.Store(0)
		req := withAuthedUser(httptest.NewRequest(http.MethodGet, "/api/pending-summary", nil), user)
		w := httptest.NewRecorder()
		permitted(webauth.PermViewStatus, activity, ok)(w, req)
		if w.Code != http.StatusNoContent {
			t.Fatalf("status %d", w.Code)
		}
		if lastUIActivity.Load() != 0 {
			return 1
		}
		return 0
	}
	if run(true) != 1 {
		t.Error("a normal request marks the UI as in use")
	}
	if run(false) != 0 {
		t.Error("the poll must not mark the UI as in use")
	}
	req := withAuthedUser(httptest.NewRequest(http.MethodGet, "/x", nil), webauth.User{Name: "nobody", Role: "none"})
	w := httptest.NewRecorder()
	permitted(webauth.PermViewStatus, false, ok)(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("a user without the permission is refused even on the quiet path, got %d", w.Code)
	}
}

func TestNavPollPausesInHiddenTabs(t *testing.T) {
	for _, want := range []string{"function pollPendingMarker(){\n  if(document.hidden) return;", "document.addEventListener('visibilitychange'"} {
		if !strings.Contains(navHTML, want) {
			t.Errorf("nav script lacks %q", want)
		}
	}
}

// BenchmarkPendingTick compares one tick of the pending summary before (fetch
// the configuration and ask each node for a candidate) and after (ask each
// node for its two stamps) against three fake nodes serving a 102-scope
// configuration.
func BenchmarkPendingTick(b *testing.B) {
	var doc strings.Builder
	doc.WriteString(`{"cluster_id":"c1","node_id":"n1","role":"core-1","control_addr":"192.0.2.1:9443","psk":"0123456789abcdef0123456789abcdef","platform":{"mgmt":"eth0","workers":["eth1"]},"scopes":{`)
	for i := 0; i < 102; i++ {
		if i > 0 {
			doc.WriteString(",")
		}
		fmt.Fprintf(&doc, `"dante-%03d":{"parent":"eth1","vlan_id":%d,"vrrp_id":%d,"preferred_worker":"core-%d","vip":"10.%d.%d.1/24","dhcp_range":["10.%d.%d.50","10.%d.%d.200"],"gateway":"10.%d.%d.1","upstream":["1.1.1.1","9.9.9.9"],"reservations":[{"mac":"aa:bb:cc:00:%02x:01","ip":"10.%d.%d.10","hostname":"printer-%d"},{"mac":"aa:bb:cc:00:%02x:02","ip":"10.%d.%d.11","hostname":"camera-%d"}]}`,
			i, 100+i, 1+i, 1+i%3, 100+i/250, i%250, 100+i/250, i%250, 100+i/250, i%250, 100+i/250, i%250, i, 100+i/250, i%250, i, i, 100+i/250, i%250, i)
	}
	doc.WriteString("}}")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/config", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, doc.String()) })
	mux.HandleFunc("/api/v1/candidate", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"candidate":null,"exists":false}`) })
	mux.HandleFunc("/api/v1/config/stamp", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"config_stamp":"1-2-3-4-5","candidate_stamp":""}`)
	})
	var nodes []NodeConfig
	for i := 0; i < 3; i++ {
		srv := httptest.NewServer(mux)
		defer srv.Close()
		nodes = append(nodes, NodeConfig{Name: fmt.Sprintf("core-%d", i+1), Addr: strings.TrimPrefix(srv.URL, "http://")})
	}
	b.Run("fetch and compare every tick (before)", func(b *testing.B) {
		for b.Loop() {
			if _, err := fetchPendingFull(nodes); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("stamps only (after)", func(b *testing.B) {
		p := &pendingChecker{stamps: fetchStampKey, full: fetchPendingFull, now: time.Now}
		p.refresh(nodes)
		for b.Loop() {
			if _, re := p.refresh(nodes); re {
				b.Fatal("recomputed")
			}
		}
	})
}

func TestHandlePendingSummary_CarriesAValidUserField(t *testing.T) {
	rec := httptest.NewRecorder()
	handlePendingSummary()(rec, httptest.NewRequest(http.MethodGet, "/api/pending-summary", nil))
	var got struct {
		HasChanges bool   `json:"hasChanges"`
		User       string `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("the summary must stay valid JSON: %v (%s)", err, rec.Body.String())
	}
}
