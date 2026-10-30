// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/probepin"
)

func TestBaseURL_PinnedProbeUsesHTTPSOnTLSPort(t *testing.T) {
	plain := NodeConfig{Addr: "192.0.2.43:9444"}
	if got := plain.baseURL(); got != "http://192.0.2.43:9444" {
		t.Fatalf("unpinned baseURL = %q", got)
	}
	pinned := NodeConfig{Addr: "192.0.2.43:9444", TLSPort: "9445", TLSFingerprint: "sha256:" + strings.Repeat("ab", 32)}
	if got := pinned.baseURL(); got != "https://192.0.2.43:9445" {
		t.Fatalf("pinned baseURL = %q", got)
	}
}

func TestPinRouter_PinnedAddressUsesOnlyItsCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	_, port, _ := net.SplitHostPort(u.Host)

	right := NodeConfig{Addr: "127.0.0.1:9444", TLSPort: port, TLSFingerprint: probepin.Fingerprint(srv.Certificate().Raw)}
	wrong := right
	wrong.TLSFingerprint = "sha256:" + strings.Repeat("00", 32)

	router := &probepin.Router{Next: http.DefaultTransport}
	router.SetPins(probePinsOf([]NodeConfig{right}))
	client := &http.Client{Transport: router}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("pinned GET: %v", err)
	}
	resp.Body.Close()

	router.SetPins(probePinsOf([]NodeConfig{wrong}))
	if resp, err := client.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("GET with a wrong pin succeeded")
	}
}

func TestHandleProbePin_RejectsBeforeAnyNetworkCall(t *testing.T) {
	ref := newConfigRef(&WebConfig{ProbeHosts: []NodeConfig{{Name: "probe", Addr: "192.0.2.43:9444"}}})
	h := handleProbePin("/nonexistent/web.json", ref)

	cases := []struct {
		name string
		addr string
		fp   string
		want int
	}{
		{name: "unknown address", addr: "192.0.2.99:9444", fp: "sha256:" + strings.Repeat("ab", 32), want: http.StatusNotFound},
		{name: "malformed fingerprint", addr: "192.0.2.43:9444", fp: "sha1:abc", want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{"addr": {tc.addr}, "tls_fingerprint": {tc.fp}}
			req := httptest.NewRequest(http.MethodPost, "/probes/pin", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestHandleProbeUnpin_ClearsPinAndSaves(t *testing.T) {
	fp := "sha256:" + strings.Repeat("ab", 32)
	path := filepath.Join(t.TempDir(), "web.json")
	ref := newConfigRef(&WebConfig{ProbeHosts: []NodeConfig{{Name: "probe", Addr: "192.0.2.43:9444", TLSPort: "9445", TLSFingerprint: fp}}})
	h := handleProbeUnpin(path, ref)

	form := url.Values{"addr": {"192.0.2.43:9444"}}
	req := httptest.NewRequest(http.MethodPost, "/probes/unpin", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want 303: %s", rec.Code, rec.Body.String())
	}
	got := ref.Load().ProbeHosts[0]
	if got.TLSFingerprint != "" || got.TLSPort != "" {
		t.Fatalf("pin still set after unpin: %+v", got)
	}
	if probePinsOf(ref.Load().ProbeHosts) == nil || len(probePinsOf(ref.Load().ProbeHosts)) != 0 {
		t.Fatal("pins still published after unpin")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("web config not saved: %v", err)
	}
}
