// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package probepin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	good := "sha256:" + strings.Repeat("ab", 32)
	if !Valid(good) {
		t.Fatalf("Valid(%q) = false", good)
	}
	for _, bad := range []string{"", "sha256:", "sha1:" + strings.Repeat("ab", 20), "sha256:" + strings.Repeat("AB", 32), "sha256:" + strings.Repeat("ab", 31)} {
		if Valid(bad) {
			t.Errorf("Valid(%q) = true, want false", bad)
		}
	}
}

func TestConfigAcceptsOnlyPinnedCertificate(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.StartTLS()
	defer srv.Close()

	pin := Fingerprint(srv.Certificate().Raw)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: Config(pin)}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("pinned GET: %v", err)
	}
	resp.Body.Close()

	wrong := "sha256:" + strings.Repeat("00", 32)
	client = &http.Client{Transport: &http.Transport{TLSClientConfig: Config(wrong)}}
	if resp, err := client.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("GET with a wrong pin succeeded")
	}
}

func TestParsePin(t *testing.T) {
	fp := "sha256:" + strings.Repeat("cd", 32)
	addr, got, err := ParsePin("192.0.2.43:9445=" + fp)
	if err != nil || addr != "192.0.2.43:9445" || got != fp {
		t.Fatalf("ParsePin = (%q, %q, %v)", addr, got, err)
	}
	for _, bad := range []string{"192.0.2.43:9445", "=" + fp, "192.0.2.43:9445=sha256:xyz"} {
		if _, _, err := ParsePin(bad); err == nil {
			t.Errorf("ParsePin(%q) accepted", bad)
		}
	}
}
