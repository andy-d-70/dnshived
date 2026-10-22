// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestPostSaveURL(t *testing.T) {
	cfg := &WebConfig{ListenAddr: "0.0.0.0:8443", VIPHost: "192.0.2.230",
		Nodes: []NodeConfig{{Name: "core-2", Addr: "192.0.2.52:9443"}}}
	cases := []struct {
		name string
		vip  *config.MgmtVIPConfig
		want string
	}{
		{"unchanged VIP", &config.MgmtVIPConfig{VIP: "192.0.2.230/24", VRRPID: 61}, "/"},
		{"VIP moved", &config.MgmtVIPConfig{VIP: "192.0.2.231/24", VRRPID: 60}, "https://192.0.2.231:8443/"},
	}
	for _, c := range cases {
		if got := postSaveURL(cfg, c.vip); got != c.want {
			t.Errorf("%s: postSaveURL = %q, want %q", c.name, got, c.want)
		}
	}
	if got := postSaveURL(cfg, nil); !strings.HasPrefix(got, "https://") || !strings.HasSuffix(got, ":8443/") || strings.Contains(got, "192.0.2.230") {
		t.Errorf("VIP removed: postSaveURL = %q, want some node's own https://<addr>:8443/", got)
	}
}

func TestSaveWatchdogHTML_TargetsAndWaitsForDoneMarker(t *testing.T) {
	js := saveWatchdogHTML("https://192.0.2.231:8443/")
	for _, want := range []string{`"https://192.0.2.231:8443/"`, `getElementById("save-done")`, `credentials:"omit"`, `addEventListener("load"`} {
		if !strings.Contains(js, want) {
			t.Errorf("watchdog script lacks %s", want)
		}
	}
	if strings.Contains(saveWatchdogHTML(`"</script>`), `"</script>`) {
		t.Error("watchdog target is not escaped")
	}
}

func TestApplyVIPHostHandler(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web.json")
	ref := newConfigRef(&WebConfig{ListenAddr: "0.0.0.0:8443", VIPHost: "192.0.2.230", SelfAdminToken: "tok"})
	h := applyVIPHostHandler(path, ref)

	req := httptest.NewRequest(http.MethodPost, "/internal/web/vip-host", strings.NewReader(`{"vip_host":"192.0.2.231"}`))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized || ref.Load().VIPHost != "192.0.2.230" {
		t.Fatalf("without token: code %d, vip_host %q — must be refused and unchanged", rec.Code, ref.Load().VIPHost)
	}

	req = httptest.NewRequest(http.MethodPost, "/internal/web/vip-host", strings.NewReader(`{"vip_host":"not-an-ip"}`))
	req.Header.Set("Authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid host: code %d, want 400", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/internal/web/vip-host", strings.NewReader(`{"vip_host":"192.0.2.231"}`))
	req.Header.Set("Authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK || ref.Load().VIPHost != "192.0.2.231" {
		t.Fatalf("valid update: code %d, vip_host %q", rec.Code, ref.Load().VIPHost)
	}
	saved, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(saved), `"vip_host": "192.0.2.231"`) {
		t.Fatalf("web.json not updated: %s, %v", saved, err)
	}
}

func TestFloatingMgmtAddr_NegativeCases(t *testing.T) {
	nodes := []string{"127.0.0.1"}
	for host, why := range map[string]string{
		"127.0.0.1":    "a node's own address is never the floating VIP",
		"not-an-ip":    "a hostname is not a held address",
		"203.0.113.77": "an address this machine doesn't hold",
	} {
		if floatingMgmtAddr(nodes, host) {
			t.Errorf("floatingMgmtAddr(%q) = true: %s", host, why)
		}
	}
}

func TestVIPHostMiddleware_ServesFloatingAddress(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	isNewVIP := func(h string) bool { return h == "192.0.2.231" }
	handler := vipHostMiddleware(fixedHost("192.0.2.230"), nil, "https", "8443", inner, isNewVIP)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "192.0.2.231:8443"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("request on the floating new VIP got %d, want 200 (vip_host not updated yet must not bounce it to the old VIP)", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "192.0.2.51:8443"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently {
		t.Errorf("request on a node address got %d, want a redirect to the VIP", rec.Code)
	}
}
