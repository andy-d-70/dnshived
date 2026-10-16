// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleLogs_RendersBothLogsAndAuditSections(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/status"):
			w.Write([]byte(`{"role":"core-1"}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/events"):
			w.Write([]byte(`[{"id":1,"ts":"2026-08-30T12:00:00Z","level":"INFO","prefix":"AGENT","message":"a real log line"}]`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/audit"):
			w.Write([]byte("2026-08-30T12:00:00Z admin committed a config change\n"))
		default:
			w.Write([]byte("{}"))
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodGet, "/logs", nil)
	rec := httptest.NewRecorder()

	handleLogs(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "a real log line") {
		t.Errorf("expected the Logs section's own event content, got:\n%s", body)
	}
	if !strings.Contains(body, "committed a config change") {
		t.Errorf("expected the merged Audit log section's own content, got:\n%s", body)
	}
	if !strings.Contains(body, `id="audit">Audit logs</h2>`) {
		t.Error("expected a distinct Audit logs section")
	}
	if !strings.Contains(body, `href="/audit"`) {
		t.Error("expected a link to the raw-text /audit export")
	}
}

func TestHandleLogs_ThreeCollapsibleSectionsWithDaemonLogsForEveryCoreRole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{}"))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	cfg := &WebConfig{Nodes: []NodeConfig{
		{Name: "core-1", Addr: addr}, {Name: "core-2", Addr: addr}, {Name: "core-3", Addr: addr},
	}}
	req := httptest.NewRequest(http.MethodGet, "/logs", nil)
	rec := httptest.NewRecorder()

	handleLogs(newConfigRef(cfg))(rec, req)
	body := rec.Body.String()

	for _, want := range []string{
		`<details><summary><h2 style="display:inline" id="logs">General logs</h2></summary>`,
		`<details><summary><h2 style="display:inline" id="audit">Audit logs</h2></summary>`,
		`<details id="daemons"><summary><h2 style="display:inline">Daemon logs (incl. dnsmasq)</h2></summary>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in body, got:\n%s", want, body)
		}
	}
	if !strings.Contains(body, `href="/logs/dnsmasq/core-1/core-dhcp" onclick="return showLogModal('core-1 — core-dhcp', '/logs/dnsmasq/core-1/core-dhcp', this)"`) {
		t.Error("expected core-1's core-dhcp link wired to the shared popup, with its real href kept as a no-JS fallback")
	}
	if !strings.Contains(body, `href="/logs/dnsmasq/core-2/core-dns" onclick="return showLogModal('core-2 — core-dns', '/logs/dnsmasq/core-2/core-dns', this)"`) {
		t.Error("expected core-2's core-dns link wired to the shared popup, with its real href kept as a no-JS fallback")
	}
	if !strings.Contains(body, `<dialog id="log-modal">`) {
		t.Error("expected the shared log-modal dialog element to render on this page")
	}
	if !strings.Contains(body, `onclick="return showLogModal('Audit log (raw)', '/audit', this)"`) {
		t.Error("expected the /audit raw-export link to open the same popup too (direct follow-up: \"also for audit\")")
	}
	if !strings.Contains(body, `href="/logs/dnsmasq/core-3/core-dhcp"`) {
		t.Error("expected core-3 to ALSO get its own dnsmasq log links — it's no longer excluded")
	}
}

func TestHandleLogs_IncludesSelfInDaemonLogsSection(t *testing.T) {
	local := newLocalConfigServer(t, "core-3", "192.168.0.22:9443")
	port := localPort(t, local)

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: "192.168.9.9:" + port, AdminToken: "shared-tok"}}}
	req := httptest.NewRequest(http.MethodGet, "/logs", nil)
	rec := httptest.NewRecorder()
	handleLogs(newConfigRef(cfg))(rec, req)
	body := rec.Body.String()

	if !strings.Contains(body, "/logs/daemon/core-3/dnshived.service") {
		t.Errorf("expected core-3's OWN daemon-log links to appear even though it's absent from cfg.Nodes (self-exclusion), got:\n%s", body)
	}
}

func TestHandleLogs_DaemonLogsSectionListsUnitsPerRole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{}"))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	cfg := &WebConfig{
		Nodes: []NodeConfig{
			{Name: "core-1", Addr: addr}, {Name: "core-2", Addr: addr}, {Name: "core-3", Addr: addr},
		},
		ProbeHosts: []NodeConfig{{Name: "probe-1", Addr: addr}},
	}
	req := httptest.NewRequest(http.MethodGet, "/logs", nil)
	rec := httptest.NewRecorder()
	handleLogs(newConfigRef(cfg))(rec, req)
	body := rec.Body.String()

	for _, node := range []string{"core-1", "core-2", "core-3"} {
		for _, unit := range []string{
			"dnshived.service", "dnshived-web.service", "dnshived-helper.service", "dnshived-keepalived-mgmt.service",
			"dnshived-keepalived.service", "dnshived-relay.service", "dnshived-dnsrelay.service",
		} {
			want := "/logs/daemon/" + node + "/" + unit
			if !strings.Contains(body, want) {
				t.Errorf("expected %q in body for every core node incl. core-3, missing for %s", want, node)
			}
		}
	}
	// The probe host gets its own section with its own two units.
	if !strings.Contains(body, "/logs/daemon/probe-1/dnshived-probe.service") {
		t.Error("expected the probe host's own dnshived-probe.service link")
	}
	if !strings.Contains(body, "/logs/daemon/probe-1/dnshived-probe-helper.service") {
		t.Error("expected the probe host's own dnshived-probe-helper.service link")
	}
}

func TestHandleLogs_NoProbeDaemonSectionWhenNoneAdopted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{}"))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: addr}}}
	req := httptest.NewRequest(http.MethodGet, "/logs", nil)
	rec := httptest.NewRecorder()
	handleLogs(newConfigRef(cfg))(rec, req)
	if strings.Contains(rec.Body.String(), "<h3>Probe host</h3>") {
		t.Error("expected no Probe host sub-heading when no probe host is configured")
	}
}

// TestHandleDaemonLogView pins the new raw-text log-view page for a node
// daemon unit.
func TestHandleDaemonLogView(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "dnshived.service"):
			w.Write([]byte(`{"lines":["journal line one","journal line two"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: addr}}}
	h := handleDaemonLogView(newConfigRef(cfg))

	req := httptest.NewRequest(http.MethodGet, "/logs/daemon/core-1/dnshived.service", nil)
	req.SetPathValue("node", "core-1")
	req.SetPathValue("unit", "dnshived.service")
	rec := httptest.NewRecorder()
	h(rec, req)
	if !strings.Contains(rec.Body.String(), "journal line one\njournal line two") {
		t.Errorf("expected the real tailed lines, got: %s", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
}

// TestHandleDaemonLogView_AllowsProbeHost.
func TestHandleDaemonLogView_AllowsProbeHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"lines":["probe journal line"]}`))
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	cfg := &WebConfig{ProbeHosts: []NodeConfig{{Name: "probe-1", Addr: addr}}}
	h := handleDaemonLogView(newConfigRef(cfg))

	req := httptest.NewRequest(http.MethodGet, "/logs/daemon/probe-1/dnshived-probe.service", nil)
	req.SetPathValue("node", "probe-1")
	req.SetPathValue("unit", "dnshived-probe.service")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "probe journal line") {
		t.Errorf("expected a probe host to be a valid daemon-log target, got status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestHandleDnsmasqLogView(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/core-dhcp"):
			w.Write([]byte(`{"lines":["line one","line two"]}`))
		case strings.Contains(r.URL.Path, "/core-dns"):
			w.Write([]byte(`{"lines":[],"note":"DNS query logging is not enabled"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: addr}}}
	h := handleDnsmasqLogView(newConfigRef(cfg))

	req := httptest.NewRequest(http.MethodGet, "/logs/dnsmasq/core-1/core-dhcp", nil)
	req.SetPathValue("node", "core-1")
	req.SetPathValue("scope", "core-dhcp")
	rec := httptest.NewRecorder()
	h(rec, req)
	if !strings.Contains(rec.Body.String(), "line one\nline two") {
		t.Errorf("expected the real tailed lines, got: %s", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/logs/dnsmasq/core-1/core-dns", nil)
	req2.SetPathValue("node", "core-1")
	req2.SetPathValue("scope", "core-dns")
	rec2 := httptest.NewRecorder()
	h(rec2, req2)
	if !strings.Contains(rec2.Body.String(), "DNS query logging is not enabled") {
		t.Errorf("expected the daemon's own note explaining the empty log, got: %s", rec2.Body.String())
	}
}

// TestHandleDnsmasqLogView_UnknownNodeIs404 confirms a probe host (or a
// nonexistent node name) is rejected — dnsmasq only ever runs on real
// core nodes.
func TestHandleDnsmasqLogView_UnknownNodeIs404(t *testing.T) {
	cfg := &WebConfig{ProbeHosts: []NodeConfig{{Name: "probe-1", Addr: "127.0.0.1:1"}}}
	h := handleDnsmasqLogView(newConfigRef(cfg))
	req := httptest.NewRequest(http.MethodGet, "/logs/dnsmasq/probe-1/core-dhcp", nil)
	req.SetPathValue("node", "probe-1")
	req.SetPathValue("scope", "core-dhcp")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for a probe host", rec.Code)
	}
}
