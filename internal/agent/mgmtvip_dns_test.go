// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func renderMgmt(t *testing.T, a *Agent) string { return renderMgmtOn(t, a, "eth0") }

func renderMgmtOn(t *testing.T, a *Agent, iface string) string {
	t.Helper()
	_ = a.RenderMgmtVIPConfig(&config.MgmtVIPConfig{VIP: "192.0.2.100/24", VRRPID: 60}, &config.Platform{Mgmt: iface})
	b, err := os.ReadFile(filepath.Join(a.dataDir, "keepalived-mgmt.conf"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRenderMgmtVIPConfig_WithoutADNSVIPNothingChanges(t *testing.T) {
	a := &Agent{dataDir: t.TempDir(), role: config.RoleCore1, psk: "secret"}
	plain := renderMgmt(t, a)
	if strings.Contains(plain, "DNSHIVED_DNS") || strings.Contains(plain, "track_file") {
		t.Fatal("no DNS VIP was asked for, the management file must be unchanged")
	}
	a.SetDNSVIP(&DNSVIPSpec{VIP: "192.0.2.53/24", VRRPID: 61, TrackFile: "/x/track"})
	a.SetDNSVIP(nil)
	if again := renderMgmt(t, a); again != plain {
		t.Fatal("switching the DNS VIP on and off again must leave the file as it was")
	}
}

func TestRenderMgmtVIPConfig_DNSVIPInstance(t *testing.T) {
	for role, prio := range map[string]string{config.RoleCore3: "110", config.RoleCore1: "100", config.RoleCore2: "90"} {
		a := &Agent{dataDir: t.TempDir(), role: role, psk: "secret"}
		a.SetDNSVIP(&DNSVIPSpec{VIP: "192.0.2.53/24", VRRPID: 61, TrackFile: "/var/lib/dnshived/dns-vip.track"})
		got := renderMgmt(t, a)
		i := strings.Index(got, "vrrp_instance DNSHIVED_DNS")
		if i < 0 {
			t.Fatalf("%s: no DNS instance:\n%s", role, got)
		}
		dns := got[i:]
		for _, want := range []string{"virtual_router_id 61", "priority " + prio, "192.0.2.53/24", "preempt_delay 20", "track_file {", "DNSHIVED_DNS_OK", "auth_pass"} {
			if !strings.Contains(dns, want) {
				t.Errorf("%s: the DNS instance lacks %q", role, want)
			}
		}
		if strings.Contains(dns, "nopreempt") {
			t.Errorf("%s: a degraded master must be replaceable, so the DNS instance may not be nopreempt", role)
		}
		if !strings.Contains(got, "file /var/lib/dnshived/dns-vip.track") || !strings.Contains(got, "init_file 0") {
			t.Errorf("%s: track file block missing", role)
		}
		if !strings.Contains(got[:i], "vrrp_instance DNSHIVED_MGMT") || !strings.Contains(got[:i], "nopreempt") {
			t.Errorf("%s: the management instance must be untouched", role)
		}
	}
}

func TestRenderMgmtVIPConfig_KeepalivedAcceptsTheDNSInstance(t *testing.T) {
	bin, err := exec.LookPath("keepalived")
	if err != nil {
		t.Skip("keepalived is not installed")
	}
	dir := t.TempDir()
	a := &Agent{dataDir: dir, role: config.RoleCore1, psk: "secret"}
	a.SetDNSVIP(&DNSVIPSpec{VIP: "192.0.2.53/24", VRRPID: 61, TrackFile: filepath.Join(dir, "dns-vip.track")})
	renderMgmtOn(t, a, "lo")
	out, _ := exec.Command(bin, "-t", "-f", filepath.Join(dir, "keepalived-mgmt.conf")).CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		l := strings.ToLower(line)
		if line == "" || strings.Contains(l, "interface") {
			continue
		}
		t.Errorf("keepalived finds a problem in the rendered file (only interface complaints are expected on this host): %s", line)
	}
	if !strings.Contains(string(out), "DNSHIVED_DNS") {
		t.Fatalf("keepalived did not read the DNS instance at all:\n%s", out)
	}
}
