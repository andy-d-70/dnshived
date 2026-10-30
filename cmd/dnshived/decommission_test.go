// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/config"
)

// TestDeletePath_RemovesFileAndDirectoryTreeOutright is the pure unit test
// for the primitive itself.
func TestDeletePath_RemovesFileAndDirectoryTreeOutright(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(file, []byte("psk"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	deletePath(file)
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("file still exists after deletePath (err=%v)", err)
	}

	treeRoot := filepath.Join(dir, "data")
	if err := os.MkdirAll(filepath.Join(treeRoot, "backups"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(treeRoot, "backups", "backup.enc"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	deletePath(treeRoot)
	if _, err := os.Stat(treeRoot); !os.IsNotExist(err) {
		t.Errorf("directory tree still exists after deletePath (err=%v)", err)
	}
}

func TestDeletePath_MissingPathIsNoop(t *testing.T) {
	deletePath("") // must not panic
	deletePath(filepath.Join(t.TempDir(), "never-existed"))
}

func TestSweepDir_RemovesEveryEntryButKeepsDirItself(t *testing.T) {
	dir := t.TempDir()
	files := []string{"cluster.json.bak", "cluster.json.bak-prewipe-20260818", "web.json.bak-precoord"}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("secret"), 0o644); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "tls"), 0o755); err != nil {
		t.Fatalf("mkdir tls: %v", err)
	}

	sweepDir(dir)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("dir itself should still exist and be readable: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("sweepDir left %d entries behind: %v", len(entries), entries)
	}
}

func TestSweepDir_MissingDirIsNoop(t *testing.T) {
	sweepDir(filepath.Join(t.TempDir(), "never-existed"))
}

func TestSelfDecommission_NoConfigFileStillReExecs(t *testing.T) {
	t.Cleanup(func() { decommissioning.Store(false) })

	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json") // never written

	origCfg := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(origCfg) })
	currentConfig.Store(nil)

	origReExec := reExecFunc
	reExecCalled := make(chan struct{}, 1)
	reExecFunc = func() { reExecCalled <- struct{}{} }
	t.Cleanup(func() { reExecFunc = origReExec })

	selfDecommission(path, "test")

	select {
	case <-reExecCalled:
	default:
		t.Fatal("reExecFunc was never called even with no config file to delete")
	}
}

func TestSelfDecommission_RestoresProbeUnitsAndDropsLegacyNFT(t *testing.T) {
	t.Cleanup(func() { decommissioning.Store(false) })

	origCfg := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(origCfg) })
	currentConfig.Store(nil)

	origReExec := reExecFunc
	reExecFunc = func() {}
	t.Cleanup(func() { reExecFunc = origReExec })

	var enabled []string
	origEnable := enableUnitFunc
	enableUnitFunc = func(unit string) error {
		enabled = append(enabled, unit)
		return nil
	}
	t.Cleanup(func() { enableUnitFunc = origEnable })

	legacyCalls := 0
	origLegacy := removeLegacyNFTFunc
	removeLegacyNFTFunc = func() error {
		legacyCalls++
		return nil
	}
	t.Cleanup(func() { removeLegacyNFTFunc = origLegacy })

	selfDecommission(filepath.Join(t.TempDir(), "cluster.json"), "test")

	if legacyCalls != 1 {
		t.Fatalf("removeLegacyNFT called %d times, want 1", legacyCalls)
	}
	if len(enabled) != len(probeUnitsForAdoption) {
		t.Fatalf("enabled %v, want %v", enabled, probeUnitsForAdoption)
	}
	for i, unit := range probeUnitsForAdoption {
		if enabled[i] != unit {
			t.Fatalf("enabled %v, want %v", enabled, probeUnitsForAdoption)
		}
	}
}

func TestComputeTrustedHosts_SortedThreeAddressSet(t *testing.T) {
	got := computeTrustedHosts("192.0.2.23:9443", "192.0.2.24:9443", "192.0.2.43:9443")
	want := []string{"192.0.2.23", "192.0.2.24", "192.0.2.43"}
	if len(got) != 3 {
		t.Fatalf("computeTrustedHosts = %v, want 3 entries", got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("computeTrustedHosts[%d] = %q, want %q (got %v)", i, got[i], w, got)
		}
	}
}

func TestComputeTrustedHosts_StripsPorts(t *testing.T) {
	got := computeTrustedHosts("192.0.2.22:9443", "192.0.2.24:9443", "192.0.2.23:9443")
	for _, h := range got {
		if h != "192.0.2.22" && h != "192.0.2.23" && h != "192.0.2.24" {
			t.Errorf("computeTrustedHosts entry %q still carries a port or is unexpected", h)
		}
	}
}

func TestComputeTrustedHosts_EmptyThirdAddrOmittedNotPolluted(t *testing.T) {
	got := computeTrustedHosts("192.0.2.23:9443", "", "192.0.2.22:9443")
	if len(got) != 2 {
		t.Fatalf("computeTrustedHosts = %v, want exactly 2 entries (no bogus empty one)", got)
	}
	for _, h := range got {
		if h == "" {
			t.Errorf("computeTrustedHosts contains an empty entry: %v", got)
		}
	}
	want := []string{"192.0.2.22", "192.0.2.23"}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("computeTrustedHosts[%d] = %q, want %q (got %v)", i, got[i], w, got)
		}
	}
}

func TestNotifyPeersOfSelfRemoval_PushesSelfAddrRemovedFromEveryPeer(t *testing.T) {
	var received [][]string
	newFakePeer := func() *httptest.Server {
		mux := http.NewServeMux()
		mux.HandleFunc("/api/v1/nodes/update-trusted-hosts", func(w http.ResponseWriter, r *http.Request) {
			var req updateTrustedHostsRequest
			json.NewDecoder(r.Body).Decode(&req)
			received = append(received, req.Hosts)
			w.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("/api/v1/nodes/remove-peer", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		return httptest.NewServer(mux)
	}
	peer1 := newFakePeer()
	defer peer1.Close()
	peer2 := newFakePeer()
	defer peer2.Close()
	peer1Addr := peer1.URL[len("http://"):]
	peer2Addr := peer2.URL[len("http://"):]

	cfg := &config.Cluster{
		ControlAddr:  "192.0.2.23:9443", // self — never actually dialed, just stripped from the pushed list
		Peers:        []string{peer1Addr, peer2Addr},
		TrustedHosts: []string{"192.0.2.22", "192.0.2.23", "192.0.2.24"},
		APITokens:    []config.APIToken{{Name: "admin", Role: "admin", Token: "tok"}},
	}

	notifyPeersOfSelfRemoval(cfg)

	if len(received) != 2 {
		t.Fatalf("expected 2 peer pushes, got %d", len(received))
	}
	for _, hosts := range received {
		for _, h := range hosts {
			if h == "192.0.2.23" {
				t.Errorf("pushed trusted_hosts %v still contains the self address that's decommissioning — the exact bug this test guards against", hosts)
			}
		}
		if len(hosts) != 2 {
			t.Errorf("pushed trusted_hosts = %v, want exactly the other 2 addresses", hosts)
		}
	}
}

func TestNotifyPeersOfSelfRemoval_AlsoPushesPeerRemoval(t *testing.T) {
	var removedAddrs []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/nodes/update-trusted-hosts", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/v1/nodes/remove-peer", func(w http.ResponseWriter, r *http.Request) {
		var req removePeerRequest
		json.NewDecoder(r.Body).Decode(&req)
		removedAddrs = append(removedAddrs, req.Addr)
		w.WriteHeader(http.StatusOK)
	})
	peer := httptest.NewServer(mux)
	defer peer.Close()
	peerAddr := peer.URL[len("http://"):]

	cfg := &config.Cluster{
		ControlAddr:  "192.0.2.23:9443",
		Peers:        []string{peerAddr},
		TrustedHosts: []string{"192.0.2.22", "192.0.2.23"},
		APITokens:    []config.APIToken{{Name: "admin", Role: "admin", Token: "tok"}},
	}

	notifyPeersOfSelfRemoval(cfg)

	if len(removedAddrs) != 1 || removedAddrs[0] != "192.0.2.23:9443" {
		t.Errorf("remove-peer received addr = %v, want exactly [%q] (this node's own ControlAddr)", removedAddrs, "192.0.2.23:9443")
	}
}

func TestUpdateTrustedHostsInConfig_SavesAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	cc := &config.Cluster{
		SchemaVersion: 2, ClusterID: "c", NodeID: "worker-a-x", Role: "core-1",
		ControlAddr: "192.0.2.22:9443", DataDir: dir,
		PSK: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd", TrustedHosts: []string{"192.0.2.22", "192.0.2.23", "192.0.2.24"},
		Scopes: map[string]config.ScopeConfig{},
	}
	raw, _ := json.MarshalIndent(cc, "", "  ")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatalf("write config: %v", err)
	}

	newHosts := []string{"192.0.2.22", "192.0.2.24", "192.0.2.43"}
	if err := updateTrustedHostsInConfig(path, newHosts); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(reloaded.TrustedHosts) != 3 || reloaded.TrustedHosts[2] != "192.0.2.43" {
		t.Errorf("reloaded.TrustedHosts = %v, want %v", reloaded.TrustedHosts, newHosts)
	}
}

func TestPeerAdminClient_SchemeMatchesTLSConfig(t *testing.T) {
	plain := &config.Cluster{}
	client, scheme := peerAdminClient(plain)
	if scheme != "http" {
		t.Errorf("scheme = %q, want http for a cluster with no TLS configured", scheme)
	}
	if client.Transport != nil {
		t.Error("plain-HTTP client should not carry a custom TLS transport")
	}

	tlsCfg := &config.Cluster{TLSCert: "/etc/dnshived/tls/cert.pem", TLSKey: "/etc/dnshived/tls/key.pem"}
	client, scheme = peerAdminClient(tlsCfg)
	if scheme != "https" {
		t.Errorf("scheme = %q, want https when TLSCert/TLSKey are both set", scheme)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("https client must skip TLS verification — this project has no CA infrastructure for peer certs, same as replicateBackupToPeers's own identical precedent")
	}
}

func TestOffboardNodeHandler_RejectsInvalidRole(t *testing.T) {
	origCfg := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(origCfg) })
	currentConfig.Store(&config.Cluster{Role: "core-1"})

	handler := offboardNodeHandler(t.TempDir()+"/cluster.json", nil)
	for _, req := range []offboardNodeRequest{
		{Role: ""},
		{Role: "probe"},
		{Role: "not-a-role"},
	} {
		body, _ := json.Marshal(req)
		httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/offboard", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		handler(rec, httpReq)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("req %+v: status = %d, want 400: %s", req, rec.Code, rec.Body.String())
		}
	}
}

// TestListDnsmasqInstances_ToleratesNoUnits confirms the glob sweep
// degrades gracefully.
func TestListDnsmasqInstances_ToleratesNoUnits(t *testing.T) {
	got := listDnsmasqInstances()
	for _, u := range got {
		if !strings.HasPrefix(u, "dnshived-dnsmasq@") || !strings.HasSuffix(u, ".service") {
			t.Errorf("returned a non-matching unit name: %q", u)
		}
	}
}
