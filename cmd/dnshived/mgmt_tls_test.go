// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/config"
)

// withFakeInterfaceDetection swaps detectInterfaceFunc for a spy that maps
// one fixed IP to one fixed interface name.
func withFakeInterfaceDetection(t *testing.T, ip, iface string) {
	t.Helper()
	orig := detectInterfaceFunc
	detectInterfaceFunc = func(gotIP string) (string, error) {
		if gotIP == ip {
			return iface, nil
		}
		return "", &setupError{msg: "no interface owns " + gotIP}
	}
	t.Cleanup(func() { detectInterfaceFunc = orig })
}

func TestBuilderState_SetMgmtVIP_RequiresSelfAddrFirst(t *testing.T) {
	b := &builderState{}
	if err := b.setMgmtVIP("192.168.0.230/24", 60); err == nil {
		t.Fatal("expected an error setting a management VIP before this node's own address is known")
	}
}

// TestBuilderState_SetMgmtVIP_RejectsInvalidCIDR confirms a malformed
// address is rejected before anything (including the interface lookup)
// runs against it.
func TestBuilderState_SetMgmtVIP_RejectsInvalidCIDR(t *testing.T) {
	b := &builderState{}
	if err := b.setSelfAddr("192.168.0.22:9443"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, bad := range []string{"not-an-ip", "192.168.0.230", "192.168.0.230/99"} {
		if err := b.setMgmtVIP(bad, 60); err == nil {
			t.Errorf("setMgmtVIP(%q, 60) returned nil error, want a rejection", bad)
		}
	}
}

// TestBuilderState_SetMgmtVIP_RejectsOutOfRangeVRRPID covers the real
// keepalived constraint (virtual_router_id is a single byte, 1-255).
func TestBuilderState_SetMgmtVIP_RejectsOutOfRangeVRRPID(t *testing.T) {
	b := &builderState{}
	if err := b.setSelfAddr("192.168.0.22:9443"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, id := range []int{0, -1, 256, 1000} {
		if err := b.setMgmtVIP("192.168.0.230/24", id); err == nil {
			t.Errorf("setMgmtVIP with VRRP ID %d returned nil error, want a rejection", id)
		}
	}
}

// TestBuilderState_SetMgmtVIP_DetectsInterfaceFromSelfAddr is the actual
// golden path — the interface is derived, not operator-entered.
func TestBuilderState_SetMgmtVIP_DetectsInterfaceFromSelfAddr(t *testing.T) {
	withFakeInterfaceDetection(t, "192.168.0.22", "eth0")
	b := &builderState{}
	if err := b.setSelfAddr("192.168.0.22:9443"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := b.setMgmtVIP("192.168.0.230/24", 60); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	vip, vrrpID, iface := b.getMgmtVIP()
	if vip != "192.168.0.230/24" || vrrpID != 60 || iface != "eth0" {
		t.Errorf("getMgmtVIP() = (%q, %d, %q), want (192.168.0.230/24, 60, eth0)", vip, vrrpID, iface)
	}
}

// TestBuilderState_SetMgmtVIP_EmptyClears confirms blanking the field back
// out actually removes a previously-set VIP rather than leaving it
// silently in place.
func TestBuilderState_SetMgmtVIP_EmptyClears(t *testing.T) {
	withFakeInterfaceDetection(t, "192.168.0.22", "eth0")
	b := &builderState{}
	b.setSelfAddr("192.168.0.22:9443")
	b.setMgmtVIP("192.168.0.230/24", 60)

	if err := b.setMgmtVIP("", 0); err != nil {
		t.Fatalf("unexpected error clearing: %v", err)
	}
	vip, vrrpID, iface := b.getMgmtVIP()
	if vip != "" || vrrpID != 0 || iface != "" {
		t.Errorf("getMgmtVIP() after clearing = (%q, %d, %q), want all zero", vip, vrrpID, iface)
	}
}

func TestBuilderState_SetTLS_RejectsMismatchedPair(t *testing.T) {
	cert1, key1, err := genSelfSignedCert([]string{"host1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, key2, err := genSelfSignedCert([]string{"host2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	b := &builderState{}
	if err := b.setTLS(string(cert1), string(key2)); err == nil {
		t.Fatal("expected an error for a cert/key that don't form a valid pair")
	}
	// The rejected pair must not have been stored.
	gotCert, gotKey := b.getTLS()
	if gotCert != "" || gotKey != "" {
		t.Error("a rejected TLS pair was stored anyway")
	}
	_ = key1
}

// TestBuilderState_SetTLS_RejectsOneBlankOneNot covers the half-supplied
// case.
func TestBuilderState_SetTLS_RejectsOneBlankOneNot(t *testing.T) {
	cert, key, err := genSelfSignedCert([]string{"host1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b := &builderState{}
	if err := b.setTLS(string(cert), ""); err == nil {
		t.Error("expected an error for a certificate without a key")
	}
	if err := b.setTLS("", string(key)); err == nil {
		t.Error("expected an error for a key without a certificate")
	}
}

// TestBuilderState_SetTLS_ValidPairStoredAndClearable is the golden path
// plus the "go back to generated" clear path.
func TestBuilderState_SetTLS_ValidPairStoredAndClearable(t *testing.T) {
	cert, key, err := genSelfSignedCert([]string{"host1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b := &builderState{}
	if err := b.setTLS(string(cert), string(key)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gotCert, gotKey := b.getTLS()
	if gotCert == "" || gotKey == "" {
		t.Fatal("valid TLS pair was not stored")
	}

	if err := b.setTLS("", ""); err != nil {
		t.Fatalf("unexpected error clearing: %v", err)
	}
	gotCert, gotKey = b.getTLS()
	if gotCert != "" || gotKey != "" {
		t.Error("TLS pair still present after clearing with two blank fields")
	}
}

func TestGenSelfSignedCert_ProducesAValidPairCoveringEverySAN(t *testing.T) {
	sans := []string{"192.168.0.22", "192.168.0.230", "localhost", "127.0.0.1"}
	certPEM, keyPEM, err := genSelfSignedCert(sans)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("generated pair does not parse as a matched TLS certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("certPEM did not contain a decodable PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}

	wantIPs := []string{"192.168.0.22", "192.168.0.230", "127.0.0.1"}
	for _, want := range wantIPs {
		found := false
		for _, ip := range cert.IPAddresses {
			if ip.String() == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("certificate IPAddresses %v missing %q", cert.IPAddresses, want)
		}
	}
	found := false
	for _, name := range cert.DNSNames {
		if name == "localhost" {
			found = true
		}
	}
	if !found {
		t.Errorf("certificate DNSNames %v missing %q", cert.DNSNames, "localhost")
	}
}

// TestBuildClusterConfig_NoMgmtSetupLeavesPlatformAndMgmtVIPNil pins the
// "operator never set a VIP" default.
func TestBuildClusterConfig_NoMgmtSetupLeavesPlatformAndMgmtVIPNil(t *testing.T) {
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nodes := []clusterNode{
		{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true},
		{Addr: "192.168.0.23:9443", Role: config.RoleCore2},
		{Addr: "192.168.0.24:9443", Role: config.RoleCore3},
	}
	cc, err := buildClusterConfig(secrets, nodes[0], nodes, mgmtSetup{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cc.Platform != nil {
		t.Errorf("Platform = %+v, want nil when no management VIP was set", cc.Platform)
	}
	if cc.MgmtVIP != nil {
		t.Errorf("MgmtVIP = %+v, want nil when no management VIP was set", cc.MgmtVIP)
	}
}

// TestBuildClusterConfig_MgmtSetupWiresPlatformAndMgmtVIP is the golden
// path.
func TestBuildClusterConfig_MgmtSetupWiresPlatformAndMgmtVIP(t *testing.T) {
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nodes := []clusterNode{
		{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true},
		{Addr: "192.168.0.23:9443", Role: config.RoleCore2},
		{Addr: "192.168.0.24:9443", Role: config.RoleCore3},
	}
	mgmt := mgmtSetup{VIP: "192.168.0.230/24", VRRPID: 60, Iface: "eth0"}
	cc, err := buildClusterConfig(secrets, nodes[0], nodes, mgmt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cc.Platform == nil || cc.Platform.Mgmt != "eth0" {
		t.Errorf("Platform = %+v, want Mgmt=eth0", cc.Platform)
	}
	if cc.MgmtVIP == nil || cc.MgmtVIP.VIP != "192.168.0.230/24" || cc.MgmtVIP.VRRPID != 60 {
		t.Errorf("MgmtVIP = %+v, want {192.168.0.230/24 60}", cc.MgmtVIP)
	}
}

func TestBuildClusterConfig_SetsCoreTLSCertAndKeyPaths(t *testing.T) {
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nodes := []clusterNode{{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true}}
	cc, err := buildClusterConfig(secrets, nodes[0], nodes, mgmtSetup{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cc.TLSCert != coreTLSCertFile || cc.TLSKey != coreTLSKeyFile {
		t.Errorf("TLSCert/TLSKey = %q/%q, want %q/%q", cc.TLSCert, cc.TLSKey, coreTLSCertFile, coreTLSKeyFile)
	}
}

func TestBuildClusterConfig_AssemblesWorkerOverridesFromRecordedNodes(t *testing.T) {
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nodes := []clusterNode{
		{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true},
		{
			Addr: "192.168.0.26:9443", Role: config.RoleCore2,
			WorkerOverride: map[string]string{"ens19": "eth1", "ens20": "eth2"},
		},
		{Addr: "192.168.0.27:9443", Role: config.RoleCore3}, // no override -- same naming as founder
	}
	mgmt := mgmtSetup{Iface: "eth0", PlatformMgmt: "eth0", PlatformWorkers: []string{"ens19", "ens20"}}
	cc, err := buildClusterConfig(secrets, nodes[0], nodes, mgmt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cc.Platform == nil {
		t.Fatal("Platform is nil")
	}
	got := cc.Platform.WorkerOverrides["core-2"]
	if got["ens19"] != "eth1" || got["ens20"] != "eth2" {
		t.Errorf("WorkerOverrides[core-2] = %+v, want {ens19:eth1 ens20:eth2}", got)
	}
	if _, ok := cc.Platform.WorkerOverrides["core-3"]; ok {
		t.Errorf("core-3 has no recorded override — must not get an entry at all, got %+v", cc.Platform.WorkerOverrides["core-3"])
	}
	if _, ok := cc.Platform.WorkerOverrides["core-1"]; ok {
		t.Error("self (the founder) must never get a WorkerOverrides entry — its own names ARE the canonical ones")
	}
	// Confirms the actual resolution round-trips correctly end to end,
	// not just that the map shape looks right.
	if local := cc.Platform.ResolveParent("core-2", "ens19"); local != "eth1" {
		t.Errorf("ResolveParent(core-2, ens19) = %q, want eth1", local)
	}
	if local := cc.Platform.ResolveParent("core-3", "ens19"); local != "ens19" {
		t.Errorf("ResolveParent(core-3, ens19) = %q, want ens19 (no override)", local)
	}
}

func TestWriteLocalClusterConfig_WritesCoreTLSMaterialToPathsNamedInConfig(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls", "cert.pem")
	keyPath := filepath.Join(dir, "tls", "key.pem")

	cc := config.Cluster{Role: config.RoleCore1, ControlAddr: "192.168.0.22:9443", TLSCert: certPath, TLSKey: keyPath}
	raw, err := json.Marshal(cc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfgPath := filepath.Join(dir, "cluster.json")
	payload := adoptPayload{
		ClusterJSON:    raw,
		CoreTLSCertPEM: []byte("fake-cert-bytes"),
		CoreTLSKeyPEM:  []byte("fake-key-bytes"),
	}
	if err := writeLocalClusterConfig(cfgPath, payload); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	gotCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("expected core TLS cert written to %s: %v", certPath, err)
	}
	if string(gotCert) != "fake-cert-bytes" {
		t.Errorf("cert content = %q, want fake-cert-bytes", gotCert)
	}
	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("expected core TLS key written to %s: %v", keyPath, err)
	}
	if string(gotKey) != "fake-key-bytes" {
		t.Errorf("key content = %q, want fake-key-bytes", gotKey)
	}
}

// TestBuildWebConfig_TLSDisabledIsPlainHTTPOnListenAddr checks
// tlsEnabled=false serves plain HTTP on ListenAddr.
func TestBuildWebConfig_TLSDisabledIsPlainHTTPOnListenAddr(t *testing.T) {
	nodes := []clusterNode{{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true}}
	cfg := buildWebConfig(nodes, "tok", "probe-tok", "", false)
	if cfg.ListenAddr != webUIListenAddr {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, webUIListenAddr)
	}
	if cfg.TLSCert != "" || cfg.TLSKey != "" || cfg.HTTPAddr != "" {
		t.Errorf("TLS fields set despite tlsEnabled=false: cert=%q key=%q httpAddr=%q", cfg.TLSCert, cfg.TLSKey, cfg.HTTPAddr)
	}
}

func TestBuildWebConfig_TLSEnabledSwitchesToHTTPSWithRedirectListener(t *testing.T) {
	nodes := []clusterNode{{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true}}
	cfg := buildWebConfig(nodes, "tok", "probe-tok", "192.168.0.230", true)
	if cfg.ListenAddr != webUITLSListenAddr {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, webUITLSListenAddr)
	}
	if cfg.HTTPAddr != webUIListenAddr {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, webUIListenAddr)
	}
	if cfg.TLSCert != webUITLSCertFile || cfg.TLSKey != webUITLSKeyFile {
		t.Errorf("TLSCert/TLSKey = %q/%q, want %q/%q", cfg.TLSCert, cfg.TLSKey, webUITLSCertFile, webUITLSKeyFile)
	}
	if cfg.VIPHost != "192.168.0.230" {
		t.Errorf("VIPHost = %q, want 192.168.0.230", cfg.VIPHost)
	}
	for _, n := range cfg.Nodes {
		if !n.TLS {
			t.Errorf("node %q has TLS=false, want true — every founded core node's own control API is TLS-enabled", n.Name)
		}
	}
}

func TestBuildWebConfig_SetsSelfAdminToken(t *testing.T) {
	nodes := []clusterNode{{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true}}
	cfg := buildWebConfig(nodes, "tok", "probe-tok", "", true)
	if cfg.SelfAdminToken != "tok" {
		t.Errorf("SelfAdminToken = %q, want %q (the same shared admin token every Nodes[] entry carries)", cfg.SelfAdminToken, "tok")
	}
}

func TestBuildWebConfig_ProbeHostsPopulatedFromRecordedProbeNode(t *testing.T) {
	nodes := []clusterNode{
		{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true},
		{Addr: "192.168.0.23:9443", Role: config.RoleCore2},
		{Addr: "192.168.0.24:9443", Role: config.RoleCore3},
		{Addr: "192.168.0.42:9444", Role: "probe", TrunkParent: "ens19"},
	}
	cfg := buildWebConfig(nodes, "tok", "probe-admin-tok", "", true)
	if len(cfg.ProbeHosts) != 1 {
		t.Fatalf("ProbeHosts = %v, want exactly 1 entry", cfg.ProbeHosts)
	}
	got := cfg.ProbeHosts[0]
	if got.Addr != "192.168.0.42:9444" {
		t.Errorf("ProbeHosts[0].Addr = %q, want 192.168.0.42:9444", got.Addr)
	}
	if got.Name == "" {
		t.Error("ProbeHosts[0].Name is empty — the web UI has nothing to label the row with")
	}
	for _, n := range cfg.Nodes {
		if n.Addr == "192.168.0.42:9444" {
			t.Error("the probe's address leaked into the core Nodes list")
		}
	}
	if got.AdminToken != "probe-admin-tok" {
		t.Errorf("ProbeHosts[0].AdminToken = %q, want the dedicated probe-admin token %q — without it dnshived-web sends no Authorization header at all against a probe that now requires one", got.AdminToken, "probe-admin-tok")
	}
	for _, n := range cfg.Nodes {
		if n.AdminToken != "tok" {
			t.Errorf("core node %q AdminToken = %q, want the real shared admin token %q — unaffected by the probe-token change", n.Name, n.AdminToken, "tok")
		}
	}
}

// TestBuildProbeConfig_EmbedsDedicatedProbeAdminTokenAsAPIToken checks the
// probe gets its own dedicated admin token as its API token.
func TestBuildProbeConfig_EmbedsDedicatedProbeAdminTokenAsAPIToken(t *testing.T) {
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nodes := []clusterNode{
		{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true},
		{Addr: "192.168.0.23:9443", Role: config.RoleCore2},
		{Addr: "192.168.0.24:9443", Role: config.RoleCore3},
	}
	probeNode := clusterNode{Addr: "192.168.0.42:9444", Role: "probe", TrunkParent: "ens19"}

	pc, err := buildProbeConfig(secrets, nodes, probeNode, mgmtSetup{})
	if err != nil {
		t.Fatalf("buildProbeConfig: %v", err)
	}
	if len(pc.APITokens) != 2 {
		t.Fatalf("APITokens = %v, want exactly 2 entries (admin + readonly)", pc.APITokens)
	}
	byRole := map[string]string{}
	for _, tok := range pc.APITokens {
		byRole[tok.Role] = tok.Token
	}
	if byRole["admin"] != secrets.ProbeAdminToken {
		t.Errorf("admin-role token = %q, want the dedicated probe-admin token %q — the Daemons tab's probe-restart button needs it", byRole["admin"], secrets.ProbeAdminToken)
	}
	if byRole["admin"] == secrets.AdminToken {
		t.Error("admin-role token on the probe equals the REAL cluster admin token — a compromised probe host would yield full RequireAdmin power over every core node")
	}
	if byRole["readonly"] != secrets.ReadonlyToken {
		t.Errorf("readonly-role token = %q, want the dedicated readonly token %q — dnshived-top's own least-privilege token must also work against the probe", byRole["readonly"], secrets.ReadonlyToken)
	}
}

func TestBuildProbeConfig_PopulatesVLANConstructionFields(t *testing.T) {
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nodes := []clusterNode{
		{Addr: "192.168.0.22:9443", Role: config.RoleCore1, Self: true},
	}
	probeNode := clusterNode{Addr: "192.168.0.42:9444", Role: "probe", TrunkParent: "ens19"}
	mgmt := mgmtSetup{PlatformWorkers: []string{"ens19", "ens20"}}

	pc, err := buildProbeConfig(secrets, nodes, probeNode, mgmt)
	if err != nil {
		t.Fatalf("buildProbeConfig: %v", err)
	}
	if pc.LocalOctet != 42 {
		t.Errorf("LocalOctet = %d, want 42 (derived from the probe's own address 192.168.0.42:9444)", pc.LocalOctet)
	}
	if pc.ProbeHelperSocket == "" {
		t.Error("ProbeHelperSocket is empty — without it, the adopted probe can't reach its own privileged helper to build VLAN interfaces at all")
	}
	if pc.KnownVLANsPath == "" {
		t.Error("KnownVLANsPath is empty — required by the probe's own loadProbeConfig whenever LocalOctet is nonzero")
	}
	if len(pc.TrunkParents) != 2 || pc.TrunkParents[0] != "ens19" || pc.TrunkParents[1] != "ens20" {
		t.Errorf("TrunkParents = %v, want %v (the cluster's full known worker-trunk list, not just TrunkParent's single value)", pc.TrunkParents, mgmt.PlatformWorkers)
	}
}

func TestBootstrapCommitHandler_GeneratesSelfSignedCertWhenNonePasted(t *testing.T) {
	origReExec := reExecFunc
	reExecFunc = func() {}
	defer func() { reExecFunc = origReExec }()

	// coreBootstrapContactAddr always forces port 80.
	var gotTLSCert, gotTLSKey []byte
	remoteBLn, err := net.Listen("tcp", "127.0.0.2:80")
	if err != nil {
		t.Skipf("port 80 unavailable in this test environment: %v", err)
	}
	remoteB := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req bootstrapAdoptRequest
		json.NewDecoder(r.Body).Decode(&req)
		gotTLSCert = req.TLSCertPEM
		gotTLSKey = req.TLSKeyPEM
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	remoteB.Listener.Close()
	remoteB.Listener = remoteBLn
	remoteB.Start()
	defer remoteB.Close()
	remoteArbLn, err := net.Listen("tcp", "127.0.0.3:80")
	if err != nil {
		t.Skipf("port 80 unavailable in this test environment: %v", err)
	}
	remoteArb := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	remoteArb.Listener.Close()
	remoteArb.Listener = remoteArbLn
	remoteArb.Start()
	defer remoteArb.Close()

	cfgPath := filepath.Join(t.TempDir(), "cluster.json")
	state := &builderState{}
	state.setRole(config.RoleCore1)
	state.setSelfAddr("192.168.0.22:9443")
	state.addNode("127.0.0.2:9443", config.RoleCore2, "OTP-B", "")
	state.addNode("127.0.0.3:9443", config.RoleCore3, "OTP-ARB", "")

	handler := bootstrapCommitHandler(cfgPath, state)
	req := httptest.NewRequest(http.MethodPost, "/setup/commit", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "https://") {
		t.Errorf("result page has no https:// link: %s", body)
	}
	if len(gotTLSCert) == 0 || len(gotTLSKey) == 0 {
		t.Error("remote node's adopt push carried no TLS material despite the operator never pasting any — the self-signed fallback didn't run")
	}
	if _, err := tls.X509KeyPair(gotTLSCert, gotTLSKey); err != nil {
		t.Errorf("pushed TLS material does not form a valid pair: %v", err)
	}
}

func TestBuildProbeConfig_TLSMatchesFoundedCoreAPI(t *testing.T) {
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nodes := []clusterNode{
		{Addr: "192.168.0.51:9443", Role: config.RoleCore1, Self: true},
		{Addr: "192.168.0.52:9443", Role: config.RoleCore2},
		{Addr: "192.168.0.53:9443", Role: config.RoleCore3},
	}
	probeNode := clusterNode{Addr: "192.168.0.54:9444", Role: "probe", TrunkParent: "ens19"}
	mgmt := mgmtSetup{PlatformMgmt: "ens18", PlatformWorkers: []string{"ens19", "ens20"}}

	coreCfg, err := buildClusterConfig(secrets, nodes[0], nodes, mgmt)
	if err != nil {
		t.Fatalf("buildClusterConfig: %v", err)
	}
	if !coreCfg.TLSEnabled() {
		t.Fatal("precondition: founding is expected to give the core API TLS")
	}

	pc, err := buildProbeConfig(secrets, nodes, probeNode, mgmt)
	if err != nil {
		t.Fatalf("buildProbeConfig: %v", err)
	}
	if len(pc.ClusterNodes) != 3 {
		t.Fatalf("ClusterNodes = %v, want the 3 core nodes", pc.ClusterNodes)
	}
	for _, n := range pc.ClusterNodes {
		if n.TLS != coreCfg.TLSEnabled() {
			t.Errorf("%s: TLS = %v, but the founded core API serves TLS = %v; the probe would get HTTP 400 on every fetch", n.Name, n.TLS, coreCfg.TLSEnabled())
		}
	}
}

func TestBuildProbeConfig_NoCoreNodeIsAnError(t *testing.T) {
	secrets, _ := generateClusterSecrets()
	probeNode := clusterNode{Addr: "192.168.0.54:9444", Role: "probe", TrunkParent: "ens19"}
	if _, err := buildProbeConfig(secrets, []clusterNode{probeNode}, probeNode, mgmtSetup{}); err == nil {
		t.Error("buildProbeConfig with no core node returned no error")
	}
}
