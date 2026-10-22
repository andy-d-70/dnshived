// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestSetupRoles_MatchesConfigRoleConstantsExactly(t *testing.T) {
	want := map[string]bool{config.RoleCore1: true, config.RoleCore2: true, config.RoleCore3: true}
	got := map[string]bool{}
	for _, r := range setupRoles {
		if r != "probe" {
			got[r] = true
		}
	}
	if len(got) != len(want) {
		t.Fatalf("setupRoles (excl. probe) = %v, want exactly %v", got, want)
	}
	for r := range want {
		if !got[r] {
			t.Errorf("setupRoles is missing %q", r)
		}
	}
}

// TestIsValidSetupRole_RejectsAnythingOutsideTheFixedSet covers the actual
// validation this wizard relies on.
func TestIsValidSetupRole_RejectsAnythingOutsideTheFixedSet(t *testing.T) {
	for _, valid := range setupRoles {
		if !isValidSetupRole(valid) {
			t.Errorf("isValidSetupRole(%q) = false, want true", valid)
		}
	}
	for _, invalid := range []string{"", "Worker-A", "worker-c", "admin", " worker-a"} {
		if isValidSetupRole(invalid) {
			t.Errorf("isValidSetupRole(%q) = true, want false", invalid)
		}
	}
}

func TestBuilderState_SetSelfAddr_RejectsMissingOrMalformedAddress(t *testing.T) {
	for _, addr := range []string{"", "192.0.2.22", "not-an-address", ":9443extra:bad", "192.0.2.22:"} {
		b := &builderState{}
		if err := b.setSelfAddr(addr); err == nil {
			t.Errorf("setSelfAddr(%q) returned nil error, want a rejection", addr)
		}
		if got := b.getSelfAddr(); got != "" {
			t.Errorf("setSelfAddr(%q): getSelfAddr() = %q after a rejected call, want empty", addr, got)
		}
	}
}

// TestBuilderState_SetSelfAddr_AcceptsValidHostPort checks a valid
// host:port is accepted.
func TestBuilderState_SetSelfAddr_AcceptsValidHostPort(t *testing.T) {
	b := &builderState{}
	if err := b.setSelfAddr("192.0.2.22:9443"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := b.getSelfAddr(); got != "192.0.2.22:9443" {
		t.Errorf("getSelfAddr() = %q, want 192.0.2.22:9443", got)
	}
}

// TestBuilderState_SetRoleRejectsInvalidWithoutMutatingState confirms an
// invalid submission doesn't clobber a previously-saved valid role.
func TestBuilderState_SetRoleRejectsInvalidWithoutMutatingState(t *testing.T) {
	b := &builderState{}
	if err := b.setRole(config.RoleCore1); err != nil {
		t.Fatalf("unexpected error setting a valid role: %v", err)
	}
	if err := b.setRole("worker-c"); err == nil {
		t.Fatal("setRole(\"worker-c\") returned nil error, want a rejection")
	}
	if got := b.getRole(); got != config.RoleCore1 {
		t.Errorf("getRole() = %q after a rejected update, want unchanged %q", got, config.RoleCore1)
	}
}

// TestBootstrapSetupHandler_ShowsRoleFormWithNothingSavedYet covers the
// very first visit.
func TestBootstrapSetupHandler_ShowsRoleFormWithNothingSavedYet(t *testing.T) {
	state := &builderState{}
	handler := bootstrapSetupHandler("worker-a-test", "9443", state)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "worker-a-test") {
		t.Errorf("body does not contain hostname: %s", body)
	}
	if strings.Contains(body, "Role recorded") {
		t.Error("body claims a role is recorded, but none was ever set")
	}
	for _, role := range setupRoles {
		if !strings.Contains(body, role) {
			t.Errorf("body does not offer role choice %q: %s", role, body)
		}
	}
}

// TestBootstrapSetupHandler_ShowsSavedRole is the template smoke test for
// the "already chosen" branch specifically.
func TestBootstrapSetupHandler_ShowsSavedRole(t *testing.T) {
	state := &builderState{}
	if err := state.setRole(config.RoleCore3); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	handler := bootstrapSetupHandler("arb-test", "9443", state)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `value="core-3" required checked`) {
		t.Errorf("body does not show %q pre-selected: %s", config.RoleCore3, body)
	}
}

// TestBootstrapSetRoleHandler_ValidRoleSavesAndRedirects covers the actual
// form submission an operator's browser sends.
func TestBootstrapSetRoleHandler_ValidRoleSavesAndRedirects(t *testing.T) {
	state := &builderState{}
	handler := bootstrapSetRoleHandler("worker-a-test", "9443", state)

	form := url.Values{"role": {config.RoleCore2}}
	req := httptest.NewRequest(http.MethodPost, "/setup/role", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303 (See Other)", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/?step=2" {
		t.Errorf("Location = %q, want /?step=2 — role is step 1, network is step 2 (the old address step is gone)", got)
	}
	if got := state.getRole(); got != config.RoleCore2 {
		t.Errorf("state role = %q, want %q", got, config.RoleCore2)
	}
}

func TestBootstrapSetRoleHandler_AlsoSetsSelfAddrFromTheRequest(t *testing.T) {
	withFakeOutboundAddrDetection(t, "192.0.2.22:9443", nil)
	state := &builderState{}
	handler := bootstrapSetRoleHandler("worker-a-test", "9443", state)

	form := url.Values{"role": {config.RoleCore1}}
	req := httptest.NewRequest(http.MethodPost, "/setup/role", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if got := state.getSelfAddr(); got != "192.0.2.22:9443" {
		t.Errorf("state address = %q, want the auto-derived address, set with zero separate operator input", got)
	}
}

// TestBootstrapSetRoleHandler_InvalidRoleRejected is the direct end-to-end
// check that a tampered/garbage form value never reaches builderState as a
// stored role.
func TestBootstrapSetRoleHandler_InvalidRoleRejected(t *testing.T) {
	state := &builderState{}
	handler := bootstrapSetRoleHandler("worker-a-test", "9443", state)

	form := url.Values{"role": {"not-a-real-role"}}
	req := httptest.NewRequest(http.MethodPost, "/setup/role", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if got := state.getRole(); got != "" {
		t.Errorf("state role = %q, want empty — invalid submission must not be stored", got)
	}
}

// TestParseStepParam covers every real input parseStepParam sees: a valid
// step number, a missing/empty value, and an out-of-range or garbage
// value.
func TestParseStepParam(t *testing.T) {
	cases := map[string]int{
		"":             stepRole,
		"1":            stepRole,
		"6":            stepReview,
		"0":            stepRole,
		"7":            stepRole,
		"-3":           stepRole,
		"not-a-number": stepRole,
	}
	for in, want := range cases {
		if got := parseStepParam(in); got != want {
			t.Errorf("parseStepParam(%q) = %d, want %d", in, got, want)
		}
	}
}

// withFakeOutboundAddrDetection swaps detectOutboundAddrFunc for a spy
// returning a fixed address.
func withFakeOutboundAddrDetection(t *testing.T, addr string, err error) {
	t.Helper()
	orig := detectOutboundAddrFunc
	detectOutboundAddrFunc = func(string) (string, error) {
		return addr, err
	}
	t.Cleanup(func() { detectOutboundAddrFunc = orig })
}

func TestNewBootstrapSetupData_AutoFillsAddressWhenNoneSavedYet(t *testing.T) {
	withFakeOutboundAddrDetection(t, "192.0.2.22:9443", nil)
	data := newBootstrapSetupData("host", "9443", &builderState{})
	if data.CurrentAddr != "192.0.2.22:9443" {
		t.Errorf("CurrentAddr = %q, want the detected default", data.CurrentAddr)
	}
}

// TestNewBootstrapSetupData_NeverOverwritesAnAlreadySavedAddress confirms
// auto-fill is a DEFAULT only, never forced.
func TestNewBootstrapSetupData_NeverOverwritesAnAlreadySavedAddress(t *testing.T) {
	withFakeOutboundAddrDetection(t, "192.0.2.99:9443", nil)
	state := &builderState{}
	if err := state.setSelfAddr("10.0.0.5:9443"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := newBootstrapSetupData("host", "9443", state)
	if data.CurrentAddr != "10.0.0.5:9443" {
		t.Errorf("CurrentAddr = %q, want the operator's own saved address, not the detected default", data.CurrentAddr)
	}
}

func TestNewBootstrapSetupData_DetectionFailureLeavesAddressBlank(t *testing.T) {
	withFakeOutboundAddrDetection(t, "", fmt.Errorf("no route"))
	data := newBootstrapSetupData("host", "9443", &builderState{})
	if data.CurrentAddr != "" {
		t.Errorf("CurrentAddr = %q, want empty on a detection failure", data.CurrentAddr)
	}
}

// TestDetectDefaultOutboundAddr_ReturnsHostPairedWithGivenPort is a real,
// unmocked smoke test of the actual detection mechanism.
func TestDetectDefaultOutboundAddr_ReturnsHostPairedWithGivenPort(t *testing.T) {
	addr, err := detectDefaultOutboundAddr("9443")
	if err != nil {
		t.Skipf("no local route available in this test environment: %v", err)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("detectDefaultOutboundAddr returned an unparseable address %q: %v", addr, err)
	}
	if host == "" {
		t.Error("detectDefaultOutboundAddr returned an empty host")
	}
	if port != "9443" {
		t.Errorf("port = %q, want the given listen port 9443", port)
	}
}

func TestSelfAddrFromRequest_UsesRealConnectionLocalAddr(t *testing.T) {
	var got string
	var gotErr error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, gotErr = selfAddrFromRequest(r, "9443")
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET %s: %v", srv.URL, err)
	}
	resp.Body.Close()

	if gotErr != nil {
		t.Fatalf("selfAddrFromRequest returned an error: %v", gotErr)
	}
	host, port, err := net.SplitHostPort(got)
	if err != nil {
		t.Fatalf("selfAddrFromRequest returned an unparseable address %q: %v", got, err)
	}
	if host != "127.0.0.1" {
		t.Errorf("host = %q, want 127.0.0.1 (httptest.Server listens on loopback)", host)
	}
	if port != "9443" {
		t.Errorf("port = %q, want the given control port 9443, not the test server's own ephemeral port", port)
	}
}

func TestSelfAddrFromRequest_FallsBackWithoutARealConnection(t *testing.T) {
	withFakeOutboundAddrDetection(t, "10.0.0.5:9443", nil)
	req := httptest.NewRequest(http.MethodPost, "/setup/role", nil)

	got, err := selfAddrFromRequest(req, "9443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "10.0.0.5:9443" {
		t.Errorf("selfAddrFromRequest = %q, want the fallback-detected address", got)
	}
}

// TestBootstrapSetNetworkHandler_SavesMgmtAndWorkersAndRedirectsToStep4
// and TestBootstrapSetNetworkHandler_EmptyMgmtRejectedInline cover step 3
// (Network).
func TestBootstrapSetNetworkHandler_SavesMgmtAndWorkersAndRedirectsToStep3(t *testing.T) {
	state := &builderState{}
	handler := bootstrapSetNetworkHandler("host", "9443", state)

	form := url.Values{"mgmt": {"eth0"}, "workers": {"ens19", "ens20"}}
	req := httptest.NewRequest(http.MethodPost, "/setup/network", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/?step=3" {
		t.Errorf("Location = %q, want /?step=3", got)
	}
	mgmt, workers := state.getPlatform()
	if mgmt != "eth0" {
		t.Errorf("mgmt = %q, want eth0", mgmt)
	}
	if len(workers) != 2 || workers[0] != "ens19" || workers[1] != "ens20" {
		t.Errorf("workers = %v, want [ens19 ens20]", workers)
	}
}

func TestBootstrapSetNetworkHandler_EmptyMgmtRejectedInline(t *testing.T) {
	state := &builderState{}
	handler := bootstrapSetNetworkHandler("host", "9443", state)

	form := url.Values{"mgmt": {""}}
	req := httptest.NewRequest(http.MethodPost, "/setup/network", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if mgmt, _ := state.getPlatform(); mgmt != "" {
		t.Errorf("mgmt = %q, want empty — a rejected submission must never be stored", mgmt)
	}
}

func TestBootstrapSetMgmtVIPHandler_ValidVIPSavesAndRedirectsToStep4(t *testing.T) {
	state := &builderState{}
	if err := state.setSelfAddr("192.0.2.22:9443"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	withFakeInterfaceDetection(t, "192.0.2.22", "eth0")
	handler := bootstrapSetMgmtVIPHandler("host", "9443", state)

	form := url.Values{"mgmt_vip": {"192.0.2.230/24"}, "vrrp_id": {"77"}}
	req := httptest.NewRequest(http.MethodPost, "/setup/mgmt-vip", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/?step=4" {
		t.Errorf("Location = %q, want /?step=4", got)
	}
	vip, vrrpID, _ := state.getMgmtVIP()
	if vip != "192.0.2.230/24" || vrrpID != 77 {
		t.Errorf("mgmt VIP = %q/%d, want 192.0.2.230/24/77", vip, vrrpID)
	}
}

func TestBootstrapSetMgmtVIPHandler_BlankSkipsAndRedirectsToStep4(t *testing.T) {
	state := &builderState{}
	handler := bootstrapSetMgmtVIPHandler("host", "9443", state)

	form := url.Values{"mgmt_vip": {""}}
	req := httptest.NewRequest(http.MethodPost, "/setup/mgmt-vip", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/?step=4" {
		t.Errorf("Location = %q, want /?step=4", got)
	}
}

func TestBootstrapSetTLSHandler_RedirectsToStep5(t *testing.T) {
	state := &builderState{}
	handler := bootstrapSetTLSHandler("host", "9443", state)

	req := httptest.NewRequest(http.MethodPost, "/setup/tls", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/?step=5" {
		t.Errorf("Location = %q, want /?step=5", got)
	}
}

func TestBootstrapAddNodeHandler_SuccessStaysOnStep5(t *testing.T) {
	state := &builderState{}
	if err := state.setSelfAddr("192.0.2.22:9443"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := state.setRole(config.RoleCore1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	handler := bootstrapAddNodeHandler("host", "9443", state)

	form := url.Values{
		"addr": {"192.0.2.23:9443"},
		"role": {config.RoleCore2},
		"otp":  {"CODE"},
	}
	req := httptest.NewRequest(http.MethodPost, "/setup/nodes", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/?step=5" {
		t.Errorf("Location = %q, want /?step=5 — adding a node stays on the same step", got)
	}
}

// TestBootstrapSetupTmpl_ReviewStepShowsFullSummary checks the review step
// shows what will be built before the operator commits.
func TestBootstrapSetupTmpl_ReviewStepShowsFullSummary(t *testing.T) {
	state := &builderState{}
	if err := state.setRole(config.RoleCore1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := state.setSelfAddr("192.0.2.22:9443"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := state.setPlatform("eth0", []string{"ens19"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := state.addNode("192.0.2.23:9443", config.RoleCore2, "CODE", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	handler := bootstrapSetupHandler("host", "9443", state)

	req := httptest.NewRequest(http.MethodGet, "/?step=6", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	body := rec.Body.String()
	for _, want := range []string{config.RoleCore1, "192.0.2.22:9443", "192.0.2.23:9443", "eth0", "Trunk 1", "ens19", "Create cluster"} {
		if !strings.Contains(body, want) {
			t.Errorf("review step body missing %q: %s", want, body)
		}
	}
}

func TestBuilderState_SetPlatform_RejectsEmptyMgmtAndDedupesWorkers(t *testing.T) {
	b := &builderState{}
	if err := b.setPlatform("", nil); err == nil {
		t.Error("setPlatform(\"\", nil) = nil error, want a rejection")
	}
	if err := b.setPlatform("eth0", []string{"ens19", "ens19", "", "ens20"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mgmt, workers := b.getPlatform()
	if mgmt != "eth0" {
		t.Errorf("mgmt = %q, want eth0", mgmt)
	}
	if len(workers) != 2 || workers[0] != "ens19" || workers[1] != "ens20" {
		t.Errorf("workers = %v, want deduped [ens19 ens20]", workers)
	}
	if err := b.setPlatform("eth0", []string{"eth0"}); err == nil {
		t.Error("setPlatform with mgmt also listed as a worker = nil error, want a rejection")
	}
}

func TestNewBootstrapSetupData_PreChecksDiscoveredCandidatesOnlyWhenNothingSaved(t *testing.T) {
	origDiscover := discoveredInterfacesFunc
	discoveredInterfacesFunc = func() ([]string, error) { return []string{"ens19", "ens20"}, nil }
	t.Cleanup(func() { discoveredInterfacesFunc = origDiscover })

	state := &builderState{}
	data := newBootstrapSetupData("host", "9443", state)
	if len(data.NetworkCandidates) != 2 {
		t.Fatalf("candidates = %v, want 2", data.NetworkCandidates)
	}
	for _, c := range data.NetworkCandidates {
		if !c.Checked {
			t.Errorf("candidate %q not pre-checked with nothing saved yet", c.Name)
		}
	}

	if err := state.setPlatform("eth0", []string{"ens19"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data = newBootstrapSetupData("host", "9443", state)
	for _, c := range data.NetworkCandidates {
		wantChecked := c.Name == "ens19"
		if c.Checked != wantChecked {
			t.Errorf("candidate %q checked = %v, want %v (only the saved selection)", c.Name, c.Checked, wantChecked)
		}
	}
}

func TestBootstrapCommitHandler_RejectsEmptySelfAddress(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "cluster.json")
	state := &builderState{}
	if err := state.setRole(config.RoleCore1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	handler := bootstrapCommitHandler(cfgPath, state)
	req := httptest.NewRequest(http.MethodPost, "/setup/commit", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(cfgPath); err == nil {
		t.Error("cluster.json was written despite an empty self address — must never happen")
	}
}
