// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestWizardBuildScope_AssemblesExpectedFields(t *testing.T) {
	d := wizardData{
		Name: "rw-200", Color: "#e6194b", Parent: "ens19", VLANID: "200", VRRPID: "77",
		VIP: "192.168.200.2/24", Gateway: "192.168.200.1", NodeIP: "192.168.200.22/24",
		DHCPStart: "192.168.200.100", DHCPEnd: "192.168.200.200",
		PreferredWorker: "core-2",
		DHCPOptionsText: "6,8.8.8.8\n66,192.168.1.1",
		DNSRecordsText:  "A|host.lan|192.168.200.50",
	}
	sc, records, err := wizardBuildScope(d)
	if err != nil {
		t.Fatalf("wizardBuildScope: %v", err)
	}
	if sc.Parent != "ens19" || sc.VLANID != 200 || sc.VRRPID != 77 {
		t.Errorf("identity fields mismatch: %+v", sc)
	}
	if sc.VIP != d.VIP || sc.Gateway != d.Gateway || sc.NodeIP != d.NodeIP {
		t.Errorf("network fields mismatch: %+v", sc)
	}
	if sc.DHCPRange != [2]string{d.DHCPStart, d.DHCPEnd} {
		t.Errorf("dhcp range mismatch: %v", sc.DHCPRange)
	}
	if sc.PreferredWorker != "core-2" || sc.Color != "#e6194b" {
		t.Errorf("preferred_worker/color mismatch: %+v", sc)
	}
	if len(sc.DHCPOptions) != 2 || sc.DHCPOptions[0] != "6,8.8.8.8" {
		t.Errorf("dhcp_options mismatch: %v", sc.DHCPOptions)
	}
	if len(records) != 1 || records[0].Name != "host.lan" {
		t.Errorf("dns_records mismatch: %v", records)
	}
}

func TestWizardBuildScope_BadDNSRecordsReturnsError(t *testing.T) {
	d := wizardData{DNSRecordsText: "NOTVALID"}
	if _, _, err := wizardBuildScope(d); err == nil {
		t.Error("expected an error for a malformed dns_records line, got nil")
	}
}

func TestWizardBuildScope_ReplacesDefaultDHCPOptions(t *testing.T) {
	d := wizardData{DHCPOptionsText: "6,1.1.1.1"} // operator edited away from whatever default was shown
	sc, _, err := wizardBuildScope(d)
	if err != nil {
		t.Fatalf("wizardBuildScope: %v", err)
	}
	if len(sc.DHCPOptions) != 1 || sc.DHCPOptions[0] != "6,1.1.1.1" {
		t.Errorf("expected exactly the operator's own edited options, got %v", sc.DHCPOptions)
	}
}

func TestUsedVLANIDsSet(t *testing.T) {
	c := config.Cluster{Scopes: map[string]config.ScopeConfig{
		"a": {Parent: "ens19", VLANID: 200}, "b": {Parent: "ens19", VLANID: 100},
	}}
	used := usedVLANIDsSet(c, "ens19")
	if !used[200] || !used[100] {
		t.Errorf("used = %v, want both 100 and 200", used)
	}
	if used[105] {
		t.Errorf("used[105] = true, want false (never configured)")
	}
}

func TestUsedVLANIDsSet_ScopedToParent(t *testing.T) {
	c := config.Cluster{Scopes: map[string]config.ScopeConfig{
		"a": {Parent: "ens19", VLANID: 10},
	}}
	if used := usedVLANIDsSet(c, "ens20"); used[10] {
		t.Errorf("vlan_id 10 on ens19 must not block vlan_id 10 on ens20, used = %v", used)
	}
	if used := usedVLANIDsSet(c, "ens19"); !used[10] {
		t.Errorf("vlan_id 10 on ens19 must still be excluded on ens19 itself, used = %v", used)
	}
}

func TestFreeVLANIDs_ExcludesUsedIDs(t *testing.T) {
	used := map[int]bool{1: true, 2: true}
	free := freeVLANIDs(used)
	// "0" (untagged) + (2..4094 minus the used "2") = 1 + 4092 = 4093.
	if len(free) != 4093 {
		t.Fatalf("got %d free IDs, want 4093 (1 untagged + 4092 numbered)", len(free))
	}
	if free[0] != "0" {
		t.Errorf("free[0] = %q, want \"0\" (untagged, offered first)", free[0])
	}
	if free[1] != "3" {
		t.Errorf("free[1] = %q, want \"3\" (the first unused numbered ID)", free[1])
	}
	for _, id := range free {
		if id == "1" || id == "2" {
			t.Errorf("expected used IDs excluded, got %v", free)
		}
	}
}

func TestFreeVLANIDs_NeverOffersVLANOne(t *testing.T) {
	free := freeVLANIDs(map[int]bool{})
	for _, id := range free {
		if id == "1" {
			t.Fatalf("freeVLANIDs offered VLAN 1, which is reserved/unusable: %v", free)
		}
	}
	if free[0] != "0" {
		t.Errorf("free[0] = %q, want \"0\" (untagged, offered first)", free[0])
	}
	if free[1] != "2" {
		t.Errorf("free[1] = %q, want \"2\" (the first usable numbered VLAN ID)", free[1])
	}
}

func TestFreeVLANIDs_OffersUntaggedFirstWhenFree(t *testing.T) {
	free := freeVLANIDs(map[int]bool{})
	if len(free) == 0 || free[0] != "0" {
		t.Fatalf("free[0] = %v, want \"0\" as the first entry when untagged is free", free)
	}
}

// TestFreeVLANIDs_ExcludesUntaggedWhenAlreadyUsed confirms exactly one
// untagged (vlan_id 0) scope is allowed per parent.
func TestFreeVLANIDs_ExcludesUntaggedWhenAlreadyUsed(t *testing.T) {
	free := freeVLANIDs(map[int]bool{0: true})
	for _, id := range free {
		if id == "0" {
			t.Fatalf("freeVLANIDs offered \"0\" (untagged) even though this parent already has one: %v", free)
		}
	}
}

// TestUsedVRRPIDsSet_IncludesMgmtVIP pins that the management VIP's own
// VRRP ID is reserved too, not just scopes'.
func TestUsedVRRPIDsSet_IncludesMgmtVIP(t *testing.T) {
	c := config.Cluster{
		MgmtVIP: &config.MgmtVIPConfig{VRRPID: 60},
		Scopes:  map[string]config.ScopeConfig{"office": {VRRPID: 50}},
	}
	used := usedVRRPIDsSet(c)
	if !used[60] || !used[50] {
		t.Errorf("used = %v, want both 50 (scope) and 60 (mgmt VIP)", used)
	}
}

func TestFreeVRRPIDs_ExcludesUsedIDs(t *testing.T) {
	used := map[int]bool{1: true, 2: true}
	free := freeVRRPIDs(used)
	if len(free) != 253 {
		t.Fatalf("got %d free IDs, want 253 (255 - 2 used)", len(free))
	}
	if free[0] != "3" {
		t.Errorf("free[0] = %q, want \"3\" (the first unused ID)", free[0])
	}
	for _, id := range free {
		if id == "1" || id == "2" {
			t.Errorf("expected used IDs excluded, got %v", free)
		}
	}
}

func TestBareIPFromVIPAndOctet(t *testing.T) {
	if got := bareIPFromVIPAndOctet("192.168.105.2/24", "1"); got != "192.168.105.1" {
		t.Errorf("got %q, want 192.168.105.1 (bare IP, no CIDR prefix)", got)
	}
	if got := bareIPFromVIPAndOctet("not-a-vip", "1"); got != "" {
		t.Errorf("got %q, want empty for an unparsable VIP", got)
	}
	if got := bareIPFromVIPAndOctet("192.168.105.2/24", "not-a-number"); got != "" {
		t.Errorf("got %q, want empty for a bad octet", got)
	}
}

func TestTemplateJS_SafeForInlineScript(t *testing.T) {
	body := "line1\nline2 with \"quotes\" and </script> inside"
	out := templateJS(body)
	if strings.Contains(out, "</script>") {
		t.Errorf("templateJS output must not contain a literal </script>, got: %s", out)
	}
	if !strings.HasPrefix(out, `"`) || !strings.HasSuffix(out, `"`) {
		t.Errorf("expected a JSON/JS string literal, got: %s", out)
	}
}

func TestValidateTemplateBody(t *testing.T) {
	cases := []struct {
		name    string
		kind    TemplateKind
		body    string
		wantErr bool
	}{
		{"valid dhcp", TemplateKindDHCP, "6,8.8.8.8\n66,192.168.1.1", false},
		{"dhcp option with an embedded \\r injects a second directive", TemplateKindDHCP, "6,8.8.8.8\rdhcp-option=99,injected", true},
		{"valid dns", TemplateKindDNS, "A|host.lan|192.168.1.50", false},
		{"invalid dns — unknown type", TemplateKindDNS, "BOGUS|host.lan|1.2.3.4", true},
		{"invalid dns — too few fields", TemplateKindDNS, "A|host.lan", true}, // needs at least TYPE|NAME|VALUE
		{"unknown kind", TemplateKind("bogus"), "x", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTemplateBody(tc.kind, tc.body)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateTemplateBody(%q, %q) error = %v, wantErr %v", tc.kind, tc.body, err, tc.wantErr)
			}
		})
	}
}

// fakeWizardNode spins up one fake cluster node answering exactly what the
// wizard's handler needs.
func fakeWizardNode(t *testing.T, pushedBody *string) *WebConfig {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				ClusterID: "test", NodeID: "worker-a-test", Role: "core-1",
				ControlAddr:        "10.0.0.1:9443",
				Platform:           &config.Platform{Mgmt: "eth0", Workers: []string{"ens19", "ens20"}},
				DefaultDHCPOptions: []string{"6,8.8.8.8"},
				GlobalDNSRecords:   []config.DNSRecord{{Type: "A", Name: "ntp.lan", Value: "192.168.0.10"}},
				Scopes: map[string]config.ScopeConfig{
					"office": {VLANID: 100, VRRPID: 51, Parent: "ens19", PreferredWorker: "core-1",
						VIP: "172.16.100.1/24", Gateway: "172.16.100.1"},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			body, _ := io.ReadAll(r.Body)
			*pushedBody = string(body)
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	return &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
}

func TestHandleScopeWizard_StepByStepThenSubmit(t *testing.T) {
	var pushedBody string
	cfg := fakeWizardNode(t, &pushedBody)
	h := handleScopeWizard(newConfigRef(cfg), &TemplateStore{})

	get := httptest.NewRequest(http.MethodGet, "/scopes/wizard", nil)
	rec := httptest.NewRecorder()
	h(rec, get)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "step 1 of 4") {
		t.Fatalf("GET /scopes/wizard: code=%d body=%s", rec.Code, rec.Body.String())
	}

	step := func(form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/scopes/wizard", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("action=%s: unexpected status %d, body=%s", form.Get("action"), rec.Code, rec.Body.String())
		}
		return rec
	}

	base := url.Values{
		"name": {"rw-105"}, "color": {"#e6194b"}, "parent": {"ens20"},
		"vlan_id": {"105"}, "vrrp_id": {"55"},
		"vip": {"192.168.105.2/24"}, "gateway": {"192.168.105.1"}, "node_ip": {""},
		"dhcp_start": {"192.168.105.100"}, "dhcp_end": {"192.168.105.200"},
		"preferred_worker": {"core-1"},
	}

	f2 := url.Values{}
	for k, v := range base {
		f2[k] = v
	}
	f2.Set("action", "step2")
	rec2 := step(f2)
	if !strings.Contains(rec2.Body.String(), "6,8.8.8.8") {
		t.Errorf("step 2 should pre-fill the cluster's default_dhcp_options, body=%s", rec2.Body.String())
	}

	// Operator overrides the pre-filled default -> step3.
	f3 := url.Values{}
	for k, v := range base {
		f3[k] = v
	}
	f3.Set("action", "step3")
	f3.Set("dhcp_options", "6,1.1.1.1")
	rec3 := step(f3)
	if !strings.Contains(rec3.Body.String(), "ntp.lan") {
		t.Errorf("step 3 should show the cluster's global_dns_records as read-only reference, body=%s", rec3.Body.String())
	}

	// -> step4/review, with one new DNS record for this scope alone.
	f4 := url.Values{}
	for k, v := range base {
		f4[k] = v
	}
	f4.Set("action", "review")
	f4.Set("dhcp_options", "6,1.1.1.1")
	f4.Set("dns_records", "A|rw105-host.lan|192.168.105.50")
	rec4 := step(f4)
	if !strings.Contains(rec4.Body.String(), "step 4 of 4") {
		t.Fatalf("expected the review step to render, body=%s", rec4.Body.String())
	}
	for _, want := range []string{
		"host-record=rw105-host.lan,192.168.105.50",
	} {
		if !strings.Contains(rec4.Body.String(), want) {
			t.Errorf("expected the render preview to contain %q, body=%s", want, rec4.Body.String())
		}
	}
	for _, notWant := range []string{
		"dhcp-range=192.168.105.100,192.168.105.200",
		"dhcp-option=6,1.1.1.1",
	} {
		if strings.Contains(rec4.Body.String(), notWant) {
			t.Errorf("expected the render preview to OMIT %q (no node_ip set — this scope genuinely gets no DHCP content in the real shared config), body=%s", notWant, rec4.Body.String())
		}
	}

	// -> submit.
	fSubmit := url.Values{}
	for k, v := range f4 {
		fSubmit[k] = v
	}
	fSubmit.Set("action", "submit")
	step(fSubmit)

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	if _, ok := pushed.Scopes["office"]; !ok {
		t.Error("expected the pre-existing scope \"office\" to survive untouched")
	}
	got, ok := pushed.Scopes["rw-105"]
	if !ok {
		t.Fatalf("expected the wizard-created scope \"rw-105\" in the pushed candidate, got scopes: %v", pushed.Scopes)
	}
	if got.Parent != "ens20" || got.VLANID != 105 || got.VRRPID != 55 {
		t.Errorf("identity mismatch: %+v", got)
	}
	if len(got.DHCPOptions) != 1 || got.DHCPOptions[0] != "6,1.1.1.1" {
		t.Errorf("expected the operator's overridden dhcp_options, got %v", got.DHCPOptions)
	}
	if len(got.DNSRecords) != 1 || got.DNSRecords[0].Name != "rw105-host.lan" {
		t.Errorf("expected the scope's own dns_records, got %v", got.DNSRecords)
	}
	if len(pushed.GlobalDNSRecords) != 1 {
		t.Errorf("expected global_dns_records untouched at 1 entry, got %v", pushed.GlobalDNSRecords)
	}
}

func TestHandleScopeWizard_ReviewSurfacesDNSClientMismatchWarning(t *testing.T) {
	var pushedBody string
	cfg := fakeWizardNode(t, &pushedBody)
	h := handleScopeWizard(newConfigRef(cfg), &TemplateStore{})

	form := url.Values{
		"action": {"review"},
		"name":   {"rw-106"}, "parent": {"ens20"}, "vlan_id": {"106"}, "vrrp_id": {"56"},
		"vip": {"192.168.106.2/24"}, "gateway": {"192.168.106.1"},
		"dhcp_start": {"192.168.106.100"}, "dhcp_end": {"192.168.106.200"},
		"preferred_worker": {"core-1"},
		"dhcp_options":     {"6,1.1.1.1"}, // overrides client DNS server away from local dnsmasq
		"dns_records":      {"A|rw106-host.lan|192.168.106.50"},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/wizard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, req)

	if !strings.Contains(rec.Body.String(), "defines local DNS name(s)") {
		t.Errorf("expected the local-DNS-vs-client-DNS warning to surface on the review step, body=%s", rec.Body.String())
	}
}

func TestHandleScopeWizard_AutoPreferredWorkerResolvesToLessLoaded(t *testing.T) {
	var pushedBody string
	cfg := fakeWizardNode(t, &pushedBody)
	h := handleScopeWizard(newConfigRef(cfg), &TemplateStore{})

	base := url.Values{
		"name": {"rw-107"}, "parent": {"ens20"}, "vlan_id": {"107"}, "vrrp_id": {"57"},
		"vip": {"192.168.107.2/24"}, "gateway": {"192.168.107.1"},
		"dhcp_start": {"192.168.107.100"}, "dhcp_end": {"192.168.107.200"},
		"preferred_worker": {"auto"},
	}

	reviewForm := url.Values{}
	for k, v := range base {
		reviewForm[k] = v
	}
	reviewForm.Set("action", "review")
	req := httptest.NewRequest(http.MethodPost, "/scopes/wizard", strings.NewReader(reviewForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, req)
	if !strings.Contains(rec.Body.String(), "auto &rarr; core-2") {
		t.Errorf("expected the review step to show the auto resolution (auto -> core-2), body=%s", rec.Body.String())
	}

	submitForm := url.Values{}
	for k, v := range base {
		submitForm[k] = v
	}
	submitForm.Set("action", "submit")
	req2 := httptest.NewRequest(http.MethodPost, "/scopes/wizard", strings.NewReader(submitForm.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	h(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("submit: unexpected status %d, body=%s", rec2.Code, rec2.Body.String())
	}

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	got, ok := pushed.Scopes["rw-107"]
	if !ok {
		t.Fatalf("expected scope rw-107 in the pushed candidate, got: %v", pushed.Scopes)
	}
	if got.PreferredWorker != "core-2" {
		t.Errorf("expected \"auto\" to resolve to core-2 (less loaded), got %q", got.PreferredWorker)
	}
}

func TestHandleScopeWizard_ReviewOnlyShowsFindingsForTheNewScope(t *testing.T) {
	var pushedBody string
	cfg := fakeWizardNode(t, &pushedBody)
	h := handleScopeWizard(newConfigRef(cfg), &TemplateStore{})

	form := url.Values{
		"action": {"review"},
		"name":   {"rw-108"}, "parent": {"ens20"}, "vlan_id": {"108"}, "vrrp_id": {"58"},
		"vip": {"192.168.108.2/24"}, "gateway": {"192.168.108.1"}, // VIP != gateway — no warning for the new scope itself
		"dhcp_start": {"192.168.108.100"}, "dhcp_end": {"192.168.108.200"},
		"preferred_worker": {"core-1"},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/wizard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, `scope &#34;office&#34;`) || strings.Contains(body, `scope "office"`) {
		t.Errorf("review step must not show a DIFFERENT scope's own findings (office's own vip-equals-gateway warning), body=%s", body)
	}
	if !strings.Contains(body, `scope &#34;rw-108&#34;: defines local DNS name(s)`) {
		t.Errorf("expected rw-108's own real warning (inherited from fixture DefaultDHCPOptions+GlobalDNSRecords) to still show, body=%s", body)
	}
}

func TestWizardTemplateButtonsHTML_InsertOnclickIsValidHTMLAttribute(t *testing.T) {
	rows := []templateRow{
		{Template: Template{Name: "dante", Color: "#c0c0c0", Body: "option:ntp-server,192.168.10.1"}},
	}
	out := string(wizardTemplateButtonsHTML(TemplateKindDHCP, "w_dhcp_options", rows))

	if !strings.Contains(out, `onclick="wizInsert_w_dhcp_options(&#34;option:ntp-server,192.168.10.1&#34;)"`) {
		t.Errorf("onclick attribute not properly HTML-escaped, got: %s", out)
	}
	// The unescaped pattern must never appear.
	if strings.Contains(out, `onclick="wizInsert_w_dhcp_options("option`) {
		t.Errorf("onclick attribute contains a raw unescaped quote, breaking the HTML attribute: %s", out)
	}
}

func TestWizardTemplateButtonsHTML_CollisionCheckPresentForDHCPAndDNS(t *testing.T) {
	rows := []templateRow{{Template: Template{Name: "t", Body: "x"}}}
	dhcp := string(wizardTemplateButtonsHTML(TemplateKindDHCP, "w_dhcp_options", rows))
	if !strings.Contains(dhcp, `l.indexOf(",")`) {
		t.Errorf("expected DHCP's own comma-split key extraction present, got: %s", dhcp)
	}
	if !strings.Contains(dhcp, "confirm(") {
		t.Errorf("expected a confirm() gate wired into the DHCP insert function, got: %s", dhcp)
	}

	dns := string(wizardTemplateButtonsHTML(TemplateKindDNS, "w_dns_records", rows))
	if !strings.Contains(dns, `l.split("|")`) {
		t.Errorf("expected DNS's own pipe-split key extraction present, got: %s", dns)
	}
	if !strings.Contains(dns, "confirm(") {
		t.Errorf("expected a confirm() gate wired into the DNS insert function, got: %s", dns)
	}
}

// TestWizardTemplateReplaceButtonsHTML_WarnsBeforeOverwriting pins the
// replace-type field's own collision fix.
func TestWizardTemplateReplaceButtonsHTML_WarnsBeforeOverwriting(t *testing.T) {
	rows := []templateRow{{Template: Template{Name: "t", Body: "172.17.42.1"}}}
	out := string(wizardTemplateReplaceButtonsHTML("w_client_dns_server", rows))
	if !strings.Contains(out, "confirm(") {
		t.Errorf("expected a confirm() gate before replacing an existing value, got: %s", out)
	}
	if !strings.Contains(out, `el.value&&el.value!==body`) {
		t.Errorf("expected the gate to only fire when a DIFFERENT non-empty value is already present, got: %s", out)
	}
}

func TestHandleScopeWizard_Step2PrefillsGatewayAndDHCPRangeFromVIP(t *testing.T) {
	cfg := fakeWizardNode(t, nil)
	h := handleScopeWizard(newConfigRef(cfg), &TemplateStore{})

	form := url.Values{
		"action": {"step2"},
		"name":   {"rw-109"}, "parent": {"ens20"}, "vlan_id": {"109"}, "vrrp_id": {"59"},
		"vip": {"192.168.109.2/24"}, "preferred_worker": {"core-1"},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/wizard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, req)

	body := rec.Body.String()
	for _, want := range []string{
		`name="gateway" value="192.168.109.1"`,
		`name="dhcp_start" value="192.168.109.100"`,
		`name="dhcp_end" value="192.168.109.200"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected step 2 to pre-fill %q, body=%s", want, body)
		}
	}
}

func TestHandleScopeWizard_GatewayFieldAcceptsMultiValuePattern(t *testing.T) {
	cfg := fakeWizardNode(t, nil)
	h := handleScopeWizard(newConfigRef(cfg), &TemplateStore{})

	form := url.Values{"action": {"step2"}, "name": {"rw-1"}, "vlan_id": {"1"}, "vrrp_id": {"1"}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/wizard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `name="gateway" value="" pattern="`+ipGatewayPattern+`"`) {
		t.Errorf("expected the gateway field to carry the multi-value GatewayPattern, body=%s", body)
	}
}

func TestHandleScopeWizard_VIPSuffixWiring(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				ClusterID: "test", NodeID: "worker-a-test", Role: "core-1",
				ControlAddr:   "10.0.0.1:9443",
				Platform:      &config.Platform{Mgmt: "eth0", Workers: []string{"ens19", "ens20"}},
				ScopeDefaults: &config.ScopeDefaults{VIPSuffix: "50"},
			})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	h := handleScopeWizard(newConfigRef(cfg), &TemplateStore{})

	req := httptest.NewRequest(http.MethodGet, "/scopes/wizard", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /scopes/wizard: code=%d body=%s", rec.Code, body)
	}
	if !strings.Contains(body, `data-vip-suffix="50"`) {
		t.Errorf("expected the vip field to carry data-vip-suffix=\"50\", body=%s", body)
	}
	if !strings.Contains(body, `oninput="autoVIPFromNetwork(this);checkVIPSubnetOverlap(this)"`) {
		t.Errorf("expected the vip field wired to autoVIPFromNetwork and checkVIPSubnetOverlap, body=%s", body)
	}
	if !strings.Contains(body, "function autoVIPFromNetwork(input)") {
		t.Errorf("expected the autoVIPFromNetwork script to be included, body=%s", body)
	}
}

func TestHandleScopeWizard_SubnetOverlapWiring(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				ClusterID: "test", NodeID: "worker-a-test", Role: "core-1",
				ControlAddr: "10.0.0.1:9443",
				Platform:    &config.Platform{Mgmt: "eth0", Workers: []string{"ens19", "ens20"}},
				Scopes: map[string]config.ScopeConfig{
					"test2": {VIP: "192.168.10.254/23"},
				},
			})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	h := handleScopeWizard(newConfigRef(cfg), &TemplateStore{})

	req := httptest.NewRequest(http.MethodGet, "/scopes/wizard", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /scopes/wizard: code=%d body=%s", rec.Code, body)
	}
	if !strings.Contains(body, `data-other-subnets="test2|192.168.10.254/23"`) {
		t.Errorf("expected the vip field to carry the other scope's subnet, body=%s", body)
	}
	if !strings.Contains(body, "function checkVIPSubnetOverlap(input)") {
		t.Errorf("expected the checkVIPSubnetOverlap script to be included, body=%s", body)
	}
}

func TestHandleScopeWizard_VLANIDIsAFindAsYouTypeCombobox(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				ClusterID: "test", NodeID: "worker-a-test", Role: "core-1",
				ControlAddr: "10.0.0.1:9443",
				Platform:    &config.Platform{Mgmt: "eth0", Workers: []string{"ens19", "ens20"}},
			})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	h := handleScopeWizard(newConfigRef(cfg), &TemplateStore{})

	req := httptest.NewRequest(http.MethodGet, "/scopes/wizard", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `<select name="vlan_id" class="js-combo">`) {
		t.Errorf("expected the vlan_id select to carry class=\"js-combo\", body=%s", body)
	}
}

// TestHandleScopeWizard_VRRPIDIsAFindAsYouTypeCombobox.
func TestHandleScopeWizard_VRRPIDIsAFindAsYouTypeCombobox(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				ClusterID: "test", NodeID: "worker-a-test", Role: "core-1",
				ControlAddr: "10.0.0.1:9443",
				Platform:    &config.Platform{Mgmt: "eth0", Workers: []string{"ens19", "ens20"}},
			})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	h := handleScopeWizard(newConfigRef(cfg), &TemplateStore{})

	req := httptest.NewRequest(http.MethodGet, "/scopes/wizard", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `<select name="vrrp_id" class="js-combo">`) {
		t.Errorf("expected the vrrp_id select to carry class=\"js-combo\", body=%s", body)
	}
}

func TestHandleScopeWizard_SubnetFieldWiring(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				ClusterID: "test", NodeID: "worker-a-test", Role: "core-1",
				ControlAddr: "10.0.0.1:9443",
				Platform:    &config.Platform{Mgmt: "eth0", Workers: []string{"ens19", "ens20"}},
			})
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	h := handleScopeWizard(newConfigRef(cfg), &TemplateStore{})

	req := httptest.NewRequest(http.MethodGet, "/scopes/wizard", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `id="w_subnet" name="subnet"`) {
		t.Errorf("expected a dedicated subnet input field, body=%s", body)
	}
	if !strings.Contains(body, `oninput="autoVIPFromSubnet(this)"`) {
		t.Errorf("expected the subnet field wired to autoVIPFromSubnet, body=%s", body)
	}
	if !strings.Contains(body, "function autoVIPFromSubnet(input)") {
		t.Errorf("expected the autoVIPFromSubnet script to be included, body=%s", body)
	}
	if strings.Contains(body, "vipEl.value = input.value") {
		t.Error("autoVIPFromSubnet copies the raw subnet into the VIP field — with no VIP suffix configured that leaves the network address (x.x.x.0/24) as the suggested VIP")
	}

	form := url.Values{
		"action": {"step2"}, "name": {"office2"}, "vlan_id": {"5"}, "vrrp_id": {"1"},
		"subnet": {"192.168.55.0/24"}, "vip": {"192.168.55.254/24"},
		"preferred_worker": {"auto"},
	}
	req2 := httptest.NewRequest(http.MethodPost, "/scopes/wizard", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	h(rec2, req2)
	body2 := rec2.Body.String()
	if !strings.Contains(body2, `name="subnet" value="192.168.55.0/24"`) {
		t.Errorf("expected subnet carried forward as a hidden field on step 2, body=%s", body2)
	}
}

func TestHandleScopeWizard_ClientDNSServerDefaultsToDnshived(t *testing.T) {
	cfg := fakeWizardNode(t, new(string))
	h := handleScopeWizard(newConfigRef(cfg), &TemplateStore{})

	form := url.Values{"action": {"step3"}, "name": {"rw-1"}, "vlan_id": {"1"}, "vrrp_id": {"1"}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/wizard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `value="dnshived" checked`) {
		t.Errorf("expected the dnshived radio checked by default, body=%s", body)
	}
	if !strings.Contains(body, `id="w_client_dns_server" name="client_dns_server" value="" placeholder="e.g. 172.17.42.1 or 172.17.42.1,172.17.42.2" disabled>`) {
		t.Errorf("expected the override input disabled and empty by default, body=%s", body)
	}
}

func TestHandleScopeWizard_ClientDNSServerOtherSubmitsWithScope(t *testing.T) {
	var pushedBody string
	cfg := fakeWizardNode(t, &pushedBody)
	h := handleScopeWizard(newConfigRef(cfg), &TemplateStore{})

	form := url.Values{
		"action": {"submit"},
		"name":   {"rw-111"}, "parent": {"ens20"}, "vlan_id": {"111"}, "vrrp_id": {"61"},
		"vip": {"192.168.111.2/24"}, "gateway": {"192.168.111.1"},
		"dhcp_start": {"192.168.111.100"}, "dhcp_end": {"192.168.111.200"},
		"preferred_worker":  {"core-1"},
		"client_dns_choice": {"other"}, "client_dns_server": {"172.17.42.1"},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/wizard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("submit: unexpected status %d, body=%s", rec.Code, rec.Body.String())
	}

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	got, ok := pushed.Scopes["rw-111"]
	if !ok {
		t.Fatalf("expected scope rw-111 in the pushed candidate, got: %v", pushed.Scopes)
	}
	if got.ClientDNSServer != "172.17.42.1" {
		t.Errorf("expected client_dns_server = 172.17.42.1, got %q", got.ClientDNSServer)
	}
}

func TestHandleScopeWizard_ClientDNSServerDnshivedChoiceWipesOverride(t *testing.T) {
	var pushedBody string
	cfg := fakeWizardNode(t, &pushedBody)
	h := handleScopeWizard(newConfigRef(cfg), &TemplateStore{})

	form := url.Values{
		"action": {"submit"},
		"name":   {"rw-112"}, "parent": {"ens20"}, "vlan_id": {"112"}, "vrrp_id": {"62"},
		"vip": {"192.168.112.2/24"}, "gateway": {"192.168.112.1"},
		"dhcp_start": {"192.168.112.100"}, "dhcp_end": {"192.168.112.200"},
		"preferred_worker":  {"core-1"},
		"client_dns_choice": {"dnshived"}, "client_dns_server": {"172.17.42.1"},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/wizard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("submit: unexpected status %d, body=%s", rec.Code, rec.Body.String())
	}

	var pushed configPushPayload
	if err := json.Unmarshal([]byte(pushedBody), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, pushedBody)
	}
	got := pushed.Scopes["rw-112"]
	if got.ClientDNSServer != "" {
		t.Errorf("expected client_dns_server wiped by the dnshived choice, got %q", got.ClientDNSServer)
	}
}

func TestHandleScopeWizard_ClientDNSServerSurvivesReviewRoundTrip(t *testing.T) {
	cfg := fakeWizardNode(t, new(string))
	h := handleScopeWizard(newConfigRef(cfg), &TemplateStore{})

	form := url.Values{
		"action": {"review"},
		"name":   {"rw-113"}, "parent": {"ens20"}, "vlan_id": {"113"}, "vrrp_id": {"63"},
		"vip": {"192.168.113.2/24"}, "gateway": {"192.168.113.1"},
		"dhcp_start": {"192.168.113.100"}, "dhcp_end": {"192.168.113.200"},
		"preferred_worker":  {"core-1"},
		"client_dns_choice": {"other"}, "client_dns_server": {"172.17.42.1,172.17.42.2"},
	}
	req := httptest.NewRequest(http.MethodPost, "/scopes/wizard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `<input type="hidden" name="client_dns_server" value="172.17.42.1,172.17.42.2">`) {
		t.Errorf("expected the review step's hidden field to carry the override forward, body=%s", body)
	}
	if !strings.Contains(body, "172.17.42.1,172.17.42.2</td></tr>") {
		t.Errorf("expected the review table to show the resolved override value, body=%s", body)
	}
}

func TestBareIPFromVIPAndOctet_OnlyOnA24(t *testing.T) {
	cases := map[string]string{
		"10.19.101.254/24": "10.19.101.200",
		"10.19.100.254/23": "",
		"10.19.101.126/25": "",
	}
	for vip, want := range cases {
		if got := bareIPFromVIPAndOctet(vip, "200"); got != want {
			t.Errorf("bareIPFromVIPAndOctet(%q, 200) = %q, want %q", vip, got, want)
		}
	}
}

func TestSuffixAutofillScripts_OnlyMatchA24(t *testing.T) {
	for name, js := range map[string]string{"wizard": wizardVIPScriptHTML, "scope editor": scopeEditorScriptHTML} {
		if strings.Contains(js, `\.0\/(\d{1,2})$`) || strings.Contains(js, `/^(\d+\.\d+\.\d+)\.\d+/);`) {
			t.Errorf("%s script still applies a last-octet suffix to any prefix length", name)
		}
	}
}
