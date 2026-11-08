// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/probepin"
)

func renderTLSStates(t *testing.T, states []probeTLSState) string {
	t.Helper()
	data := probesPageData{
		ProbeHostNames: []string{"probe"},
		probeManagementData: probeManagementData{
			NodeProbeHosts:        []NodeConfig{{Name: "probe", Addr: "192.0.2.5:9444"}},
			ProbeHostDisplayNames: map[string]string{}, ProbeTLSStates: states,
		},
	}
	var buf strings.Builder
	if err := probesTmpl.Execute(&buf, data); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestProbesTmpl_TLSStates(t *testing.T) {
	fp := "sha256:" + strings.Repeat("ab", 32)
	unpinned := renderTLSStates(t, []probeTLSState{{Name: "probe", Addr: "192.0.2.5:9444", PlainOpen: true}})
	for _, want := range []string{"not pinned", "open (unencrypted)", `action="/probes/pin-now"`} {
		if !strings.Contains(unpinned, want) {
			t.Errorf("unpinned probe: expected %q", want)
		}
	}
	if strings.Contains(unpinned, `action="/probes/tls/upload"`) {
		t.Error("an unpinned probe must not offer a certificate upload: the key would cross an unencrypted connection")
	}

	open := renderTLSStates(t, []probeTLSState{{Name: "probe", Addr: "192.0.2.5:9444", Pinned: true, Fingerprint: fp, PlainKnown: true, PlainOpen: true}})
	for _, want := range []string{"pinned", fp, `action="/probes/plain-http"`, `action="/probes/tls/upload"`, `action="/probes/unpin"`} {
		if !strings.Contains(open, want) {
			t.Errorf("pinned probe with the plain port open: expected %q", want)
		}
	}

	closed := renderTLSStates(t, []probeTLSState{{Name: "probe", Addr: "192.0.2.5:9444", Pinned: true, Fingerprint: fp, PlainKnown: true, PlainOpen: false}})
	if !strings.Contains(closed, `class="ok">closed`) {
		t.Error("a closed plain port must read as closed")
	}
	if strings.Contains(closed, `action="/probes/unpin"`) || strings.Contains(closed, `action="/probes/plain-http"`) {
		t.Error("once the plain port is closed there is no unpin: it would cut the probe off")
	}
}

func TestHandleProbePlainHTTP_RefusesToCloseAnUnpinnedProbe(t *testing.T) {
	ref := newConfigRef(&WebConfig{ProbeHosts: []NodeConfig{{Name: "probe", Addr: "192.0.2.5:9444"}}})
	form := url.Values{"addr": {"192.0.2.5:9444"}, "enabled": {"0"}}
	r := httptest.NewRequest(http.MethodPost, "/probes/plain-http", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleProbePlainHTTP(ref)(w, r)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: closing the plain port of an unpinned probe would cut it off", w.Code)
	}
}

func TestHandleProbeCertUpload_RefusesAnUnpinnedProbeBeforeSendingAKey(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	ref := newConfigRef(&WebConfig{ProbeHosts: []NodeConfig{{Name: "probe", Addr: addr}}})
	form := url.Values{"addr": {addr}, "cert_pem": {"x"}, "key_pem": {"y"}}
	r := httptest.NewRequest(http.MethodPost, "/probes/tls/upload", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleProbeCertUpload("/nonexistent", ref)(w, r)

	if w.Code != http.StatusConflict || hit {
		t.Fatalf("status %d, probe contacted %v: a private key must never be sent to an unpinned probe", w.Code, hit)
	}
}

func TestPushProbeHostCertificate_ReturnsTheNewFingerprintAndRelaysTheProbesError(t *testing.T) {
	fp := "sha256:" + strings.Repeat("cd", 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			CertPEM string `json:"cert_pem"`
			KeyPEM  string `json:"key_pem"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if in.CertPEM == "bad" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "the certificate expired"})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "tls_fingerprint": fp})
	}))
	defer srv.Close()
	node := NodeConfig{Name: "probe", Addr: strings.TrimPrefix(srv.URL, "http://"), AdminToken: "tok"}

	got, err := pushProbeHostCertificate(node, "good", "key")
	if err != nil || got != fp || !probepin.Valid(got) {
		t.Fatalf("got %q, %v, want %s", got, err, fp)
	}
	if _, err := pushProbeHostCertificate(node, "bad", "key"); err == nil || !strings.Contains(err.Error(), "the certificate expired") {
		t.Fatalf("err = %v, want the probe's reason", err)
	}
}

func TestClosePlainAfterAdopt_WithoutAProvenFingerprintItLeavesTheProbeReachable(t *testing.T) {
	msg := closePlainAfterAdopt(NodeConfig{Name: "probe", Addr: "192.0.2.5:9444"})
	if !strings.Contains(msg, "stays on plain HTTP") {
		t.Errorf("message %q, want it to say the probe stays reachable and how to pin it", msg)
	}
}

func TestFetchProbeTLSInfo_UsesThePublicEndpointWithoutAnyToken(t *testing.T) {
	fp := "sha256:" + strings.Repeat("ef", 32)
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = sawAuth || r.Header.Get("Authorization") != ""
		switch r.URL.Path {
		case "/api/v1/tls-info":
			json.NewEncoder(w).Encode(map[string]string{"tls_port": "9445", "tls_fingerprint": fp})
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	info, err := fetchProbeTLSInfo(NodeConfig{Name: "probe", Addr: strings.TrimPrefix(srv.URL, "http://"), AdminToken: "secret"})

	if err != nil || info.TLSFingerprint != fp || info.TLSPort != "9445" {
		t.Fatalf("info %+v err %v, want the fingerprint from tls-info", info, err)
	}
	if sawAuth {
		t.Error("no token may be sent over the unencrypted connection to read a public fingerprint")
	}
}

func TestFetchProbeTLSInfo_OlderProbeFallsBackToStatusAndSaysWhyWhenItNeedsAToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/status" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	_, err := fetchProbeTLSInfo(NodeConfig{Name: "probe", Addr: strings.TrimPrefix(srv.URL, "http://")})

	if err == nil || !strings.Contains(err.Error(), "needs an upgrade") {
		t.Fatalf("err = %v, want it to say the probe needs an upgrade", err)
	}
}

func TestManualProbeTable_ButtonsAreReadableAndTheAddBoxFollowsTheServedRule(t *testing.T) {
	render := func(served bool) string {
		data := probesPageData{
			ProbeHostNames: []string{"probe"},
			probeManagementData: probeManagementData{
				ProbeHostDisplayNames: map[string]string{},
				ManualProbeHosts: []manualProbeHost{{Name: "probe", Addr: "192.0.2.5:9444", Rows: []manualProbeRow{
					{Name: "seg", Interface: "ens18", VLAN: "untagged", ResultText: "ROGUE 10.0.0.9", ResultClass: "crit", Served: served,
						Chips: []serverChip{{Server: "10.0.0.9", Label: "unknown", Class: "crit", Action: "ack", CanToggle: true}}},
				}}},
			},
		}
		var buf strings.Builder
		if err := probesTmpl.Execute(&buf, data); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	open, served := render(false), render(true)
	if !strings.Contains(open, `class="btn-sm"`) {
		t.Error("the chip buttons need the small-button class")
	}
	for _, page := range []string{open, served} {
		if strings.Contains(page, `class="dim" style="font-size`) {
			t.Error("a muted-text class on a button makes grey text on the blue button: unreadable")
		}
	}
	if !strings.Contains(open, `placeholder="add address"`) {
		t.Error("a segment without a scope offers an add-address box")
	}
	if strings.Contains(served, `placeholder="add address"`) {
		t.Error("a served segment never accepts a second DHCP server: no add box")
	}
}

func TestHandleManualProbeAck_RefusesWhatIsNotAnIPv4Address(t *testing.T) {
	ref := newConfigRef(&WebConfig{ProbeHosts: []NodeConfig{{Name: "probe", Addr: "192.0.2.5:9444"}}})
	for _, server := range []string{"", "not-an-ip", "fe80::1", "10.0.0.1; drop"} {
		form := url.Values{"addr": {"192.0.2.5:9444"}, "name": {"seg"}, "server": {server}, "action": {"ack"}}
		r := httptest.NewRequest(http.MethodPost, "/probes/manual/ack", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		handleManualProbeAck(ref)(w, r)

		if w.Code != http.StatusBadRequest {
			t.Errorf("server %q: status %d, want 400", server, w.Code)
		}
	}
}

func tlsProbeFor(t *testing.T, h http.HandlerFunc) (NodeConfig, string, func()) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	u, _ := url.Parse(srv.URL)
	fp := probepin.Fingerprint(srv.Certificate().Raw)
	return NodeConfig{Name: "probe", Addr: "127.0.0.1:1", TLSPort: u.Port()}, fp, srv.Close
}

func TestCheckPinnedTLS_TheHandshakeIsTheProofSoATokenProtectedAnswerPasses(t *testing.T) {
	host, fp, closeSrv := tlsProbeFor(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	defer closeSrv()
	if err := checkPinnedTLS(host, fp); err != nil {
		t.Fatalf("err = %v: a 401 over the pinned handshake still proves the certificate", err)
	}
}

func TestCheckPinnedTLS_RefusesAnotherCertificateAndAServerError(t *testing.T) {
	host, fp, closeSrv := tlsProbeFor(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"tls_fingerprint": fp0})
	})
	defer closeSrv()
	other := "sha256:" + strings.Repeat("00", 32)
	if err := checkPinnedTLS(host, other); err == nil {
		t.Error("a different fingerprint must fail the handshake")
	}
	if err := checkPinnedTLS(host, fp); err == nil || !strings.Contains(err.Error(), "not the pinned one") {
		t.Errorf("err = %v, want the mismatch between the served and the reported fingerprint named", err)
	}
	host2, fp2, closeSrv2 := tlsProbeFor(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	defer closeSrv2()
	if err := checkPinnedTLS(host2, fp2); err == nil {
		t.Error("a 5xx answer is not a working probe API")
	}
}

func TestCheckPinnedTLS_AgreeingFingerprintPasses(t *testing.T) {
	var fp string
	host, fpv, closeSrv := tlsProbeFor(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"tls_port": "9445", "tls_fingerprint": fp})
	})
	defer closeSrv()
	fp = fpv
	if err := checkPinnedTLS(host, fpv); err != nil {
		t.Fatal(err)
	}
}

const fp0 = "sha256:abababababababababababababababababababababababababababababababab"

// pinFixture builds a probe host the way the pin flow sees it: a plain port that
// answers tls-info (with proofs made from proofToken) and a TLS port with a
// self-signed certificate that also takes the token rotation.
func pinFixture(t *testing.T, adminToken, proofToken string, withProofs bool) (cfgPath string, ref *configRef, host NodeConfig, rotated *[]string) {
	t.Helper()
	var got []string
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/rotate-token":
			var in struct {
				NewToken string `json:"new_token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			got = append(got, r.Header.Get("Authorization")+"|"+in.NewToken)
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		case "/api/v1/tls-info":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(tlsSrv.Close)
	tlsURL, _ := url.Parse(tlsSrv.URL)
	fp := probepin.Fingerprint(tlsSrv.Certificate().Raw)

	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := map[string]interface{}{"tls_port": tlsURL.Port(), "tls_fingerprint": fp}
		if withProofs {
			out["proofs"] = map[string]string{"probe-admin": probepin.TokenProof(proofToken, fp, r.URL.Query().Get("nonce"))}
		}
		json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(plain.Close)

	host = NodeConfig{Name: "probe", Addr: strings.TrimPrefix(plain.URL, "http://"), AdminToken: adminToken}
	cfgPath = filepath.Join(t.TempDir(), "web.json")
	ref = newConfigRef(&WebConfig{ProbeHosts: []NodeConfig{host}})
	return cfgPath, ref, host, &got
}

func postPinNow(t *testing.T, cfgPath string, ref *configRef, addr string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"addr": {addr}}
	r := httptest.NewRequest(http.MethodPost, "/probes/pin-now", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleProbePinNow(cfgPath, ref)(w, r)
	return w
}

func TestPinNow_AProbeThatProvesItsCertificateIsPinnedAndItsTokenReplacedOverTLS(t *testing.T) {
	cfgPath, ref, host, rotated := pinFixture(t, "the-current-admin-token-0123456789abcdef", "the-current-admin-token-0123456789abcdef", true)

	w := postPinNow(t, cfgPath, ref, host.Addr)

	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "is pinned") {
		t.Fatalf("status %d body %q, want the pinned page", w.Code, w.Body.String())
	}
	got := ref.Load().ProbeHosts[0]
	if got.TLSFingerprint == "" || got.TLSPort == "" {
		t.Fatalf("host %+v, want it pinned without anyone comparing a fingerprint", got)
	}
	if len(*rotated) != 1 || !strings.HasPrefix((*rotated)[0], "Bearer the-current-admin-token-0123456789abcdef|") {
		t.Fatalf("rotation calls %v, want one, authenticated with the old token", *rotated)
	}
	newTok := strings.SplitN((*rotated)[0], "|", 2)[1]
	if len(newTok) < 32 || got.AdminToken != newTok {
		t.Errorf("stored token %q vs sent %q: the new token must be kept and strong", got.AdminToken, newTok)
	}
	if !strings.Contains(w.Body.String(), "was replaced") {
		t.Error("the page must say the token was replaced")
	}
	saved, err := os.ReadFile(cfgPath)
	if err != nil || !strings.Contains(string(saved), got.TLSFingerprint) {
		t.Errorf("the pin must be saved to web.json: %v", err)
	}
}

func TestPinNow_NoProofOrAProofFromAnotherTokenFallsBackToTheManualComparison(t *testing.T) {
	for name, fixture := range map[string]struct {
		withProofs bool
		proofToken string
	}{
		"older probe, no proofs":        {false, ""},
		"proof made with another token": {true, "some-other-token-0123456789abcdef0123456789"},
	} {
		t.Run(name, func(t *testing.T) {
			cfgPath, ref, host, rotated := pinFixture(t, "the-current-admin-token-0123456789abcdef", fixture.proofToken, fixture.withProofs)

			w := postPinNow(t, cfgPath, ref, host.Addr)

			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "compare it with the fingerprint") {
				t.Fatalf("status %d body %q, want the manual comparison dialog", w.Code, w.Body.String())
			}
			if ref.Load().ProbeHosts[0].TLSFingerprint != "" || len(*rotated) != 0 {
				t.Error("an unproven fingerprint must neither be pinned nor trigger a token rotation")
			}
			if _, err := os.Stat(cfgPath); err == nil {
				t.Error("nothing may be saved before the operator confirms")
			}
		})
	}
}
