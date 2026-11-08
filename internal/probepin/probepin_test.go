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

func TestAdoptProof_OnlyTheJoinCodeHolderCanProveAFingerprint(t *testing.T) {
	fp := "sha256:" + strings.Repeat("ab", 32)
	proof := AdoptProof("join-code-1", fp)
	if !VerifyAdoptProof("join-code-1", fp, proof) {
		t.Fatal("a proof made with the same join code must verify")
	}
	if VerifyAdoptProof("join-code-2", fp, proof) {
		t.Error("a different join code must not verify")
	}
	if VerifyAdoptProof("join-code-1", "sha256:"+strings.Repeat("cd", 32), proof) {
		t.Error("a proof must not verify for another fingerprint")
	}
	if VerifyAdoptProof("join-code-1", fp, "") || VerifyAdoptProof("join-code-1", fp, "zz") {
		t.Error("an empty or malformed proof must not verify")
	}
}

func TestTokenProof_BoundToTokenFingerprintAndNonce(t *testing.T) {
	fp := "sha256:" + strings.Repeat("ab", 32)
	p := TokenProof("tok-1", fp, "n1")
	if !VerifyTokenProof("tok-1", fp, "n1", p) {
		t.Fatal("a proof from the same token, fingerprint and nonce must verify")
	}
	for name, ok := range map[string]bool{
		"other token":       VerifyTokenProof("tok-2", fp, "n1", p),
		"other fingerprint": VerifyTokenProof("tok-1", "sha256:"+strings.Repeat("cd", 32), "n1", p),
		"other nonce":       VerifyTokenProof("tok-1", fp, "n2", p),
		"empty proof":       VerifyTokenProof("tok-1", fp, "n1", ""),
		"not hex":           VerifyTokenProof("tok-1", fp, "n1", "zz"),
	} {
		if ok {
			t.Errorf("%s must not verify (a replayed or forged answer)", name)
		}
	}
}
