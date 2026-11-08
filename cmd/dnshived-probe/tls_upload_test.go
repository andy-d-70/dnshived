// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/probepin"
)

func makeCertPEM(t *testing.T, notBefore, notAfter time.Time, rsaBits int) (certPEM, keyPEM []byte) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "uploaded"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if rsaBits > 0 {
		key, err := rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			t.Fatal(err)
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func TestInstallUploadedCert_ReplacesTheCertificateAndKeepsTheKeyPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	if _, _, err := loadOrCreateProbeCert(dir); err != nil {
		t.Fatal(err)
	}
	_, oldFP, _ := loadOrCreateProbeCert(dir)
	certPEM, keyPEM := makeCertPEM(t, time.Now().Add(-time.Hour), time.Now().AddDate(1, 0, 0), 0)

	pair, fp, err := installUploadedCert(dir, certPEM, keyPEM)

	if err != nil {
		t.Fatal(err)
	}
	if fp == oldFP || fp != probepin.Fingerprint(pair.Certificate[0]) {
		t.Errorf("fingerprint %s, want the uploaded certificate's, not the old %s", fp, oldFP)
	}
	if _, again, err := loadOrCreateProbeCert(dir); err != nil || again != fp {
		t.Errorf("a restart must load the uploaded certificate: %v %s", err, again)
	}
	st, err := os.Stat(filepath.Join(dir, "key.pem"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("key.pem mode %v err %v, want 0600", st.Mode().Perm(), err)
	}
	if _, err := os.Stat(dir + ".old"); err == nil {
		t.Error("the replaced directory must not be left behind")
	}
}

func TestInstallUploadedCert_RefusesWhatCannotBeServedAndKeepsTheOldCertificate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	_, oldFP, _ := loadOrCreateProbeCert(dir)
	good, goodKey := makeCertPEM(t, time.Now().Add(-time.Hour), time.Now().AddDate(1, 0, 0), 0)
	_, otherKey := makeCertPEM(t, time.Now().Add(-time.Hour), time.Now().AddDate(1, 0, 0), 0)
	expired, expiredKey := makeCertPEM(t, time.Now().AddDate(-2, 0, 0), time.Now().AddDate(-1, 0, 0), 0)
	future, futureKey := makeCertPEM(t, time.Now().AddDate(1, 0, 0), time.Now().AddDate(2, 0, 0), 0)
	weak, weakKey := makeCertPEM(t, time.Now().Add(-time.Hour), time.Now().AddDate(1, 0, 0), 1024)
	tests := []struct {
		name      string
		cert, key []byte
		want      string
	}{
		{"key of another certificate", good, otherKey, "does not match"},
		{"expired", expired, expiredKey, "expired"},
		{"not valid yet", future, futureKey, "not valid before"},
		{"weak RSA", weak, weakKey, "2048"},
		{"empty", nil, nil, "both required"},
		{"not PEM", []byte("hello"), goodKey, "PEM"},
		{"oversized", append(good, make([]byte, maxUploadedPEM)...), goodKey, "at most"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := installUploadedCert(dir, tt.cert, tt.key); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
			if _, fp, err := loadOrCreateProbeCert(dir); err != nil || fp != oldFP {
				t.Fatalf("a refused upload must leave the old certificate: %v %s", err, fp)
			}
		})
	}
}

func TestServeLiveCert_FollowsAReplacement(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	first, fp1, _ := loadOrCreateProbeCert(dir)
	setLiveCert(first, fp1)
	got, err := serveLiveCert(nil)
	if err != nil || probepin.Fingerprint(got.Certificate[0]) != fp1 || currentFingerprint() != fp1 {
		t.Fatalf("serving %v err %v, want the first certificate", got, err)
	}
	certPEM, keyPEM := makeCertPEM(t, time.Now().Add(-time.Hour), time.Now().AddDate(1, 0, 0), 0)
	pair, fp2, err := installUploadedCert(dir, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	setLiveCert(pair, fp2)
	got, _ = serveLiveCert(nil)
	if probepin.Fingerprint(got.Certificate[0]) != fp2 || currentFingerprint() != fp2 {
		t.Error("new connections must get the replaced certificate without a restart")
	}
}

func TestProbeConfig_PlainHTTPDefaultsToOnSoOldConfigsKeepWorking(t *testing.T) {
	var c ProbeConfig
	if !c.plainHTTP() {
		t.Error("a configuration without plain_http must keep the plain API")
	}
	off := false
	c.PlainHTTP = &off
	if c.plainHTTP() {
		t.Error("plain_http=false must switch the plain API off")
	}
}

func TestTLSInfoHandler_ReportsTheCertificateServedNow(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	pair, fp, err := loadOrCreateProbeCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	setLiveCert(pair, fp)

	rec := httptest.NewRecorder()
	tlsInfoHandler(rec, httptest.NewRequest(http.MethodGet, "/api/v1/tls-info", nil))

	var got struct {
		Port        string `json:"tls_port"`
		Fingerprint string `json:"tls_fingerprint"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.Port != probeTLSPort || got.Fingerprint != fp {
		t.Fatalf("got %+v err %v, want port %s and %s", got, err, probeTLSPort, fp)
	}
}

func TestTLSInfoHandler_ProofsOnlyForAdminTokensAndOnlyWithANonce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	pair, fp, _ := loadOrCreateProbeCert(dir)
	setLiveCert(pair, fp)
	toks := []config.APIToken{
		{Name: "probe-admin", Token: "admin-secret-token-0123456789abcdef0123", Role: "admin"},
		{Name: "monitoring", Token: "readonly-secret-token-0123456789abcdef01", Role: "readonly"},
	}
	liveTokens.Store(&toks)
	get := func(query string) map[string]interface{} {
		rec := httptest.NewRecorder()
		tlsInfoHandler(rec, httptest.NewRequest(http.MethodGet, "/api/v1/tls-info"+query, nil))
		var out map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	if _, has := get("")["proofs"]; has {
		t.Error("without a nonce there is nothing to prove, and a recorded answer must not be replayable")
	}
	if _, has := get("?nonce=short")["proofs"]; has {
		t.Error("a malformed nonce must be ignored")
	}
	proofs, _ := get("?nonce=abcdef0123456789")["proofs"].(map[string]interface{})
	if len(proofs) != 1 {
		t.Fatalf("proofs = %v, want exactly the admin token's", proofs)
	}
	got, _ := proofs["probe-admin"].(string)
	if !probepin.VerifyTokenProof(toks[0].Token, fp, "abcdef0123456789", got) {
		t.Error("the admin proof must verify with the admin token")
	}
	if probepin.VerifyTokenProof(toks[1].Token, fp, "abcdef0123456789", got) {
		t.Error("the readonly token must not be able to produce the admin proof")
	}
}
