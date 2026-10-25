// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dnshived/internal/bootstrap"
)

func TestProbeBootstrapUnits_IsEmpty(t *testing.T) {
	if len(probeBootstrapUnits) != 0 {
		t.Errorf("probeBootstrapUnits = %v, want empty — see this test's own doc comment for why no unit belongs here", probeBootstrapUnits)
	}
}

// TestProbeBootstrapStatusHandler_NeverLeaksOTP mirrors cmd/dnshived's
// identical guard — the join code must never be served over HTTP.
func TestProbeBootstrapStatusHandler_NeverLeaksOTP(t *testing.T) {
	handler := probeBootstrapStatusHandler("probe-test")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	body := rec.Body.String()
	for _, forbidden := range []string{"otp", "OTP", "join_code", "code"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("response body contains %q — the join code must never be served over HTTP: %s", forbidden, body)
		}
	}
}

func withMockProbeHelperWrite(t *testing.T, result error) *[]byte {
	t.Helper()
	orig := probeHelperWriteConfigFunc
	var got []byte
	probeHelperWriteConfigFunc = func(content []byte) error {
		got = content
		return result
	}
	t.Cleanup(func() { probeHelperWriteConfigFunc = orig })
	return &got
}

// TestProbeAdoptHandler_WrongCodeRejectedBeforeTouchingConfig is the core
// security property.
func TestProbeAdoptHandler_WrongCodeRejectedBeforeTouchingConfig(t *testing.T) {
	written := withMockProbeHelperWrite(t, nil)
	handler := probeAdoptHandler("REAL-CODE")

	body, _ := json.Marshal(probeAdoptRequest{Code: "WRONG-CODE", Config: json.RawMessage(`{"listen_addr":"x"}`)})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/adopt", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if *written != nil {
		t.Error("probeHelperWriteConfigFunc was called despite a wrong code — must never happen")
	}
}

func TestProbeAdoptHandler_Sealed(t *testing.T) {
	seal := func(code, purpose string) []byte {
		plain, _ := json.Marshal(probeAdoptRequest{Config: json.RawMessage(`{"listen_addr":"0.0.0.0:9444"}`)})
		sealed, err := bootstrap.Seal(code, purpose, plain)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(sealed)
		return body
	}
	cases := []struct {
		name string
		body []byte
		want int
	}{
		{"wrong code", seal("WRONG-CODE", bootstrap.PurposeProbeAdopt), http.StatusUnauthorized},
		{"core purpose", seal("REAL-CODE", bootstrap.PurposeCoreAdopt), http.StatusUnauthorized},
		{"right code reaches validation", seal("REAL-CODE", bootstrap.PurposeProbeAdopt), http.StatusBadRequest},
	}
	for _, c := range cases {
		written := withMockProbeHelperWrite(t, nil)
		rec := httptest.NewRecorder()
		probeAdoptHandler("REAL-CODE")(rec, httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/adopt", bytes.NewReader(c.body)))
		if rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d", c.name, rec.Code, c.want)
		}
		if *written != nil {
			t.Errorf("%s: config written", c.name)
		}
	}
}

// TestProbeAdoptHandler_MissingRequiredFieldsRejected covers the
// validation this handler does in place of a shared ValidateExtended
// (ProbeConfig has none).
func TestProbeAdoptHandler_MissingRequiredFieldsRejected(t *testing.T) {
	written := withMockProbeHelperWrite(t, nil)
	handler := probeAdoptHandler("REAL-CODE")

	// Missing trunk_parent/cluster_token/cluster_nodes.
	body, _ := json.Marshal(probeAdoptRequest{Code: "REAL-CODE", Config: json.RawMessage(`{"listen_addr":"0.0.0.0:9444"}`)})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/adopt", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if *written != nil {
		t.Error("probeHelperWriteConfigFunc was called despite missing required fields — must never happen")
	}
}

func TestProbeAdoptHandler_HelperFailureSurfacedAsServerError(t *testing.T) {
	withMockProbeHelperWrite(t, errWriteFailed)
	handler := probeAdoptHandler("REAL-CODE")

	raw := []byte(`{"listen_addr":"0.0.0.0:9444","trunk_parent":"ens19","cluster_token":"tok","cluster_nodes":[{"name":"core-1","addr":"192.0.2.22:9443","tls":false}]}`)
	body, _ := json.Marshal(probeAdoptRequest{Code: "REAL-CODE", Config: raw})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/adopt", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

var errWriteFailed = &testError{"probehelper: permission denied"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

// TestProbeAdoptHandler_ValidConfigWrittenViaHelperAndReExecScheduled is
// the golden path.
func TestProbeAdoptHandler_ValidConfigWrittenViaHelperAndReExecScheduled(t *testing.T) {
	written := withMockProbeHelperWrite(t, nil)

	origReExec := probeReExecFunc
	called := make(chan struct{}, 1)
	probeReExecFunc = func() { called <- struct{}{} }
	defer func() { probeReExecFunc = origReExec }()

	handler := probeAdoptHandler("REAL-CODE")

	raw := []byte(`{"listen_addr":"0.0.0.0:9444","trunk_parent":"ens19","cluster_token":"tok","cluster_nodes":[{"name":"core-1","addr":"192.0.2.22:9443","tls":false}]}`)
	body, _ := json.Marshal(probeAdoptRequest{Code: "REAL-CODE", Config: raw})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/adopt", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(*written, raw) {
		t.Error("content handed to probeHelperWriteConfigFunc does not match the pushed payload exactly")
	}

	select {
	case <-called:
	case <-time.After(time.Second):
		t.Error("probeReExecFunc was never called within 1s of a successful adopt — the scheduled restart is missing")
	}
}

// TestDefaultProbeBootstrapOTPPath_SharedWithCoreAndWritable: this binary
// runs unprivileged, so the code can't live in root-owned /run/dnshived/.
func TestDefaultProbeBootstrapOTPPath_SharedWithCoreAndWritable(t *testing.T) {
	if strings.HasPrefix(defaultProbeBootstrapOTPPath, "/run/dnshived/") {
		t.Errorf("defaultProbeBootstrapOTPPath = %q is inside root-owned /run/dnshived/, which this unprivileged binary can't write", defaultProbeBootstrapOTPPath)
	}
	if defaultProbeBootstrapOTPPath != "/run/dnshived-bootstrap/otp" {
		t.Errorf("defaultProbeBootstrapOTPPath = %q, want the path shared with cmd/dnshived (/run/dnshived-bootstrap/otp)", defaultProbeBootstrapOTPPath)
	}
}
