// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlePendingSummary_ReflectsCachedValue(t *testing.T) {
	h := handlePendingSummary()

	pendingHasChanges.Store(false)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/pending-summary", nil))
	if !strings.Contains(rec.Body.String(), `"hasChanges":false`) {
		t.Errorf("expected hasChanges:false, got %s", rec.Body.String())
	}

	pendingHasChanges.Store(true)
	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/pending-summary", nil))
	if !strings.Contains(rec.Body.String(), `"hasChanges":true`) {
		t.Errorf("expected hasChanges:true, got %s", rec.Body.String())
	}
	pendingHasChanges.Store(false) // leave clean for other tests
}
