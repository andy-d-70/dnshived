// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"dnshived/internal/backupcrypt"
	"dnshived/internal/config"
	"dnshived/internal/webauth"
)

func asUser(r *http.Request, name string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userContextKey{}, webauth.User{Name: name}))
}

func importFile(t *testing.T, c config.Cluster) []byte {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func uploadReq(t *testing.T, data []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "export.json")
	fw.Write(data)
	mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/config/import/upload", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return asUser(r, "tester")
}

func TestHandleImportUpload_HoldsTheFileAndShowsTheChoice(t *testing.T) {
	data := importFile(t, config.Cluster{ClusterID: "src", PSK: "secret", Scopes: map[string]config.ScopeConfig{"a": {VLANID: 5}}, LocalDomains: []config.LocalDomain{{Name: "x.lan"}}})
	w := httptest.NewRecorder()
	handleImportUpload(w, uploadReq(t, data))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/config/import?t=") {
		t.Fatalf("redirect = %q", loc)
	}
	r := asUser(httptest.NewRequest(http.MethodGet, loc, nil), "tester")
	w = httptest.NewRecorder()
	handleImportGet(w, r)
	out := w.Body.String()
	for _, want := range []string{"export.json", "from cluster <b>src</b>", "cluster key", `name="g_scopes"`, `name="g_domains"`, `name="m_scopes"`, `value="a"`} {
		if !strings.Contains(out, want) {
			t.Errorf("choice page lacks %q", want)
		}
	}
	if strings.Contains(out, "secret") {
		t.Error("the page must never show a secret from the file")
	}

	other := asUser(httptest.NewRequest(http.MethodGet, loc, nil), "someone-else")
	w = httptest.NewRecorder()
	handleImportGet(w, other)
	if !strings.Contains(w.Body.String(), "no longer held") {
		t.Error("another user must not see a held file")
	}
}

func TestHandleImportUpload_RefusesNonConfigFiles(t *testing.T) {
	for _, body := range []string{"hello", `[1,2]`, `{"schema_version":99,"cluster_id":"x"}`} {
		w := httptest.NewRecorder()
		handleImportUpload(w, uploadReq(t, []byte(body)))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `class="crit"`) {
			t.Errorf("%q: HTTP %d, want the form again with an error", body, w.Code)
		}
	}
}

func holdFile(t *testing.T, c config.Cluster) string {
	t.Helper()
	w := httptest.NewRecorder()
	handleImportUpload(w, uploadReq(t, importFile(t, c)))
	return strings.TrimPrefix(w.Header().Get("Location"), "/config/import?t=")
}

func postForm(path string, v url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return asUser(r, "tester")
}

func TestHandleImportPreviewAndStage(t *testing.T) {
	live := testClusterWithScopes()
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	ref := newConfigRef(cfg)
	tok := holdFile(t, config.Cluster{ClusterID: "src", PSK: "other-psk",
		Scopes:       map[string]config.ScopeConfig{"guest": {VLANID: 110, VIP: "192.168.110.1/24"}},
		LocalDomains: []config.LocalDomain{{Name: "imp.lan", Records: []config.LocalDomainHost{{Host: "h", Type: "A", Value: "10.1.1.1"}}}}})
	form := url.Values{"t": {tok}, "g_scopes": {"on"}, "m_scopes": {"merge"}, "g_domains": {"on"}, "m_domains": {"merge"}}

	w := httptest.NewRecorder()
	handleImportPreview(ref)(w, postForm("/config/import/preview", form))
	out := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(out, "new: guest") || !strings.Contains(out, "imp.lan") || !strings.Contains(out, "Stage as pending change") {
		t.Fatalf("preview HTTP %d:\n%s", w.Code, out)
	}
	if len(pushed.LocalDomains) != 0 || len(pushed.ParkedScopes) != 0 {
		t.Error("a preview must stage nothing")
	}

	w = httptest.NewRecorder()
	handleImportStage(ref)(w, postForm("/config/import/stage", form))
	if w.Code >= 400 {
		t.Fatalf("stage HTTP %d: %s", w.Code, w.Body.String())
	}
	if _, ok := pushed.ParkedScopes["guest"]; !ok || len(pushed.ParkedScopes) != 1 {
		t.Errorf("parked = %v, want guest", pushed.ParkedScopes)
	}
	if len(pushed.Scopes) != len(live.Scopes) {
		t.Error("live scopes must be untouched")
	}
	if len(pushed.LocalDomains) != 1 || pushed.LocalDomains[0].Name != "imp.lan" {
		t.Errorf("domains = %v", pushed.LocalDomains)
	}
	if pushed.PSK != live.PSK {
		t.Error("the cluster key must stay this cluster's own")
	}
}

func TestHandleImportPreview_NeedsAGroup(t *testing.T) {
	tok := holdFile(t, config.Cluster{ClusterID: "src", LocalDomains: []config.LocalDomain{{Name: "x.lan"}}})
	w := httptest.NewRecorder()
	handleImportPreview(newConfigRef(&WebConfig{}))(w, postForm("/config/import/preview", url.Values{"t": {tok}}))
	if !strings.Contains(w.Body.String(), "Tick at least one group") {
		t.Errorf("body: %s", w.Body.String())
	}
}

func TestDataExport_HasNoTrustOrIdentity(t *testing.T) {
	c := config.Cluster{ClusterID: "c", NodeID: "n", Role: "core-1", ControlAddr: "1.2.3.4:9443", PSK: "p", Peers: []string{"x"}, TrustedHosts: []string{"y"},
		TLSCert: "c", TLSKey: "k", APITokens: []config.APIToken{{Name: "t", Token: "tok"}}, HelperSocket: "/h", BackupPassword: "pw", ConfigRevision: 9,
		Scopes:       map[string]config.ScopeConfig{"a": {VLANID: 1, NodeIP: "10.0.0.2/24"}},
		LocalDomains: []config.LocalDomain{{Name: "x.lan"}}}
	raw, _ := json.Marshal(dataExport(c))
	for _, bad := range []string{`"psk"`, `"api_tokens"`, `"trusted_hosts"`, `"tls_key"`, `"backup_password"`, `"node_id":"n"`, `"node_ip"`, "tok"} {
		if strings.Contains(string(raw), bad) {
			t.Errorf("the data export contains %s: %s", bad, raw)
		}
	}
	if !strings.Contains(string(raw), "x.lan") || !strings.Contains(string(raw), `"vlan_id":1`) {
		t.Errorf("the data export lost data: %s", raw)
	}
}

func encryptedBackup(t *testing.T, password string, c config.Cluster) []byte {
	t.Helper()
	plain, _ := json.Marshal(c)
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	gw.Write(plain)
	gw.Close()
	blob, err := backupcrypt.Encrypt(password, gz.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func uploadWithPassword(t *testing.T, data []byte, password string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "backup.dnsbak")
	fw.Write(data)
	mw.WriteField("password", password)
	mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/config/import/upload", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return asUser(r, "tester")
}

func TestHandleImportUpload_ReadsAnEncryptedBackup(t *testing.T) {
	restoreLimiter = &failLimiter{clients: map[string]*failState{}, what: "restore attempts"}
	blob := encryptedBackup(t, "backup-pw", config.Cluster{ClusterID: "src", PSK: "secret", Scopes: map[string]config.ScopeConfig{"a": {VLANID: 5}}})

	w := httptest.NewRecorder()
	handleImportUpload(w, uploadWithPassword(t, blob, "backup-pw"))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("right password: HTTP %d: %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	handleImportUpload(w, uploadWithPassword(t, blob, ""))
	if !strings.Contains(w.Body.String(), "enter its password") {
		t.Errorf("no password: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	handleImportUpload(w, uploadWithPassword(t, blob, "wrong"))
	if !strings.Contains(w.Body.String(), "wrong password") {
		t.Errorf("wrong password: %s", w.Body.String())
	}
}
