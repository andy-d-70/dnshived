// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"dnshived/internal/backupcrypt"
	"dnshived/internal/config"
	"dnshived/internal/configimport"
)

func exportFileFor(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(config.Cluster{
		ClusterID: "old-cluster", PSK: "old-psk", NodeID: "core-1-old", ControlAddr: "192.0.2.51:9443", Peers: []string{"192.0.2.52:9443"},
		APITokens:    []config.APIToken{{Name: "x", Token: "old-token", Role: "admin"}},
		LogLevel:     "debug",
		Scopes:       map[string]config.ScopeConfig{"office": {VLANID: 100, VIP: "192.168.100.1/24", Reservations: []config.Reservation{{MAC: "aa:bb:cc:00:00:01", IP: "192.168.100.50", Hostname: "nas"}}}},
		LocalDomains: []config.LocalDomain{{Name: "office.lan", Records: []config.LocalDomainHost{{Host: "nas", Type: "A", Value: "192.168.100.50"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func importUpload(t *testing.T, state *builderState, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "x.json")
	fw.Write(data)
	mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/setup/import/upload", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	bootstrapImportUploadHandler("host", "9443", state)(rec, r)
	return rec
}

func TestBootstrapImportUpload(t *testing.T) {
	state := &builderState{}
	rec := importUpload(t, state, exportFileFor(t))
	if rec.Code != http.StatusSeeOther || state.importCopy() == nil {
		t.Fatalf("HTTP %d, import held: %v", rec.Code, state.importCopy() != nil)
	}
	if g := state.importCopy().groups; !g[configimport.GroupScopes] || !g[configimport.GroupDomains] || !g[configimport.GroupSettings] {
		t.Errorf("groups = %v, want the groups the file holds chosen by default", g)
	}
	bad := &builderState{}
	rec = importUpload(t, bad, []byte("not json"))
	if rec.Code != http.StatusBadRequest || bad.importCopy() != nil {
		t.Errorf("a bad file: HTTP %d, held %v", rec.Code, bad.importCopy() != nil)
	}
}

func postChoose(state *builderState, v url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/setup/import/choose", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	bootstrapImportChooseHandler("host", "9443", state)(rec, r)
	return rec
}

func TestBootstrapImportChoose_RestoreNeedsTheWord(t *testing.T) {
	state := &builderState{}
	importUpload(t, state, exportFileFor(t))
	rec := postChoose(state, url.Values{"g_scopes": {"on"}, "keep_id": {"on"}})
	if rec.Code != http.StatusBadRequest || state.importCopy().keepID {
		t.Errorf("keeping the cluster ID without the word: HTTP %d keep %v", rec.Code, state.importCopy().keepID)
	}
	rec = postChoose(state, url.Values{"g_scopes": {"on"}, "keep_id": {"on"}, "confirm": {"RESTORE"}})
	if rec.Code != http.StatusSeeOther || !state.importCopy().keepID {
		t.Errorf("with the word: HTTP %d keep %v", rec.Code, state.importCopy().keepID)
	}
	if g := state.importCopy().groups; len(g) != 1 || !g[configimport.GroupScopes] {
		t.Errorf("groups = %v, want scopes only", g)
	}
}

func TestApplyBootstrapImport_KeepsGeneratedTrustAndParksScopes(t *testing.T) {
	state := &builderState{}
	importUpload(t, state, exportFileFor(t))
	secrets, err := generateClusterSecrets()
	if err != nil {
		t.Fatal(err)
	}
	self := clusterNode{Addr: "192.0.2.77:9443", Role: config.RoleCore1, Self: true}
	cc, err := buildClusterConfig(secrets, self, []clusterNode{self}, mgmtSetup{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := applyBootstrapImport(cc, state.importCopy())
	if err != nil {
		t.Fatal(err)
	}
	if out.PSK != secrets.PSK || out.ClusterID != secrets.ClusterID || strings.Contains(out.NodeID, "old") || out.ControlAddr != self.Addr {
		t.Errorf("trust or identity came from the file: %+v", out)
	}
	for _, tk := range out.APITokens {
		if tk.Token == "old-token" {
			t.Error("a token from the file was used")
		}
	}
	if len(out.Scopes) != 0 || len(out.ParkedScopes) != 1 || out.ParkedScopes["office"].VLANID != 100 {
		t.Errorf("scopes %v parked %v, want office parked only", out.Scopes, out.ParkedScopes)
	}
	if len(out.LocalDomains) != 1 || out.LogLevel != "debug" {
		t.Errorf("domains %v log level %q", out.LocalDomains, out.LogLevel)
	}
	if res := out.ValidateExtended(); !res.OK() {
		t.Errorf("the result must validate: %v", res.Errors)
	}
}

func TestApplyBootstrapImport_RefusesDataThatDoesNotValidate(t *testing.T) {
	state := &builderState{}
	bad, _ := json.Marshal(config.Cluster{ClusterID: "x", LocalDomains: []config.LocalDomain{{Name: "ok.lan", Records: []config.LocalDomainHost{{Host: "h", Type: "A", Value: "not-an-address"}}}}})
	importUpload(t, state, bad)
	secrets, _ := generateClusterSecrets()
	self := clusterNode{Addr: "192.0.2.77:9443", Role: config.RoleCore1, Self: true}
	cc, _ := buildClusterConfig(secrets, self, []clusterNode{self}, mgmtSetup{})
	if _, err := applyBootstrapImport(cc, state.importCopy()); err == nil {
		t.Error("an invalid record in the file must stop the cluster creation before anything is written")
	}
}

func TestAnsweringFileAddresses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	c := &config.Cluster{ControlAddr: ln.Addr().String(), Peers: []string{"127.0.0.1:1", "192.0.2.99:9443"}}
	got := answeringFileAddresses(c, "192.0.2.77:9443", 300*time.Millisecond)
	if len(got) != 1 || got[0] != ln.Addr().String() {
		t.Errorf("answering = %v, want only the listener", got)
	}
	if own := answeringFileAddresses(&config.Cluster{ControlAddr: ln.Addr().String()}, ln.Addr().String(), 300*time.Millisecond); len(own) != 0 {
		t.Errorf("this node's own address must not count: %v", own)
	}
}

func TestBootstrapSetupPage_ReviewStepOffersTheImport(t *testing.T) {
	state := &builderState{}
	state.setRole(config.RoleCore1)
	state.setSelfAddr("192.0.2.51:9443")
	rec := httptest.NewRecorder()
	bootstrapSetupHandler("host", "9443", state)(rec, httptest.NewRequest(http.MethodGet, "/?step=6", nil))
	if !strings.Contains(rec.Body.String(), `action="/setup/import/upload"`) {
		t.Error("step 6 must offer the file upload")
	}
	importUpload(t, state, exportFileFor(t))
	rec = httptest.NewRecorder()
	bootstrapSetupHandler("host", "9443", state)(rec, httptest.NewRequest(http.MethodGet, "/?step=6", nil))
	out := rec.Body.String()
	for _, want := range []string{"x.json", "old-cluster", "cluster key", `name="g_scopes"`, `name="keep_id"`, `action="/setup/import/clear"`} {
		if !strings.Contains(out, want) {
			t.Errorf("step 6 lacks %q", want)
		}
	}
	if strings.Contains(out, "old-psk") || strings.Contains(out, "old-token") {
		t.Error("a secret from the file must never be shown")
	}
}

func TestBootstrapImportUpload_ReadsAnEncryptedBackup(t *testing.T) {
	orig := backupGuessPause
	backupGuessPause = time.Millisecond
	defer func() { backupGuessPause = orig }()

	plain := exportFileFor(t)
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	gw.Write(plain)
	gw.Close()
	blob, err := backupcrypt.Encrypt("pw", gz.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	up := func(state *builderState, password string) *httptest.ResponseRecorder {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		fw, _ := mw.CreateFormFile("file", "b.dnsbak")
		fw.Write(blob)
		mw.WriteField("password", password)
		mw.Close()
		r := httptest.NewRequest(http.MethodPost, "/setup/import/upload", &body)
		r.Header.Set("Content-Type", mw.FormDataContentType())
		rec := httptest.NewRecorder()
		bootstrapImportUploadHandler("host", "9443", state)(rec, r)
		return rec
	}
	ok := &builderState{}
	if rec := up(ok, "pw"); rec.Code != http.StatusSeeOther || ok.importCopy() == nil {
		t.Fatalf("right password: HTTP %d", rec.Code)
	}
	for _, pw := range []string{"", "nope"} {
		st := &builderState{}
		if rec := up(st, pw); rec.Code != http.StatusBadRequest || st.importCopy() != nil {
			t.Errorf("password %q: HTTP %d, held %v", pw, rec.Code, st.importCopy() != nil)
		}
	}
}
