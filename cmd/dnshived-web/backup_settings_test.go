// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"dnshived/internal/backup"
	"dnshived/internal/backupcrypt"
	"dnshived/internal/config"
)

func TestHandleBackupSettingsPost_PreservesLiveScopesUnedited(t *testing.T) {
	live := testClusterWithScopes()
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	form := strings.NewReader("backup_enabled=on&backup_interval_hours=12&backup_retention_count=7&backup_password=hunter2")
	r := httptest.NewRequest(http.MethodPost, "/backup/settings", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleBackupSettingsPost(newConfigRef(cfg))(w, r)

	if w.Code >= 400 {
		t.Fatalf("handler returned HTTP %d: %s", w.Code, w.Body.String())
	}
	if len(pushed.Scopes) != 1 {
		t.Errorf("pushed candidate has %d scope(s), want 1 (existing scopes must survive a backup-settings save)", len(pushed.Scopes))
	}
	if !pushed.BackupEnabled {
		t.Error("pushed candidate BackupEnabled = false, want true")
	}
	if pushed.BackupIntervalHours != 12 {
		t.Errorf("pushed candidate BackupIntervalHours = %d, want 12", pushed.BackupIntervalHours)
	}
	if pushed.BackupRetentionCount != 7 {
		t.Errorf("pushed candidate BackupRetentionCount = %d, want 7", pushed.BackupRetentionCount)
	}
	if pushed.BackupPassword != "hunter2" {
		t.Errorf("pushed candidate BackupPassword = %q, want %q", pushed.BackupPassword, "hunter2")
	}
}

func TestHandleBackupSettingsPost_UncheckedBoxDisables(t *testing.T) {
	live := config.Cluster{BackupEnabled: true, BackupPassword: "old"}
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}
	form := strings.NewReader("backup_interval_hours=&backup_retention_count=&backup_password=old")
	r := httptest.NewRequest(http.MethodPost, "/backup/settings", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handleBackupSettingsPost(newConfigRef(cfg))(w, r)

	if w.Code >= 400 {
		t.Fatalf("handler returned HTTP %d: %s", w.Code, w.Body.String())
	}
	if pushed.BackupEnabled {
		t.Error("pushed candidate BackupEnabled = true, want false (checkbox was unchecked)")
	}
}

func TestHandleBackupCreatePost_RedirectsWithSuccessCount(t *testing.T) {
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"Name":"backup-x.enc"}`))
	}))
	defer node.Close()
	n := nodeConfigFor(t, node)
	n.Name = "core-1"
	cfg := &WebConfig{Nodes: []NodeConfig{n}}

	form := strings.NewReader("password=hunter2")
	r := httptest.NewRequest(http.MethodPost, "/backup/create", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleBackupCreatePost(newConfigRef(cfg))(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "backup_ok=1") {
		t.Errorf("Location = %q, want it to contain backup_ok=1", loc)
	}
	if strings.Contains(loc, "backup_failed=") {
		t.Errorf("Location = %q, want no backup_failed on full success", loc)
	}
}

// TestHandleBackupCreatePost_SendsCommentToEveryNode checks a manual
// backup's comment reaches every node.
func TestHandleBackupCreatePost_SendsCommentToEveryNode(t *testing.T) {
	var gotComment string
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Password string `json:"password"`
			Comment  string `json:"comment"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		gotComment = body.Comment
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"Name":"backup-x.enc"}`))
	}))
	defer node.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, node)}}

	form := strings.NewReader("password=hunter2&comment=" + url.QueryEscape("before DNS relay cutover"))
	r := httptest.NewRequest(http.MethodPost, "/backup/create", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleBackupCreatePost(newConfigRef(cfg))(w, r)

	if gotComment != "before DNS relay cutover" {
		t.Errorf("comment sent to node = %q, want %q", gotComment, "before DNS relay cutover")
	}
}

func TestHandleBackupDeleteGroup_FansOutToEveryNode(t *testing.T) {
	var mu sync.Mutex
	var deletedOn []string
	newNode := func(name string) NodeConfig {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			deletedOn = append(deletedOn, name)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"ok":true}`))
		}))
		t.Cleanup(srv.Close)
		n := nodeConfigFor(t, srv)
		n.Name = name
		return n
	}
	cfg := &WebConfig{Nodes: []NodeConfig{newNode("core-1"), newNode("core-2"), newNode("core-3")}}

	r := httptest.NewRequest(http.MethodPost, "/backup/delete-group/backup-x.enc", nil)
	r.SetPathValue("name", "backup-x.enc")
	w := httptest.NewRecorder()
	handleBackupDeleteGroup(newConfigRef(cfg))(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303: %s", w.Code, w.Body.String())
	}
	sort.Strings(deletedOn)
	if len(deletedOn) != 3 {
		t.Fatalf("deleted on %v, want all 3 nodes", deletedOn)
	}
}

func TestHandleBackupDeleteGroup_404OnOneNodeIsNotAFailure(t *testing.T) {
	hasIt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer hasIt.Close()
	doesNotHaveIt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not found"}`))
	}))
	defer doesNotHaveIt.Close()

	n1, n2 := nodeConfigFor(t, hasIt), nodeConfigFor(t, doesNotHaveIt)
	n1.Name, n2.Name = "core-1", "core-2"
	cfg := &WebConfig{Nodes: []NodeConfig{n1, n2}}

	r := httptest.NewRequest(http.MethodPost, "/backup/delete-group/backup-x.enc", nil)
	r.SetPathValue("name", "backup-x.enc")
	w := httptest.NewRecorder()
	handleBackupDeleteGroup(newConfigRef(cfg))(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 (a 404 on one node must not fail the whole delete): %s", w.Code, w.Body.String())
	}
}

// TestHandleBackupDeleteGroup_RealFailureIsSurfaced confirms a GENUINE
// error (not a 404) on one node is not silently swallowed.
func TestHandleBackupDeleteGroup_RealFailureIsSurfaced(t *testing.T) {
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"disk error"}`))
	}))
	defer broken.Close()
	n := nodeConfigFor(t, broken)
	n.Name = "core-1"
	cfg := &WebConfig{Nodes: []NodeConfig{n}}

	r := httptest.NewRequest(http.MethodPost, "/backup/delete-group/backup-x.enc", nil)
	r.SetPathValue("name", "backup-x.enc")
	w := httptest.NewRecorder()
	handleBackupDeleteGroup(newConfigRef(cfg))(w, r)

	if w.Code == http.StatusSeeOther {
		t.Fatalf("status = 303, want a real error status for a genuine node failure")
	}
	if !strings.Contains(w.Body.String(), "core-1") {
		t.Errorf("body does not name the failing node: %s", w.Body.String())
	}
}

func TestHandleBackup_RendersGroupedRowWithCommentAndBothNodes(t *testing.T) {
	when := time.Now()
	newNode := func(name string) NodeConfig {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/config":
				json.NewEncoder(w).Encode(config.Cluster{ClusterID: "lab01"})
			case "/api/v1/backups":
				json.NewEncoder(w).Encode([]backupInfo{{Name: "backup-20260830-160000.enc", Size: 100, ModTime: when, Comment: "before cutover"}})
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)
		n := nodeConfigFor(t, srv)
		n.Name = name
		return n
	}
	cfg := &WebConfig{Nodes: []NodeConfig{newNode("core-1"), newNode("core-2")}}

	r := httptest.NewRequest(http.MethodGet, "/backup", nil)
	w := httptest.NewRecorder()
	handleBackup(newConfigRef(cfg))(w, r)

	body := w.Body.String()
	if strings.Count(body, "<td>backup-20260830-160000.enc</td>") != 1 {
		t.Errorf("expected exactly ONE row for the shared filename, body: %s", body)
	}
	if !strings.Contains(body, "before cutover") {
		t.Errorf("body does not show the comment: %s", body)
	}
	if !strings.Contains(body, "/backup/download/core-1/backup-20260830-160000.enc") ||
		!strings.Contains(body, "/backup/download/core-2/backup-20260830-160000.enc") {
		t.Errorf("body does not link both nodes' own download paths: %s", body)
	}
	if !strings.Contains(body, "/backup/delete-group/backup-20260830-160000.enc") {
		t.Errorf("body does not offer the one-click delete-everywhere action: %s", body)
	}
}

func TestHandleBackup_MarksAutomatedVsManualBackups(t *testing.T) {
	when := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{ClusterID: "lab01"})
		case "/api/v1/backups":
			json.NewEncoder(w).Encode([]backupInfo{
				{Name: "backup-20260831-020125.enc", Size: 100, ModTime: when, Automated: true},
				{Name: "backup-20260831-153245.enc", Size: 100, ModTime: when.Add(time.Hour), Automated: false},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}

	r := httptest.NewRequest(http.MethodGet, "/backup", nil)
	w := httptest.NewRecorder()
	handleBackup(newConfigRef(cfg))(w, r)

	body := w.Body.String()
	if !strings.Contains(body, `<span class="dim">automatic</span>`) {
		t.Errorf("body does not mark the automated backup, body: %s", body)
	}
	if !strings.Contains(body, "<td>manual</td>") {
		t.Errorf("body does not mark the manual backup, body: %s", body)
	}
}

func TestHandleBackupCreatePost_RedirectsWithFailedNodeName(t *testing.T) {
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"disk full"}`))
	}))
	defer node.Close()
	n := nodeConfigFor(t, node)
	n.Name = "core-2"
	cfg := &WebConfig{Nodes: []NodeConfig{n}}

	form := strings.NewReader("password=hunter2")
	r := httptest.NewRequest(http.MethodPost, "/backup/create", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleBackupCreatePost(newConfigRef(cfg))(w, r)

	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "backup_ok=0") {
		t.Errorf("Location = %q, want backup_ok=0", loc)
	}
	if !strings.Contains(loc, "core-2") {
		t.Errorf("Location = %q, want the failing node named", loc)
	}
}

func TestHandleBackup_RendersSuccessBannerAfterCreate(t *testing.T) {
	c := config.Cluster{ClusterID: "lab01"}
	srv := fakeConfigServer(t, c)
	defer srv.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}

	r := httptest.NewRequest(http.MethodGet, "/backup?backup_ok=3", nil)
	w := httptest.NewRecorder()
	handleBackup(newConfigRef(cfg))(w, r)

	if !strings.Contains(w.Body.String(), "Backed up 3 node(s) successfully") {
		t.Errorf("body does not contain the success banner: %s", w.Body.String())
	}
}

func TestHandleBackup_RendersFailureBannerAfterCreate(t *testing.T) {
	c := config.Cluster{ClusterID: "lab01"}
	srv := fakeConfigServer(t, c)
	defer srv.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}

	r := httptest.NewRequest(http.MethodGet, "/backup?backup_ok=1&backup_failed=worker-b", nil)
	w := httptest.NewRecorder()
	handleBackup(newConfigRef(cfg))(w, r)

	body := w.Body.String()
	if !strings.Contains(body, "failed on: worker-b") {
		t.Errorf("body does not contain the failure banner: %s", body)
	}
}

func TestHandleBackup_RendersFullPageWithRealBackupRows(t *testing.T) {
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{ClusterID: "lab01"})
		case "/api/v1/backups":
			json.NewEncoder(w).Encode([]backupInfo{{Name: "backup-20260101-000000.enc", Size: 123, ModTime: time.Now()}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer node.Close()
	n := nodeConfigFor(t, node)
	n.Name = "core-1"
	cfg := &WebConfig{Nodes: []NodeConfig{n}}

	r := httptest.NewRequest(http.MethodGet, "/backup", nil)
	w := httptest.NewRecorder()
	handleBackup(newConfigRef(cfg))(w, r)

	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, body)
	}
	if !strings.Contains(body, "backup-20260101-000000.enc") {
		t.Errorf("body does not list the real backup row: %s", body)
	}
	if !strings.Contains(body, "core-1") {
		t.Errorf("body does not show the node's display name: %s", body)
	}
	// Content that comes AFTER the row in the template — missing here
	// means the render broke partway through, even at HTTP 200.
	if !strings.Contains(body, "<h2>Restore</h2>") || !strings.Contains(body, "<h2>Import</h2>") {
		t.Errorf("body is missing sections that render after the backup rows — template execution likely failed partway through: %s", body)
	}
}

func TestHandleBackup_NoBannerOnPlainGet(t *testing.T) {
	c := config.Cluster{ClusterID: "lab01"}
	srv := fakeConfigServer(t, c)
	defer srv.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}

	r := httptest.NewRequest(http.MethodGet, "/backup", nil)
	w := httptest.NewRecorder()
	handleBackup(newConfigRef(cfg))(w, r)

	if strings.Contains(w.Body.String(), "Backed up") {
		t.Errorf("plain GET /backup should never show a create banner: %s", w.Body.String())
	}
}

func TestHandleBackupListAPI_NoErrorsMarshalsAsEmptyArrayNotNull(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]backupInfo{})
	}))
	defer ok.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, ok)}}

	r := httptest.NewRequest(http.MethodGet, "/backup/list", nil)
	w := httptest.NewRecorder()
	handleBackupListAPI(newConfigRef(cfg))(w, r)

	if !strings.Contains(w.Body.String(), `"node_errors":[]`) {
		t.Errorf("body = %s, want node_errors to be [] not null", w.Body.String())
	}
}

func TestFetchBackupGroups_DifferentNamesStayUngroupedNewestFirst(t *testing.T) {
	older := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	nodeA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]backupInfo{{Name: "backup-a-old.enc", Size: 10, ModTime: older}})
	}))
	defer nodeA.Close()
	nodeB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]backupInfo{{Name: "backup-b-new.enc", Size: 20, ModTime: newer}})
	}))
	defer nodeB.Close()

	nodes := []NodeConfig{nodeConfigFor(t, nodeA), nodeConfigFor(t, nodeB)}
	nodes[0].Name, nodes[1].Name = "core-1", "core-2"

	groups, nodeErrs := fetchBackupGroups(nodes)
	if len(nodeErrs) != 0 {
		t.Fatalf("nodeErrs = %v, want none", nodeErrs)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %+v, want 2 entries", groups)
	}
	if groups[0].Name != "backup-b-new.enc" || groups[1].Name != "backup-a-old.enc" {
		t.Errorf("groups not sorted newest-first: %+v", groups)
	}
	if len(groups[0].Nodes) != 1 || len(groups[1].Nodes) != 1 {
		t.Errorf("groups = %+v, want exactly 1 node each (different names, never grouped together)", groups)
	}
}

func TestFetchBackupGroups_SameNameAcrossNodesGroupsTogether(t *testing.T) {
	when := time.Date(2026, 8, 30, 16, 0, 0, 0, time.UTC)
	nodeA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]backupInfo{{Name: "backup-20260830-160000.enc", Size: 100, ModTime: when, Comment: "before cutover"}})
	}))
	defer nodeA.Close()
	nodeB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]backupInfo{{Name: "backup-20260830-160000.enc", Size: 100, ModTime: when}})
	}))
	defer nodeB.Close()

	nodes := []NodeConfig{nodeConfigFor(t, nodeA), nodeConfigFor(t, nodeB)}
	nodes[0].Name, nodes[1].Name = "core-1", "core-2"

	groups, _ := fetchBackupGroups(nodes)
	if len(groups) != 1 {
		t.Fatalf("groups = %+v, want exactly 1 group (same filename on both nodes)", groups)
	}
	g := groups[0]
	if len(g.Nodes) != 2 {
		t.Fatalf("group.Nodes = %+v, want both worker-a and worker-b", g.Nodes)
	}
	if g.Comment != "before cutover" {
		t.Errorf("group.Comment = %q, want %q (from whichever node's copy carried one)", g.Comment, "before cutover")
	}
}

// TestFetchBackupGroups_AutomatedPropagatesFromAnyNode mirrors the
// Comment-propagation test above for the Automated marker.
func TestFetchBackupGroups_AutomatedPropagatesFromAnyNode(t *testing.T) {
	when := time.Date(2026, 8, 31, 4, 1, 25, 0, time.UTC)
	nodeA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]backupInfo{{Name: "backup-20260831-020125.enc", Size: 100, ModTime: when, Automated: true}})
	}))
	defer nodeA.Close()
	nodeB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]backupInfo{{Name: "backup-20260831-020125.enc", Size: 100, ModTime: when}})
	}))
	defer nodeB.Close()

	nodes := []NodeConfig{nodeConfigFor(t, nodeA), nodeConfigFor(t, nodeB)}
	nodes[0].Name, nodes[1].Name = "core-1", "core-2"

	groups, _ := fetchBackupGroups(nodes)
	if len(groups) != 1 {
		t.Fatalf("groups = %+v, want exactly 1 group", groups)
	}
	if !groups[0].Automated {
		t.Errorf("group.Automated = false, want true (worker-a's own copy reported it)")
	}
}

// TestFetchBackupGroups_UnreachableNodeDegradesGracefully confirms one
// down node contributes a readable error line instead of failing the whole
// aggregation.
func TestFetchBackupGroups_UnreachableNodeDegradesGracefully(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]backupInfo{{Name: "backup-ok.enc", Size: 5, ModTime: time.Now()}})
	}))
	defer ok.Close()

	nodes := []NodeConfig{nodeConfigFor(t, ok), {Name: "down-node", Addr: "127.0.0.1:1"}}
	groups, nodeErrs := fetchBackupGroups(nodes)
	if len(groups) != 1 {
		t.Fatalf("groups = %+v, want 1 entry from the reachable node", groups)
	}
	if len(nodeErrs) != 1 || !strings.Contains(nodeErrs[0], "down-node") {
		t.Fatalf("nodeErrs = %v, want one entry mentioning down-node", nodeErrs)
	}
}

func buildMultipartBackupUpload(t *testing.T, filename, password string, fileContent []byte) (*http.Request, error) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("password", password); err != nil {
		return nil, err
	}
	fw, err := mw.CreateFormFile("backup_file", filename)
	if err != nil {
		return nil, err
	}
	if _, err := fw.Write(fileContent); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	r := httptest.NewRequest(http.MethodPost, "/backup/restore", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r, nil
}

func TestHandleBackupRestorePost_DecryptsAndStagesCandidate(t *testing.T) {
	restored := config.Cluster{
		ClusterID: "restored-cluster",
		PSK:       "restored-psk",
		Scopes: map[string]config.ScopeConfig{
			"office": {Parent: "ens19", VLANID: 42, NodeIP: "192.168.10.22/24"},
		},
	}
	plaintext, err := json.Marshal(restored)
	if err != nil {
		t.Fatal(err)
	}
	backupDir := t.TempDir()
	info, err := backup.Create(backupDir, "hunter2", plaintext, "", false)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := backup.Read(backupDir, info.Name)
	if err != nil {
		t.Fatal(err)
	}

	live := config.Cluster{ClusterID: "live-cluster"}
	srv, pushed := fakeCandidateNode(t, live)
	defer srv.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{nodeConfigFor(t, srv)}}

	r, err := buildMultipartBackupUpload(t, "backup-20260101-000000.enc", "hunter2", blob)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handleBackupRestorePost(newConfigRef(cfg))(w, r)

	if w.Code >= 400 {
		t.Fatalf("handler returned HTTP %d: %s", w.Code, w.Body.String())
	}
	if pushed.PSK != "restored-psk" {
		t.Errorf("pushed candidate PSK = %q, want %q", pushed.PSK, "restored-psk")
	}
	if len(pushed.Scopes) != 1 {
		t.Errorf("pushed candidate has %d scope(s), want 1", len(pushed.Scopes))
	}
}

// TestHandleBackupRestorePost_DirectFromNodeSkipsUpload checks a restore
// straight from a node needs no file upload.
func TestHandleBackupRestorePost_DirectFromNodeSkipsUpload(t *testing.T) {
	restored := config.Cluster{
		ClusterID: "restored-cluster",
		PSK:       "restored-psk",
		Scopes: map[string]config.ScopeConfig{
			"office": {Parent: "ens19", VLANID: 42, NodeIP: "192.168.10.22/24"},
		},
	}
	plaintext, err := json.Marshal(restored)
	if err != nil {
		t.Fatal(err)
	}
	backupDir := t.TempDir()
	info, err := backup.Create(backupDir, "hunter2", plaintext, "", false)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := backup.Read(backupDir, info.Name)
	if err != nil {
		t.Fatal(err)
	}

	var pushed config.Cluster
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/backups/"+info.Name:
			w.Write(blob)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			json.NewEncoder(w).Encode(map[string]any{"exists": false})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			json.NewDecoder(r.Body).Decode(&pushed)
			json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	n := nodeConfigFor(t, srv)
	n.Name = "core-1"
	cfg := &WebConfig{Nodes: []NodeConfig{n}}

	form := strings.NewReader("node=core-1&name=" + info.Name + "&password=hunter2")
	r := httptest.NewRequest(http.MethodPost, "/backup/restore", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleBackupRestorePost(newConfigRef(cfg))(w, r)

	if w.Code >= 400 {
		t.Fatalf("handler returned HTTP %d: %s", w.Code, w.Body.String())
	}
	if pushed.PSK != "restored-psk" {
		t.Errorf("pushed candidate PSK = %q, want %q (blob should have been fetched server-side, no upload)", pushed.PSK, "restored-psk")
	}
	if len(pushed.Scopes) != 1 {
		t.Errorf("pushed candidate has %d scope(s), want 1", len(pushed.Scopes))
	}
}

func TestHandleBackupRestorePost_DirectFromNodeWrongPasswordPreservesContext(t *testing.T) {
	blob, err := backupcrypt.Encrypt("correct-password", []byte(`{"cluster_id":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(blob)
	}))
	defer srv.Close()
	n := nodeConfigFor(t, srv)
	n.Name = "core-1"
	cfg := &WebConfig{Nodes: []NodeConfig{n}}

	form := strings.NewReader("node=core-1&name=backup-20260101-000000.enc&password=wrong")
	r := httptest.NewRequest(http.MethodPost, "/backup/restore", form)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleBackupRestorePost(newConfigRef(cfg))(w, r)

	body := w.Body.String()
	if !strings.Contains(body, "core-1") {
		t.Errorf("body does not preserve the node context on failure: %s", body)
	}
	if !strings.Contains(body, "backup-20260101-000000.enc") {
		t.Errorf("body does not preserve the name context on failure: %s", body)
	}
}

func TestHandleBackupRestoreGet_QueryParamsPrefillDirectForm(t *testing.T) {
	cfg := &WebConfig{}
	r := httptest.NewRequest(http.MethodGet, "/backup/restore?node=core-1&name=backup-20260101-000000.enc", nil)
	w := httptest.NewRecorder()
	handleBackupRestoreGet(newConfigRef(cfg))(w, r)

	body := w.Body.String()
	if !strings.Contains(body, `value="core-1"`) || !strings.Contains(body, `value="backup-20260101-000000.enc"`) {
		t.Errorf("body does not prefill node/name as hidden fields: %s", body)
	}
	if strings.Contains(body, `enctype="multipart/form-data"`) {
		t.Errorf("direct-from-node restore should not render the upload form: %s", body)
	}
}

// TestHandleBackupRestoreGet_NoQueryParamsShowsUploadForm confirms a plain
// /backup/restore visit (no node/name) still offers the fallback upload
// path.
func TestHandleBackupRestoreGet_NoQueryParamsShowsUploadForm(t *testing.T) {
	cfg := &WebConfig{}
	r := httptest.NewRequest(http.MethodGet, "/backup/restore", nil)
	w := httptest.NewRecorder()
	handleBackupRestoreGet(newConfigRef(cfg))(w, r)

	if !strings.Contains(w.Body.String(), `enctype="multipart/form-data"`) {
		t.Errorf("plain /backup/restore should show the upload form: %s", w.Body.String())
	}
}

// TestHandleBackupRestorePost_WrongPasswordShowsErrorNotCrash confirms a
// wrong password produces a real, readable error page.
func TestHandleBackupRestorePost_WrongPasswordShowsErrorNotCrash(t *testing.T) {
	blob, err := backupcrypt.Encrypt("correct-password", []byte(`{"cluster_id":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &WebConfig{}
	r, err := buildMultipartBackupUpload(t, "backup-20260101-000000.enc", "wrong-password", blob)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handleBackupRestorePost(newConfigRef(cfg))(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (a decrypt failure renders a normal page with an inline error, not an HTTP error)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "wrong password") {
		t.Errorf("body does not mention the wrong-password error: %s", w.Body.String())
	}
}
