// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"dnshived/internal/backup"
	"dnshived/internal/backupcrypt"
)

// backupInfo mirrors internal/backup.Info's JSON shape exactly.
type backupInfo struct {
	Name      string    `json:"Name"`
	Size      int64     `json:"Size"`
	ModTime   time.Time `json:"ModTime"`
	Comment   string    `json:"Comment"`
	Automated bool      `json:"Automated"`
}

// backupGroupNode is one node's own copy of a given backup revision —
// nested inside backupGroup below.
type backupGroupNode struct {
	Node         NodeConfig
	NodeClass    string // roleClass(Node.Name), precomputed
	NodeDisplay  string
	DownloadPath string
}

// backupGroup is every node's own copy of the SAME backup revision,
// collapsed into one row.
type backupGroup struct {
	Name    string
	Comment string // from whichever node's own copy carries one — see fetchBackupGroups
	// Automated reports whether ANY node's own copy of this revision was
	// written by the automated ticker.
	Automated bool
	ModTime   time.Time
	Size      int64
	Nodes     []backupGroupNode
	// RestorePath links to /backup/restore?node=&name=, pre-filled against
	// WHICHEVER node in Nodes happens to be first.
	RestorePath string
}

type backupPageData struct {
	SourceNode string
	ClusterID  string

	BackupEnabled          bool
	BackupIntervalHours    int
	BackupRetentionCount   int
	BackupPassword         string
	BackupReplicateToPeers bool

	Groups        []backupGroup
	NodeErrors    []string // "worker-b: connection refused" — surfaced but never blocking
	CheckErrors   []string
	CheckWarnings []string

	// CreateAttempted/CreateOK/CreateFailed are set only right after a "Back
	// up now" submit redirected here (see handleBackupCreatePost).
	CreateAttempted bool
	CreateOK        int
	CreateFailed    []string
}

var backupTmpl = template.Must(template.New("backup").Parse(`<!doctype html>
<title>dnshived-web — config management</title>
` + styleHTML + `
<h1>Config management</h1>
` + navHTML + `
<p>Snapshot from node: <strong>{{.SourceNode}}</strong> (cluster:
<strong>{{.ClusterID}}</strong>).</p>

<h2>Export</h2>
<p>
<a href="/config/export?mode=all">Export all</a> —
<a href="/config/export?mode=cluster">Export cluster identity</a> (no scopes) —
<a href="/config/export?mode=scopes">Export scopes only</a> (no PSK/tokens)
</p>

<h2>Backup</h2>
{{range .CheckErrors}}<p class="crit">error: {{.}}</p>{{end}}
{{range .CheckWarnings}}<p class="warn">warning: {{.}}</p>{{end}}

<h3>Automated backups</h3>
<p class="dim">Only the arbiter node originates an automated backup
(zero scope-serving load, already this cluster's coordinator for
other cluster-wide concerns) — every node's config is supposed to be
identical anyway (a mismatch shows up on Overview's own coherence
check), so one origin already captures the whole cluster; "spread to
every node" below is what gets it onto the other nodes too. Runs on
real fixed UTC time slots (cron-style), not "N hours after whenever it
last happened to run" — a 2-hour interval always lands on
00:00/02:00/04:00/.../22:00 UTC, so the actual gap between backups
never drifts. While the arbiter itself is unreachable, no automated
backup runs anywhere until it's back — "back up now" below is
unaffected and always available on any reachable node regardless.</p>
<form method="post" action="/backup/settings">
<table>
<tr><td>enabled</td><td><input type="checkbox" name="backup_enabled" {{if .BackupEnabled}}checked{{end}}></td></tr>
<tr><td>interval (hours)</td><td><input type="number" min="1" name="backup_interval_hours" value="{{.BackupIntervalHours}}" placeholder="24"></td></tr>
<tr><td>keep (count) <span class="info-ico" title="only counts automated backups toward this limit — a manual &quot;back up now&quot; backup is never pruned by this setting, regardless of age">ⓘ</span></td><td><input type="number" min="1" name="backup_retention_count" value="{{.BackupRetentionCount}}" placeholder="14"></td></tr>
<tr><td>encryption password</td><td><input type="password" name="backup_password" value="" size="40" autocomplete="new-password" placeholder="{{if .BackupPassword}}unchanged{{else}}not set{{end}}" title="The backup password is never sent to the browser. Leave blank to keep the current one."></td></tr>
<tr><td>spread to every node <span class="info-ico" title="pushes each backup the arbiter writes to every other reachable node too, still encrypted — for real disaster recovery, so a node's own snapshot history survives even if that specific node is later destroyed. Only covers backups created from now on.">ⓘ</span></td><td><input type="checkbox" name="backup_replicate_to_peers" {{if .BackupReplicateToPeers}}checked{{end}}></td></tr>
</table>
<p class="dim">"Spread to every node" pushes each backup the arbiter
writes to every other reachable node too, still encrypted — for real
disaster recovery, so a node's own snapshot history survives even if
that specific node is later destroyed, not just recoverable from it.
Only covers backups created FROM NOW ON — a node onboarded later never
retroactively receives backups that already existed before it
joined.</p>
<button type="submit">Save</button>
</form>

<h3>Backup now</h3>
{{if .CreateAttempted}}
{{if .CreateFailed}}
<p class="warn">Backed up {{.CreateOK}} node(s); failed on: {{range $i, $n := .CreateFailed}}{{if $i}}, {{end}}{{$n}}{{end}}.</p>
{{else}}
<p class="ok">Backed up {{.CreateOK}} node(s) successfully.</p>
{{end}}
{{end}}
<p class="dim">Takes a snapshot on every reachable node right now,
using whatever password you type below — independent of the
automated-backup password above, so you can take a one-off backup
before a risky change without ever enabling the scheduler. An optional
comment shows up next to this backup in the list below, on every
node's own copy.</p>
<form method="post" action="/backup/create">
<input type="password" name="password" placeholder="encryption password" size="40" autocomplete="off" required>
<input type="text" name="comment" placeholder="comment (optional) — e.g. before DNS relay cutover" size="50">
<button type="submit">Back up now</button>
</form>

<h3>Existing backups</h3>
<p class="dim">Every node's own copy of the same backup (same
filename — every "back up now" click fires at once on every reachable
node) is grouped into one row here — delete removes it from every
node in one click, not one at a time.</p>
{{range .NodeErrors}}<p class="dim">{{.}}</p>{{end}}
{{if .Groups}}
<div class="table-wrap">
<table>
<tr><th>Filename</th><th>Source</th><th>Comment</th><th>Size</th><th>Written</th><th>On</th><th></th><th></th></tr>
{{range .Groups}}
<tr>
<td>{{.Name}}</td>
<td>{{if .Automated}}<span class="dim">automatic</span>{{else}}manual{{end}}</td>
<td>{{if .Comment}}{{.Comment}}{{else}}<span class="dim">—</span>{{end}}</td>
<td>{{.Size}} bytes</td>
<td>{{.ModTime.Format "2006-01-02 15:04:05"}}</td>
<td>
{{range $i, $n := .Nodes}}{{if $i}} <span class="dim">|</span> {{end}}<a class="{{$n.NodeClass}}" href="{{$n.DownloadPath}}" title="download from {{$n.NodeDisplay}}">{{$n.NodeDisplay}}</a>{{end}}
</td>
<td><a href="{{.RestorePath}}">restore</a></td>
<td>
<form method="post" action="/backup/delete-group/{{.Name}}" onsubmit="return confirm('Delete {{.Name}} from every node?')">
<button type="submit">delete (all nodes)</button>
</form>
</td>
</tr>
{{end}}
</table>
</div>
{{else}}
<p class="dim">No backups yet on any reachable node.</p>
{{end}}

<h2>Restore</h2>
<p><a href="/backup/restore">Restore from a backup file</a> — decrypts an
uploaded backup and stages the difference against the current live
config as an ordinary pending change, reviewed and committed exactly
like any other config edit.</p>

<h2>Import</h2>
<p class="dim">Not built yet — no design exists for this either.</p>
`))

func handleBackup(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		nodes := nodesIncludingSelf(cfg)
		c, node, err := firstReachableConfig(nodes)
		if err != nil {
			http.Error(w, "could not read config from any node: "+err.Error(), http.StatusBadGateway)
			return
		}
		groups, nodeErrs := fetchBackupGroups(nodes)
		data := backupPageData{
			SourceNode:             node.Name,
			ClusterID:              c.ClusterID,
			BackupEnabled:          c.BackupEnabled,
			BackupIntervalHours:    c.BackupIntervalHours,
			BackupRetentionCount:   c.BackupRetentionCount,
			BackupPassword:         maskedSecret(c.BackupPassword),
			BackupReplicateToPeers: c.BackupReplicateToPeers,
			Groups:                 groups,
			NodeErrors:             nodeErrs,
		}
		if v := r.URL.Query().Get("backup_ok"); v != "" {
			data.CreateAttempted = true
			data.CreateOK, _ = strconv.Atoi(v)
			if f := r.URL.Query().Get("backup_failed"); f != "" {
				data.CreateFailed = strings.Split(f, ",")
			}
		}
		renderTemplate(w, backupTmpl, data, "backup")
	}
}

func fetchBackupGroups(nodes []NodeConfig) (groups []backupGroup, nodeErrs []string) {
	type result struct {
		node  NodeConfig
		infos []backupInfo
		err   error
	}
	results := make([]result, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n NodeConfig) {
			defer wg.Done()
			results[i].node = n
			infos, err := fetchBackupList(n)
			results[i].infos = infos
			results[i].err = err
		}(i, n)
	}
	wg.Wait()

	byName := make(map[string]*backupGroup)
	var order []string
	for _, res := range results {
		if res.err != nil {
			nodeErrs = append(nodeErrs, res.node.displayName()+": "+res.err.Error())
			continue
		}
		for _, info := range res.infos {
			g, ok := byName[info.Name]
			if !ok {
				g = &backupGroup{Name: info.Name, ModTime: info.ModTime, Size: info.Size}
				byName[info.Name] = g
				order = append(order, info.Name)
			}
			if info.Comment != "" && g.Comment == "" {
				g.Comment = info.Comment
			}
			if info.Automated {
				g.Automated = true
			}
			if info.ModTime.After(g.ModTime) {
				g.ModTime = info.ModTime
			}
			g.Nodes = append(g.Nodes, backupGroupNode{
				Node:         res.node,
				NodeClass:    roleClass(res.node.Name),
				NodeDisplay:  res.node.displayName(),
				DownloadPath: "/backup/download/" + res.node.Name + "/" + info.Name,
			})
		}
	}
	for _, name := range order {
		g := *byName[name]
		if len(g.Nodes) > 0 {
			g.RestorePath = "/backup/restore?node=" + g.Nodes[0].Node.Name + "&name=" + g.Name
		}
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].ModTime.After(groups[j].ModTime) })
	return groups, nodeErrs
}

// backupListEntry is the JSON shape handleBackupListAPI returns.
type backupListEntry struct {
	Node       string    `json:"node"`
	Name       string    `json:"name"`
	Size       int64     `json:"size"`
	ModTime    time.Time `json:"mod_time"`
	Comment    string    `json:"comment"`
	Automated  bool      `json:"automated"`
	Downloaded string    `json:"download_path"`
}

// handleBackupListAPI is the script-friendly counterpart to the HTML
// backup table on /backup.
func handleBackupListAPI(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		groups, nodeErrs := fetchBackupGroups(nodesIncludingSelf(cfg))
		out := make([]backupListEntry, 0)
		for _, g := range groups {
			for _, n := range g.Nodes {
				out = append(out, backupListEntry{
					Node:       n.Node.Name,
					Name:       g.Name,
					Size:       g.Size,
					ModTime:    g.ModTime,
					Comment:    g.Comment,
					Automated:  g.Automated,
					Downloaded: n.DownloadPath,
				})
			}
		}
		if nodeErrs == nil {
			nodeErrs = []string{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"backups": out, "node_errors": nodeErrs})
	}
}

func fetchBackupList(n NodeConfig) ([]backupInfo, error) {
	req, err := http.NewRequest(http.MethodGet, n.baseURL()+"/api/v1/backups", nil)
	if err != nil {
		return nil, err
	}
	if n.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.AdminToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	var infos []backupInfo
	if err := json.NewDecoder(resp.Body).Decode(&infos); err != nil {
		return nil, err
	}
	return infos, nil
}

// handleBackupSettingsPost stages the automated-backup settings
// (enabled/interval/retention/password) as a pending change.
func handleBackupSettingsPost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		current, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		payload := clusterPushPayloadFrom(current)
		payload.Scopes = current.Scopes
		payload.BackupEnabled = r.PostForm.Get("backup_enabled") != ""
		payload.BackupIntervalHours, _ = strconv.Atoi(r.PostForm.Get("backup_interval_hours"))
		payload.BackupRetentionCount, _ = strconv.Atoi(r.PostForm.Get("backup_retention_count"))
		if pw := r.PostForm.Get("backup_password"); pw != "" {
			payload.BackupPassword = pw
		}
		payload.BackupReplicateToPeers = r.PostForm.Get("backup_replicate_to_peers") != ""

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/backup", "back to config management")
	}
}

// handleBackupCreatePost fans out POST /api/v1/backups to every reachable
// node with the operator-typed password from the form.
func handleBackupCreatePost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		password := r.PostForm.Get("password")
		if password == "" {
			http.Error(w, "password is required", http.StatusBadRequest)
			return
		}
		comment := r.PostForm.Get("comment")

		var wg sync.WaitGroup
		var mu sync.Mutex
		var ok int
		var failed []string
		for _, n := range nodesIncludingSelf(cfg) {
			wg.Add(1)
			go func(n NodeConfig) {
				defer wg.Done()
				err := createBackupOnNode(n, password, comment)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					failed = append(failed, n.displayName())
				} else {
					ok++
				}
			}(n)
		}
		wg.Wait()

		q := url.Values{}
		q.Set("backup_ok", strconv.Itoa(ok))
		if len(failed) > 0 {
			q.Set("backup_failed", strings.Join(failed, ","))
		}
		http.Redirect(w, r, "/backup?"+q.Encode(), http.StatusSeeOther)
	}
}

// createBackupOnNode fires the identical create request at n.
func createBackupOnNode(n NodeConfig, password, comment string) error {
	body, err := json.Marshal(map[string]string{"password": password, "comment": comment})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, n.baseURL()+"/api/v1/backups", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if n.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.AdminToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// handleBackupDownload proxies GET /api/v1/backups/{name} on one specific
// node, streaming the still-encrypted bytes straight through.
func handleBackupDownload(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		n, ok := findNodeByName(nodesIncludingSelf(cfg), r.PathValue("node"))
		if !ok {
			http.Error(w, "unknown node", http.StatusNotFound)
			return
		}
		name := r.PathValue("name")
		blob, status, err := fetchBackupBlob(n, name)
		if err != nil {
			http.Error(w, "node unreachable: "+err.Error(), http.StatusBadGateway)
			return
		}
		if status != http.StatusOK {
			http.Error(w, string(blob), status)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Write(blob)
	}
}

// handleBackupDeletePost proxies DELETE /api/v1/backups/{name} on one
// specific node.
func handleBackupDeletePost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		n, ok := findNodeByName(nodesIncludingSelf(cfg), r.PathValue("node"))
		if !ok {
			http.Error(w, "unknown node", http.StatusNotFound)
			return
		}
		name := r.PathValue("name")
		req, err := http.NewRequest(http.MethodDelete, n.baseURL()+"/api/v1/backups/"+name, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if n.AdminToken != "" {
			req.Header.Set("Authorization", "Bearer "+n.AdminToken)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			http.Error(w, "node unreachable: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			http.Error(w, string(body), resp.StatusCode)
			return
		}
		http.Redirect(w, r, "/backup", http.StatusSeeOther)
	}
}

// handleBackupDeleteGroup fans DELETE /api/v1/backups/{name} out to EVERY
// configured node at once.
func handleBackupDeleteGroup(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		name := r.PathValue("name")
		var wg sync.WaitGroup
		var mu sync.Mutex
		var failed []string
		for _, n := range nodesIncludingSelf(cfg) {
			wg.Add(1)
			go func(n NodeConfig) {
				defer wg.Done()
				err := deleteBackupOnNode(n, name)
				if err == nil {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				failed = append(failed, n.displayName())
			}(n)
		}
		wg.Wait()

		if len(failed) > 0 {
			http.Error(w, "failed to delete "+name+" on: "+strings.Join(failed, ", "), http.StatusBadGateway)
			return
		}
		http.Redirect(w, r, "/backup", http.StatusSeeOther)
	}
}

// deleteBackupOnNode returns nil for both a genuine success AND a 404 (the
// node never had this backup).
func deleteBackupOnNode(n NodeConfig, name string) error {
	req, err := http.NewRequest(http.MethodDelete, n.baseURL()+"/api/v1/backups/"+name, nil)
	if err != nil {
		return err
	}
	if n.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.AdminToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// fetchBackupBlob fetches one backup's raw (still-encrypted) bytes from n.
func fetchBackupBlob(n NodeConfig, name string) (blob []byte, status int, err error) {
	req, err := http.NewRequest(http.MethodGet, n.baseURL()+"/api/v1/backups/"+name, nil)
	if err != nil {
		return nil, 0, err
	}
	if n.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.AdminToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}

func findNodeByName(nodes []NodeConfig, name string) (NodeConfig, bool) {
	for _, n := range nodes {
		if n.Name == name {
			return n, true
		}
	}
	return NodeConfig{}, false
}

type restorePageData struct {
	CheckErrors   []string
	CheckWarnings []string
	DecryptError  string
	Node          string
	Name          string
}

// leaseRestoreFieldHTML is the shared "also restore DHCP lease shadow
// data" checkbox.
const leaseRestoreFieldHTML = `<p><label><input type="checkbox" name="restore_leases" value="1"> ` +
	`Also restore DHCP lease shadow data</label> ` +
	`<span class="info-ico" title="off by default: a restored lease is a stale snapshot from whenever the backup was taken, not something a restore should silently bring back just because the backup happens to carry it — real clients renew on their own regardless.">ⓘ</span></p>`

// reliabilityRestoreFieldHTML is the trunk-reliability counterpart of
// leaseRestoreFieldHTML above.
const reliabilityRestoreFieldHTML = `<p><label><input type="checkbox" name="restore_reliability" value="1"> ` +
	`Also restore trunk reliability history</label> ` +
	`<span class="info-ico" title="off by default: a restored trust-index history is a stale snapshot from whenever the backup was taken — bringing it back only matters if you specifically want old flap history to keep influencing failover grace periods; most restores don't need this.">ⓘ</span></p>`

var restoreTmpl = template.Must(template.New("restore").Parse(`<!doctype html>
<title>dnshived-web — restore from backup</title>
` + styleHTML + `
<h1>Restore from backup</h1>
` + navHTML + `
<p><a href="/backup">&larr; back to config management</a></p>

{{if .DecryptError}}<p class="crit">{{.DecryptError}}</p>{{end}}
{{range .CheckErrors}}<p class="crit">error: {{.}}</p>{{end}}
{{range .CheckWarnings}}<p class="warn">warning: {{.}}</p>{{end}}

{{if .Name}}
<p class="dim">Restoring <strong>{{.Name}}</strong> from <strong>{{.Node}}</strong>
directly — no need to download it first. The decrypted config is
diffed against the current live config and staged as an ordinary
pending change; nothing is applied until you review and commit it on
the Pending Changes page, exactly like any other edit in this
package.</p>
<form method="post" action="/backup/restore">
<input type="hidden" name="node" value="{{.Node}}">
<input type="hidden" name="name" value="{{.Name}}">
<p><input type="password" name="password" placeholder="encryption password" size="40" autocomplete="off" required autofocus></p>
` + leaseRestoreFieldHTML + reliabilityRestoreFieldHTML + `
<button type="submit">Decrypt and stage as pending change</button>
</form>
<p><a href="/backup/restore">Restore from an uploaded file instead &rarr;</a></p>
{{else}}
<p class="dim">Upload a previously-downloaded backup file and its
password — for restoring a backup that's no longer on any node (only
a copy you downloaded and kept elsewhere). To restore a backup that's
still on a node, use the "restore" link next to it on the Config
management page instead — no upload needed.</p>
<form method="post" action="/backup/restore" enctype="multipart/form-data">
<p><input type="file" name="backup_file" required></p>
<p><input type="password" name="password" placeholder="encryption password" size="40" autocomplete="off" required></p>
` + leaseRestoreFieldHTML + reliabilityRestoreFieldHTML + `
<button type="submit">Decrypt and stage as pending change</button>
</form>
{{end}}
`))

func handleBackupRestoreGet(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := restorePageData{
			Node: r.URL.Query().Get("node"),
			Name: r.URL.Query().Get("name"),
		}
		renderTemplate(w, restoreTmpl, data, "restore")
	}
}

// handleBackupRestorePost decrypts a backup blob.
func handleBackupRestorePost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		var blob []byte
		var password, nodeName, name string

		if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
			if err := r.ParseMultipartForm(32 << 20); err != nil {
				http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
				return
			}
			password = r.FormValue("password")
			file, _, err := r.FormFile("backup_file")
			if err != nil {
				http.Error(w, "backup_file is required: "+err.Error(), http.StatusBadRequest)
				return
			}
			defer file.Close()
			blob, err = io.ReadAll(file)
			if err != nil {
				http.Error(w, "read upload: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
				return
			}
			password = r.PostForm.Get("password")
			nodeName = r.PostForm.Get("node")
			name = r.PostForm.Get("name")
			n, ok := findNodeByName(nodesIncludingSelf(cfg), nodeName)
			if !ok {
				http.Error(w, "unknown node", http.StatusBadRequest)
				return
			}
			fetched, status, err := fetchBackupBlob(n, name)
			if err != nil {
				renderTemplate(w, restoreTmpl, restorePageData{
					DecryptError: "fetch from " + nodeName + ": " + err.Error(), Node: nodeName, Name: name,
				}, "restore")
				return
			}
			if status != http.StatusOK {
				renderTemplate(w, restoreTmpl, restorePageData{
					DecryptError: "fetch from " + nodeName + ": status " + strconv.Itoa(status) + ": " + string(fetched),
					Node:         nodeName, Name: name,
				}, "restore")
				return
			}
			blob = fetched
		}

		compressed, err := backupcrypt.Decrypt(password, blob)
		if err != nil {
			renderTemplate(w, restoreTmpl, restorePageData{DecryptError: err.Error(), Node: nodeName, Name: name}, "restore")
			return
		}
		plaintext, err := backup.Decompress(compressed)
		if err != nil {
			renderTemplate(w, restoreTmpl, restorePageData{DecryptError: "decrypted content is not a valid backup: " + err.Error(), Node: nodeName, Name: name}, "restore")
			return
		}
		var restored backup.Payload
		if err := json.Unmarshal(plaintext, &restored); err != nil {
			renderTemplate(w, restoreTmpl, restorePageData{DecryptError: "decrypted content is not a valid backup: " + err.Error(), Node: nodeName, Name: name}, "restore")
			return
		}

		payload := clusterPushPayloadFrom(restored.Cluster)
		payload.Scopes = restored.Cluster.Scopes

		if r.PostFormValue("restore_leases") != "" && restored.DHCPLeases != nil && len(restored.DHCPLeases.Leases) > 0 {
			if self, ok := selfNodeConfig(cfg); ok {
				if err := restoreLeasesOnNode(self, restored.DHCPLeases.Leases); err != nil {
					log.Printf("[BACKUP] restore lease shadow data on %s: %v", self.displayName(), err)
				}
			}
		}

		if r.PostFormValue("restore_reliability") != "" && restored.Reliability != nil {
			if self, ok := selfNodeConfig(cfg); ok {
				if err := restoreReliabilityOnNode(self, *restored.Reliability); err != nil {
					log.Printf("[BACKUP] restore reliability history on %s: %v", self.displayName(), err)
				}
			}
		}

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/backup", "back to config management")
	}
}

// restoreLeasesOnNode POSTs leases to n's own POST /api/v1/leasesync/
// restore — mirrors createBackupOnNode's own request shape exactly.
func restoreLeasesOnNode(n NodeConfig, leases []backup.LeaseEntry) error {
	body, err := json.Marshal(map[string][]backup.LeaseEntry{"leases": leases})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, n.baseURL()+"/api/v1/leasesync/restore", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if n.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.AdminToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// restoreReliabilityOnNode POSTs a trunk-reliability snapshot to n's own
// POST /api/v1/reliability/restore.
func restoreReliabilityOnNode(n NodeConfig, data backup.ReliabilityData) error {
	body, err := json.Marshal(data)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, n.baseURL()+"/api/v1/reliability/restore", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if n.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.AdminToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}
