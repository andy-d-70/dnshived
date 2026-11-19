// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"dnshived/internal/backupcrypt"
	"dnshived/internal/config"
	"dnshived/internal/configimport"
	"dnshived/internal/loglevel"
)

const restoreConfirmWord = "RESTORE"

// setupImport is the optional export file the wizard starts from.
type setupImport struct {
	name   string
	src    *configimport.Source
	groups map[configimport.Group]bool
	keepID bool
}

type setupImportGroup struct {
	Key     string
	Label   string
	Count   int
	Checked bool
}

type setupImportView struct {
	FileName  string
	ClusterID string
	Ignored   string
	Groups    []setupImportGroup
	KeepID    bool
	Answering []string
	Chosen    bool
}

// bootstrapImportGroups are the groups offered at bootstrap; the platform comes from the wizard's
// own interface detection.
var bootstrapImportGroups = []configimport.Group{
	configimport.GroupScopes, configimport.GroupDomains, configimport.GroupDNS,
	configimport.GroupDHCP, configimport.GroupAccess, configimport.GroupSettings,
}

func (b *builderState) setImport(name string, src *configimport.Source) {
	groups := map[configimport.Group]bool{}
	for g := range src.Counts() {
		for _, ok := range bootstrapImportGroups {
			if g == ok {
				groups[g] = true
			}
		}
	}
	b.mu.Lock()
	b.imp = &setupImport{name: name, src: src, groups: groups}
	b.mu.Unlock()
}

func (b *builderState) clearImport() {
	b.mu.Lock()
	b.imp = nil
	b.mu.Unlock()
}

func (b *builderState) importCopy() *setupImport {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.imp == nil {
		return nil
	}
	c := *b.imp
	c.groups = make(map[configimport.Group]bool, len(b.imp.groups))
	for g, v := range b.imp.groups {
		c.groups[g] = v
	}
	return &c
}

func (b *builderState) setImportChoice(groups map[configimport.Group]bool, keepID bool) {
	b.mu.Lock()
	if b.imp != nil {
		b.imp.groups, b.imp.keepID = groups, keepID
	}
	b.mu.Unlock()
}

func (b *builderState) importView(selfAddr string) *setupImportView {
	imp := b.importCopy()
	if imp == nil {
		return nil
	}
	v := &setupImportView{FileName: imp.name, ClusterID: imp.src.Cluster.ClusterID, Ignored: strings.Join(imp.src.IgnoredSecrets, ", "), KeepID: imp.keepID}
	counts := imp.src.Counts()
	for _, g := range bootstrapImportGroups {
		if counts[g] == 0 {
			continue
		}
		v.Groups = append(v.Groups, setupImportGroup{Key: string(g), Label: g.Label(), Count: counts[g], Checked: imp.groups[g]})
	}
	if imp.keepID {
		v.Answering = answeringFileAddresses(&imp.src.Cluster, selfAddr, 800*time.Millisecond)
	}
	return v
}

// answeringFileAddresses lists the control addresses named in the file that accept a connection
// right now, other than this node's own: a sign the original cluster still runs.
func answeringFileAddresses(c *config.Cluster, selfAddr string, timeout time.Duration) []string {
	seen := map[string]bool{}
	var addrs []string
	for _, a := range append([]string{c.ControlAddr}, c.Peers...) {
		a = strings.TrimSpace(a)
		if a == "" || seen[a] || hostOnly(a) == hostOnly(selfAddr) {
			continue
		}
		seen[a] = true
		addrs = append(addrs, a)
		if len(addrs) >= 16 {
			break
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var up []string
	for _, a := range addrs {
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", a, timeout)
			if err != nil {
				return
			}
			conn.Close()
			mu.Lock()
			up = append(up, a)
			mu.Unlock()
		}(a)
	}
	wg.Wait()
	sort.Strings(up)
	return up
}

var backupGuessMu sync.Mutex

// openBackupSerialized opens a backup one at a time and makes every wrong password cost a pause, so
// the join-code-protected page cannot be used to guess a backup password quickly.
func openBackupSerialized(blob []byte, password string) (*configimport.Source, error) {
	backupGuessMu.Lock()
	defer backupGuessMu.Unlock()
	src, err := configimport.ParseBackup(blob, password)
	if err != nil && errors.Is(err, backupcrypt.ErrWrongPasswordOrCorrupt) {
		time.Sleep(backupGuessPause)
	}
	return src, err
}

var backupGuessPause = 1500 * time.Millisecond

func bootstrapImportUploadHandler(hostname, controlPort string, state *builderState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, configimport.MaxFileBytes+(1<<20))
		f, hdr, err := r.FormFile("file")
		if err != nil {
			renderSetupStepError(w, hostname, controlPort, state, stepReview, &setupError{msg: "no file received: " + err.Error()})
			return
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, configimport.MaxFileBytes+1))
		if err != nil {
			renderSetupStepError(w, hostname, controlPort, state, stepReview, &setupError{msg: "could not read the file: " + err.Error()})
			return
		}
		var src *configimport.Source
		if configimport.LooksEncrypted(data) {
			src, err = openBackupSerialized(data, r.FormValue("password"))
		} else {
			src, err = configimport.Parse(data)
		}
		if err != nil {
			loglevel.Warnf("[BOOTSTRAP:ERROR] the import file was refused: %v", err)
			renderSetupStepError(w, hostname, controlPort, state, stepReview, &setupError{msg: err.Error()})
			return
		}
		name := hdr.Filename
		if len(name) > 120 {
			name = name[:120]
		}
		state.setImport(name, src)
		http.Redirect(w, r, "/?step=6", http.StatusSeeOther)
	}
}

func bootstrapImportChooseHandler(hostname, controlPort string, state *builderState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			renderSetupStepError(w, hostname, controlPort, state, stepReview, &setupError{msg: "malformed form: " + err.Error()})
			return
		}
		if state.importCopy() == nil {
			http.Redirect(w, r, "/?step=6", http.StatusSeeOther)
			return
		}
		groups := map[configimport.Group]bool{}
		for _, g := range bootstrapImportGroups {
			if r.PostForm.Get("g_"+string(g)) != "" {
				groups[g] = true
			}
		}
		keep := r.PostForm.Get("keep_id") != ""
		if keep && strings.TrimSpace(r.PostForm.Get("confirm")) != restoreConfirmWord {
			renderSetupStepError(w, hostname, controlPort, state, stepReview, &setupError{msg: "to keep the cluster ID of the file (a restore) type " + restoreConfirmWord + " in the confirmation field"})
			return
		}
		state.setImportChoice(groups, keep)
		http.Redirect(w, r, "/?step=6", http.StatusSeeOther)
	}
}

func bootstrapImportClearHandler(state *builderState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state.clearImport()
		http.Redirect(w, r, "/?step=6", http.StatusSeeOther)
	}
}

// applyBootstrapImport merges the chosen groups of the file into a freshly built configuration.
// Everything that identifies or authenticates the cluster stays as the wizard generated it.
func applyBootstrapImport(cc *config.Cluster, imp *setupImport) (*config.Cluster, error) {
	opt := configimport.Options{Groups: map[configimport.Group]configimport.Mode{}}
	for g, on := range imp.groups {
		if on {
			opt.Groups[g] = configimport.Replace
		}
	}
	out, _, err := configimport.Apply(*cc, imp.src, opt)
	if err != nil {
		return nil, err
	}
	if res := out.ValidateExtended(); !res.OK() {
		return nil, fmt.Errorf("the imported data does not validate: %s", strings.Join(res.Errors, "; "))
	}
	return &out, nil
}

const setupImportCardHTML = `<h2>Start from an export file (optional)</h2>
{{if .Import}}
<p>File <strong>{{.Import.FileName}}</strong>{{if .Import.ClusterID}} from cluster <strong>{{.Import.ClusterID}}</strong>{{end}}.{{if .Import.Ignored}} Not used: {{.Import.Ignored}}. This cluster gets a new key, new tokens and new certificates.{{end}}</p>
<form method="post" action="/setup/import/choose">
{{range .Import.Groups}}<label><input type="checkbox" name="g_{{.Key}}"{{if .Checked}} checked{{end}}> {{.Label}} — {{.Count}} in the file</label>{{end}}
<p class="hint">Scopes arrive parked: nothing is built for them until you enable them in the web UI. The network interfaces come from this wizard, not from the file.</p>
<label><input type="checkbox" name="keep_id"{{if .Import.KeepID}} checked{{end}}> Restore: keep the cluster ID of the file</label>
<label>To keep the ID, type RESTORE: <input type="text" name="confirm" autocomplete="off" placeholder="RESTORE"></label>
{{if .Import.KeepID}}{{if .Import.Answering}}<p class="error">These control addresses from the file answer right now: {{range .Import.Answering}}{{.}} {{end}}. The original cluster may still be running. Two servers on the same networks means two DHCP and DNS servers and VRRP on the same VIPs. You decide; the new cluster has its own key, so the old nodes cannot join it.</p>{{else}}<p class="hint">None of the control addresses in the file answers.</p>{{end}}{{end}}
<button type="submit">Save choice</button>
</form>
<form method="post" action="/setup/import/clear"><button type="submit">Do not use the file</button></form>
{{else}}
<p class="hint">Import the data of another cluster (its export file) into the new one. Keys, tokens, certificates and node identity in the file are never used.</p>
<form method="post" action="/setup/import/upload" enctype="multipart/form-data">
<label>Export file or backup: <input type="file" name="file"></label>
<label>Password, only for an encrypted backup: <input type="password" name="password" autocomplete="off"></label>
<button type="submit">Read file</button>
</form>
{{end}}`
