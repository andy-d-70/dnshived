// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"dnshived/internal/backupcrypt"
	"dnshived/internal/config"
	"dnshived/internal/configimport"
)

const (
	importStashMax = 3
	importStashTTL = 30 * time.Minute
)

type importStashItem struct {
	src  *configimport.Source
	user string
	name string
	at   time.Time
}

type importStashT struct {
	mu    sync.Mutex
	items map[string]importStashItem
}

var importStash = &importStashT{items: map[string]importStashItem{}}

func (s *importStashT) put(user, name string, src *configimport.Source) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, it := range s.items {
		if now.Sub(it.at) > importStashTTL {
			delete(s.items, k)
		}
	}
	for len(s.items) >= importStashMax {
		oldest, at := "", now
		for k, it := range s.items {
			if it.at.Before(at) {
				oldest, at = k, it.at
			}
		}
		delete(s.items, oldest)
	}
	s.items[tok] = importStashItem{src: src, user: user, name: name, at: now}
	return tok, nil
}

func (s *importStashT) get(tok, user string) (importStashItem, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.items[tok]
	if !ok || it.user != user || time.Since(it.at) > importStashTTL {
		return importStashItem{}, false
	}
	return it, true
}

type cfgImportGroupRow struct {
	Key     string
	Label   string
	Count   int
	Checked bool
	Mode    string
}

type cfgImportPage struct {
	Title     string
	Error     string
	Token     string
	FileName  string
	ClusterID string
	Ignored   string
	Groups    []cfgImportGroupRow
	Scopes    []string
	Report    []cfgImportReportRow
	HasReport bool
	Changes   int
	Hidden    []formField
}

type cfgImportReportRow struct {
	Label     string
	Mode      string
	Added     []string
	Changed   []string
	Removed   []string
	Skipped   []string
	Notes     []string
	Unchanged int
}

var cfgImportTmpl = template.Must(template.New("import").Funcs(template.FuncMap{}).Parse(`<!doctype html>
<title>dnshived-web — import</title>
` + styleHTML + `
` + navHTML + `
<div class="pagehead"><h1>Import configuration</h1></div>
<p><a href="/backup#tab-export">&larr; Maintenance, Export &amp; import</a></p>
{{if .Error}}<p class="crit">{{.Error}}</p>{{end}}
{{if not .Token}}
<p>Import data from an export file of another cluster, or from this one. The file's cluster key, API tokens, certificates, trusted hosts and node identity are never used. Scopes arrive <b>parked</b> (kept, but nothing is built until you enable them), existing scopes are never touched, and nothing is applied until you commit the pending change.</p>
<form method="post" action="/config/import/upload" enctype="multipart/form-data">
<p><input type="file" name="file" required> <button type="submit" class="btn-primary">Read file</button></p>
<p><label>Password, only for an encrypted backup file: <input type="password" name="password" autocomplete="off" size="30"></label></p>
<p class="dim">An export (data, all, cluster or scopes), a cluster.json or a backup, at most 64 MiB. Export &ldquo;data&rdquo; on the other cluster is the right file for a copy; a backup is read for its configuration only.</p>
</form>
{{else if not .HasReport}}
<p>File <b>{{.FileName}}</b>{{if .ClusterID}} from cluster <b>{{.ClusterID}}</b>{{end}}.{{if .Ignored}} Not used: {{.Ignored}}.{{end}}</p>
<form method="post" action="/config/import/preview">
<input type="hidden" name="t" value="{{.Token}}">
<table class="list-table" border="1" cellpadding="4" cellspacing="0">
<tr><th>Take</th><th>What</th><th>In the file</th><th>If it exists here</th></tr>
{{range .Groups}}<tr><td style="text-align:center"><input type="checkbox" name="g_{{.Key}}" id="g_{{.Key}}"{{if .Checked}} checked{{end}}></td><td><label for="g_{{.Key}}">{{.Label}}</label>{{if eq .Key "platform"}}<br><span class="warn">Takes the interface names and the management VIP of the file. Do not tick this while the cluster the file came from is running: both would claim the same VIP.</span>{{end}}</td><td>{{.Count}}</td>
<td><label><input type="radio" name="m_{{.Key}}" value="merge" checked> Merge (keep what the file does not mention)</label> <label><input type="radio" name="m_{{.Key}}" value="replace"> Replace</label></td></tr>
{{end}}
</table>
{{if .Scopes}}<h3>Scopes</h3>
<p class="dim">Tick the scopes to take; none ticked means all. Replace never touches a live scope; it only removes parked scopes the file lacks, and only when no scope is ticked.</p>
<p>{{range .Scopes}}<label style="margin-right:1rem"><input type="checkbox" name="scope" value="{{.}}"> {{.}}</label>{{end}}</p>
{{end}}
<p><button type="submit" class="btn-primary">Show what will happen</button></p>
</form>
{{else}}
<p>File <b>{{.FileName}}</b>. Nothing is staged yet.</p>
{{range .Report}}<h3>{{.Label}} <span class="dim">({{.Mode}})</span></h3>
<ul>
{{range .Added}}<li>new: {{.}}</li>{{end}}{{range .Changed}}<li>changed: {{.}}</li>{{end}}{{range .Removed}}<li>removed: {{.}}</li>{{end}}{{range .Skipped}}<li class="dim">skipped: {{.}}</li>{{end}}{{range .Notes}}<li class="warn">note: {{.}}</li>{{end}}
{{if .Unchanged}}<li class="dim">{{.Unchanged}} unchanged</li>{{end}}
</ul>
{{end}}
{{if .Changes}}
<form method="post" action="/config/import/stage">
{{range .Hidden}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">{{end}}
<p><button type="submit" class="btn-primary">Stage as pending change</button> <a href="/config/import?t={{.Token}}">Back</a></p>
</form>
{{else}}<p>The file brings nothing new with these choices. <a href="/config/import">Choose another file</a></p>{{end}}
{{end}}
`))

func importHandlerUser(r *http.Request) string {
	u, ok := userFromContext(r)
	if !ok {
		return ""
	}
	return u.Name
}

func handleImportGet(w http.ResponseWriter, r *http.Request) {
	page := cfgImportPage{}
	if t := r.URL.Query().Get("t"); t != "" {
		it, ok := importStash.get(t, importHandlerUser(r))
		if !ok {
			page.Error = "The file is no longer held (it is kept for 30 minutes). Choose it again."
		} else {
			fillImportChoice(&page, t, it)
		}
	}
	renderCfgImport(w, page)
}

func fillImportChoice(page *cfgImportPage, tok string, it importStashItem) {
	page.Token, page.FileName, page.ClusterID = tok, it.name, it.src.Cluster.ClusterID
	page.Ignored = strings.Join(it.src.IgnoredSecrets, ", ")
	counts := it.src.Counts()
	for _, g := range configimport.AllGroups {
		n := counts[g]
		if n == 0 {
			continue
		}
		page.Groups = append(page.Groups, cfgImportGroupRow{Key: string(g), Label: g.Label(), Count: n, Checked: g != configimport.GroupPlatform && g != configimport.GroupSettings})
	}
	page.Scopes = it.src.ScopeNames()
}

func renderCfgImport(w http.ResponseWriter, page cfgImportPage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := cfgImportTmpl.Execute(w, page); err != nil {
		http.Error(w, "render: "+err.Error(), http.StatusInternalServerError)
	}
}

// openBackupForImport decrypts a backup under the restore page's own guess limits.
func openBackupForImport(r *http.Request, blob []byte, password string) (*configimport.Source, error) {
	if password == "" {
		return nil, configimport.ErrNeedPassword
	}
	user, _ := userFromContext(r)
	key := user.Name + "|" + clientAddr(r)
	if wait := restoreLimiter.retryAfter(key, time.Now()); wait > 0 {
		return nil, errors.New(restoreLockedText)
	}
	select {
	case restoreSlot <- struct{}{}:
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
	defer func() { <-restoreSlot }()
	if wait := restoreLimiter.retryAfter(key, time.Now()); wait > 0 {
		return nil, errors.New(restoreLockedText)
	}
	src, err := configimport.ParseBackup(blob, password)
	if err != nil && errors.Is(err, backupcrypt.ErrWrongPasswordOrCorrupt) {
		restoreLimiter.fail(key, time.Now())
	}
	return src, err
}

func handleImportUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, configimport.MaxFileBytes+(1<<20))
	f, hdr, err := r.FormFile("file")
	if err != nil {
		renderCfgImport(w, cfgImportPage{Error: "No file received: " + err.Error()})
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, configimport.MaxFileBytes+1))
	if err != nil {
		renderCfgImport(w, cfgImportPage{Error: "Could not read the file: " + err.Error()})
		return
	}
	var src *configimport.Source
	if configimport.LooksEncrypted(data) {
		src, err = openBackupForImport(r, data, r.FormValue("password"))
	} else {
		src, err = configimport.Parse(data)
	}
	if err != nil {
		renderCfgImport(w, cfgImportPage{Error: err.Error()})
		return
	}
	name := hdr.Filename
	if len(name) > 120 {
		name = name[:120]
	}
	tok, err := importStash.put(importHandlerUser(r), name, src)
	if err != nil {
		http.Error(w, "could not hold the file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/config/import?t="+tok, http.StatusSeeOther)
}

// importOptionsFrom reads the checklist the choice page posts.
func importOptionsFrom(r *http.Request, src *configimport.Source) (configimport.Options, []formField) {
	opt := configimport.Options{Groups: map[configimport.Group]configimport.Mode{}}
	var hidden []formField
	for _, g := range configimport.AllGroups {
		if r.PostForm.Get("g_"+string(g)) == "" {
			continue
		}
		m := configimport.Mode(r.PostForm.Get("m_" + string(g)))
		if m != configimport.Replace {
			m = configimport.Merge
		}
		opt.Groups[g] = m
		hidden = append(hidden, formField{"g_" + string(g), "on"}, formField{"m_" + string(g), string(m)})
	}
	known := map[string]bool{}
	for _, n := range src.ScopeNames() {
		known[n] = true
	}
	for _, n := range r.PostForm["scope"] {
		if known[n] {
			opt.Scopes = append(opt.Scopes, n)
			hidden = append(hidden, formField{"scope", n})
		}
	}
	return opt, hidden
}

func buildImportReport(rep configimport.Report) []cfgImportReportRow {
	rows := make([]cfgImportReportRow, 0, len(rep.Groups))
	capList := func(l []string) []string {
		if len(l) > 40 {
			return append(append([]string(nil), l[:40]...), fmt.Sprintf("… and %d more", len(l)-40))
		}
		return l
	}
	for _, g := range rep.Groups {
		rows = append(rows, cfgImportReportRow{Label: g.Group.Label(), Mode: string(g.Mode), Added: capList(g.Added), Changed: capList(g.Changed), Removed: capList(g.Removed), Skipped: capList(g.Skipped), Notes: g.Notes, Unchanged: g.Unchanged})
	}
	return rows
}

func importCurrent(ref *configRef) (config.Cluster, *WebConfig, error) {
	cfg := ref.Load()
	current, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
	return current, cfg, err
}

func handleImportPreview(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		tok := r.PostForm.Get("t")
		it, ok := importStash.get(tok, importHandlerUser(r))
		if !ok {
			renderCfgImport(w, cfgImportPage{Error: "The file is no longer held (it is kept for 30 minutes). Choose it again."})
			return
		}
		opt, hidden := importOptionsFrom(r, it.src)
		page := cfgImportPage{Token: tok, FileName: it.name, HasReport: true}
		if len(opt.Groups) == 0 {
			fillImportChoice(&page, tok, it)
			page.HasReport = false
			page.Error = "Tick at least one group."
			renderCfgImport(w, page)
			return
		}
		current, _, err := importCurrent(ref)
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		_, rep, err := configimport.Apply(current, it.src, opt)
		if err != nil {
			http.Error(w, "import: "+err.Error(), http.StatusBadRequest)
			return
		}
		page.Report = buildImportReport(rep)
		page.Changes = rep.Changes()
		page.Hidden = append([]formField{{"t", tok}}, hidden...)
		renderCfgImport(w, page)
	}
}

func handleImportStage(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		it, ok := importStash.get(r.PostForm.Get("t"), importHandlerUser(r))
		if !ok {
			renderCfgImport(w, cfgImportPage{Error: "The file is no longer held (it is kept for 30 minutes). Choose it again."})
			return
		}
		opt, _ := importOptionsFrom(r, it.src)
		if len(opt.Groups) == 0 {
			http.Error(w, "no group chosen", http.StatusBadRequest)
			return
		}
		current, cfg, err := importCurrent(ref)
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		out, rep, err := configimport.Apply(current, it.src, opt)
		if err != nil {
			http.Error(w, "import: "+err.Error(), http.StatusBadRequest)
			return
		}
		if rep.Changes() == 0 {
			http.Redirect(w, r, "/config/import?t="+url.QueryEscape(r.PostForm.Get("t")), http.StatusSeeOther)
			return
		}
		payload := clusterPushPayloadFrom(out)
		payload.Scopes = out.Scopes
		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/pending", "to the pending changes")
	}
}
