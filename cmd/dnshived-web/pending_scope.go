// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sort"
	"strings"

	"dnshived/internal/changeset"
	"dnshived/internal/config"
)

const (
	confirmCommitAll  = "COMMIT ALL"
	confirmDiscardAll = "DISCARD ALL"
	pendingLinesShown = 6
)

type pendingAuthorGroup struct {
	User  string
	Mine  bool
	Count int
	Lines []string
	More  int
}

type pendingAuthors struct {
	Supported  bool
	Me         string
	MineCount  int
	OtherCount int
	Groups     []pendingAuthorGroup
}

// Show reports whether the page has to say who changed what.
func (a pendingAuthors) Show() bool { return a.Supported && a.OtherCount > 0 }

// OthersGroups is every group that is not the viewer's own.
func (a pendingAuthors) OthersGroups() []pendingAuthorGroup {
	var out []pendingAuthorGroup
	for _, g := range a.Groups {
		if !g.Mine {
			out = append(out, g)
		}
	}
	return out
}

// pendingView is one consistent read of the live document, the staged
// candidate and who changed what.
type pendingView struct {
	live, cand       config.Cluster
	liveTree, candTr any
	authors          map[string]string
	supported        bool
	paths            []string
}

func newPendingView(live config.Cluster, cr candidateResponse) (*pendingView, error) {
	lt, err1 := changeset.TreeMax(live, changeset.MaxDocBytes)
	ct, err2 := changeset.TreeMax(cr.Candidate, changeset.MaxDocBytes)
	if err := errors.Join(err1, err2); err != nil {
		if errors.Is(err, changeset.ErrTooLarge) {
			return &pendingView{live: live, cand: cr.Candidate}, nil
		}
		return nil, err
	}
	return &pendingView{
		live: live, cand: cr.Candidate, liveTree: lt, candTr: ct,
		authors: cr.Authors, supported: cr.Authors != nil,
		paths: changeset.Changes(lt, ct),
	}, nil
}

func (v *pendingView) summary(me string) pendingAuthors {
	out := pendingAuthors{Supported: v.supported, Me: me}
	if !v.supported {
		return out
	}
	by := map[string][]string{}
	for _, p := range v.paths {
		by[v.authors[p]] = append(by[v.authors[p]], changeset.Label(p))
	}
	for user, lines := range by {
		g := pendingAuthorGroup{User: user, Mine: user != "" && user == me, Count: len(lines)}
		sort.Strings(lines)
		g.Lines = lines
		if len(lines) > pendingLinesShown {
			g.More = len(lines) - pendingLinesShown
			g.Lines = lines[:pendingLinesShown]
		}
		if g.Mine {
			out.MineCount += g.Count
		} else {
			out.OtherCount += g.Count
		}
		out.Groups = append(out.Groups, g)
	}
	rank := func(g pendingAuthorGroup) int {
		switch {
		case g.Mine:
			return 0
		case g.User == "" || g.User == changeset.Mixed:
			return 2
		}
		return 1
	}
	sort.Slice(out.Groups, func(i, j int) bool {
		a, b := out.Groups[i], out.Groups[j]
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		return a.User < b.User
	})
	return out
}

func (g pendingAuthorGroup) Name() string {
	switch g.User {
	case "":
		return "unknown author"
	case changeset.Mixed:
		return "changed by several admins"
	}
	return g.User
}

func (v *pendingView) minePaths(me string) []string {
	return changeset.Mine(v.liveTree, v.candTr, v.authors, me)
}

func toCluster(tree any) (config.Cluster, error) {
	raw, err := json.Marshal(tree)
	if err != nil {
		return config.Cluster{}, err
	}
	var c config.Cluster
	if err := json.Unmarshal(raw, &c); err != nil {
		return config.Cluster{}, err
	}
	return c, nil
}

// onlyMine is live plus the viewer's own staged changes.
func (v *pendingView) onlyMine(me string) (config.Cluster, int, error) {
	mine := v.minePaths(me)
	set := make(map[string]bool, len(mine))
	for _, p := range mine {
		set[p] = true
	}
	c, err := toCluster(changeset.Merge(v.liveTree, v.candTr, func(p string) bool { return set[p] }))
	return c, len(mine), err
}

// withoutMine is the candidate with the viewer's own changes reverted.
func (v *pendingView) withoutMine(me string) (config.Cluster, int, error) {
	mine := v.minePaths(me)
	set := make(map[string]bool, len(mine))
	for _, p := range mine {
		set[p] = true
	}
	c, err := toCluster(changeset.Merge(v.candTr, v.liveTree, func(p string) bool { return set[p] }))
	return c, len(mine), err
}

// keepRemainder runs after a partial commit: whatever is still staged and now
// differs from live stays staged, anything else is cleared. It reads both
// documents again so a change staged in the meantime is not lost.
func keepRemainder(cfg *WebConfig) {
	nodes := nodesIncludingSelf(cfg)
	live, _, err := firstReachableConfig(nodes)
	if err != nil {
		log.Printf("[PENDING] read live config after a partial commit: %v", err)
		return
	}
	cr, _, err := firstReachableCandidateResponse(nodes)
	if err != nil {
		log.Printf("[PENDING] read candidate after a partial commit: %v", err)
		return
	}
	if !cr.Exists {
		return
	}
	v, err := newPendingView(live, cr)
	if err != nil || (v.supported && len(v.paths) == 0) {
		discardCandidateEverywhere(cfg)
		return
	}
	if err := restageCandidate(cfg, cr.Candidate); err != nil {
		log.Printf("[PENDING] re-stage the other changes after a partial commit: %v", err)
	}
}

// restageCandidate stages c as the pending candidate on every node, with no author.
func restageCandidate(cfg *WebConfig, c config.Cluster) error {
	payload := clusterPushPayloadFrom(c)
	payload.Scopes = c.Scopes
	var errs []error
	for _, n := range nodesIncludingSelf(cfg) {
		body, err := json.Marshal(payloadForNode(payload, n))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n.Name, err))
			continue
		}
		status, resp, err := pushCandidate(n, body)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", n.Name, err))
		case status != http.StatusOK:
			errs = append(errs, fmt.Errorf("%s: status %d: %s", n.Name, status, strings.TrimSpace(string(resp))))
		}
	}
	return errors.Join(errs...)
}

func discardCandidateEverywhere(cfg *WebConfig) {
	for _, n := range nodesIncludingSelf(cfg) {
		if err := discardCandidate(n); err != nil {
			log.Printf("[PENDING] clear candidate on %s: %v", n.Name, err)
		}
	}
}

func auditPending(cfg *WebConfig, user, action, summary string) {
	for _, n := range nodesIncludingSelf(cfg) {
		pushAudit(n, user, action, summary)
	}
}

func (a pendingAuthors) describe() string {
	var parts []string
	for _, g := range a.Groups {
		parts = append(parts, fmt.Sprintf("%s (%d)", g.Name(), g.Count))
	}
	return strings.Join(parts, ", ")
}

type pendingConfirmData struct {
	Error   string
	Action  string
	Verb    string
	Phrase  string
	Total   int
	Authors pendingAuthors
}

var pendingConfirmTmpl = template.Must(template.New("pendingconfirm").Parse(`<!doctype html>
<title>dnshived-web — confirm</title>
` + styleHTML + navHTML + `
<div class="pagehead"><h1>{{.Verb}} everyone's pending changes</h1></div>
{{if .Error}}<p class="crit">{{.Error}}</p>{{else}}
<section class="card pend-card" style="border-color:var(--crit)">
<p class="crit" style="font-size:1.4rem"><b>⚠ WARNING — this {{.Action}}s changes made by other admins.</b></p>
<p class="crit">{{if eq .Action "commit"}}Their changes go live on every node together with yours. They cannot be taken back out of the staged changes afterwards.{{else}}Their staged work is thrown away on every node. It cannot be restored.{{end}}</p>
{{range .Authors.OthersGroups}}
<h2>{{.Name}} — {{.Count}} change(s)</h2>
<ul class="card-list">{{range .Lines}}<li>{{.}}</li>{{end}}{{if .More}}<li class="dim">and {{.More}} more</li>{{end}}</ul>
{{end}}
{{if .Authors.MineCount}}<p class="dim">Your own {{.Authors.MineCount}} change(s) are {{if eq .Action "commit"}}included{{else}}included too{{end}}.</p>{{end}}
<form method="post" action="/pending/{{.Action}}">
<input type="hidden" name="back" value="/pending">
<label style="display:block;margin:.6rem 0">Type <b>{{.Phrase}}</b> to confirm: <input type="text" name="confirm" autocomplete="off" required pattern="{{.Phrase}}" size="14"></label>
<button type="submit" class="btn-danger">{{.Verb}} all {{.Total}} change(s)</button>
<a href="/pending" class="btn">Cancel</a>
</form>
</section>
{{end}}
`))

// handlePendingConfirm (GET /pending/confirm) is the warning page shown before
// everyone's changes are committed or discarded.
func handlePendingConfirm(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		user, _ := userFromContext(r)
		data := pendingConfirmData{Action: "commit", Verb: "Commit", Phrase: confirmCommitAll}
		if r.URL.Query().Get("action") == "discard" {
			data.Action, data.Verb, data.Phrase = "discard", "Discard", confirmDiscardAll
		}
		nodes := nodesIncludingSelf(cfg)
		live, _, err := firstReachableConfig(nodes)
		if err == nil {
			var cr candidateResponse
			if cr, _, err = firstReachableCandidateResponse(nodes); err == nil {
				var v *pendingView
				if v, err = newPendingView(live, cr); err == nil {
					data.Authors = v.summary(user.Name)
					data.Total = len(v.paths)
				}
			}
		}
		if err != nil {
			data.Error = "could not read the pending changes: " + err.Error()
		} else if !data.Authors.Show() {
			http.Redirect(w, r, "/pending", http.StatusSeeOther)
			return
		}
		renderTemplate(w, pendingConfirmTmpl, data, "pending confirm")
	}
}
