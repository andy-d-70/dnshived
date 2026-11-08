// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"

	"dnshived/internal/config"
	"dnshived/internal/preflight"
)

// moveAllRow is one scope in the move-all check.
type moveAllRow struct {
	Scope    string
	VLAN     int
	Disabled bool
	Class    string
	Verdict  string
	Details  []string
}

// moveAllPlan is the outcome of checking a move of every scope on one
// interface to another. Nothing is changed by building it.
type moveAllPlan struct {
	From, To  string
	Rows      []moveAllRow
	Moved     map[string]config.ScopeConfig
	Conflicts int
	Warnings  int
}

// planMoveAll checks moving every scope that sits on from to to, keeping each
// scope's VLAN ID, VIP, addresses and pool. It never renumbers: a clash is
// listed for the operator to resolve by hand. The scopes are checked against
// every scope that stays and against each other.
func planMoveAll(c config.Cluster, from, to string) (moveAllPlan, error) {
	plan := moveAllPlan{From: from, To: to, Moved: make(map[string]config.ScopeConfig)}
	if c.Platform == nil {
		return plan, fmt.Errorf("the cluster has no platform configuration")
	}
	if from == "" || to == "" {
		return plan, fmt.Errorf("choose both interfaces")
	}
	if from == to {
		return plan, fmt.Errorf("source and target are the same interface")
	}
	serving := false
	for _, s := range c.Platform.ServingInterfaces() {
		serving = serving || s == to
	}
	if !serving {
		return plan, fmt.Errorf("%q is not a serving interface: switch it on in the cluster settings first", to)
	}
	stay := make(map[string]config.ScopeConfig, len(c.Scopes))
	for name, sc := range c.Scopes {
		if sc.Parent == from {
			sc.Parent = to
			plan.Moved[name] = sc
			continue
		}
		stay[name] = sc
	}
	if len(plan.Moved) == 0 {
		return plan, fmt.Errorf("no scope is on %q", from)
	}

	ctx := preflight.Context{Existing: stay, Workers: c.Platform.ServingInterfaces(), Mgmt: c.Platform.Mgmt}
	if c.MgmtVIP != nil {
		ctx.MgmtVRRPID = c.MgmtVIP.VRRPID
		ctx.MgmtVIPHost, _, _ = strings.Cut(c.MgmtVIP.VIP, "/")
	}
	byName := make(map[string]preflight.Result)
	for _, r := range preflight.Check(ctx, plan.Moved) {
		byName[r.Scope] = r
	}

	names := make([]string, 0, len(plan.Moved))
	for n := range plan.Moved {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		sc := plan.Moved[n]
		row := moveAllRow{Scope: n, VLAN: sc.VLANID, Disabled: sc.DNSMasqDisabled, Class: "ok", Verdict: "can move"}
		for _, col := range byName[n].Collisions {
			row.Details = append(row.Details, col.Detail)
			if col.Severity == preflight.SevError {
				row.Class, row.Verdict = "crit", "conflict"
			} else if row.Class == "ok" {
				row.Class, row.Verdict = "warn", "can move, check"
			}
		}
		switch row.Class {
		case "crit":
			plan.Conflicts++
		case "warn":
			plan.Warnings++
		}
		plan.Rows = append(plan.Rows, row)
	}
	return plan, nil
}

type moveAllPageData struct {
	Interfaces []string
	From, To   string
	Error      string
	Plan       *moveAllPlan
}

var moveAllTmpl = template.Must(template.New("moveall").Parse(`<!doctype html>
<title>dnshived-web — move scopes</title>
` + styleHTML + `
` + navHTML + `
<h1>Move all scopes from one interface to another</h1>

<p class="dim">Every scope on the source interface moves to the target with its VLAN ID, VIP, addresses and pool unchanged.
Nothing is renumbered: the check below lists every VLAN, subnet or address clash first, and nothing is staged until it is clean.
The move is staged as a pending change; you review and commit it from Pending changes. A source interface can be switched off
afterwards (cluster settings) once no active scope is left on it.</p>
{{if .Error}}<p class="crit">{{.Error}}</p>{{end}}
<form method="post" action="/scopes/move-all/check">
<label>From: <input type="text" name="from" list="move-ifaces" value="{{.From}}" required></label>
<label>To: <input type="text" name="to" list="move-ifaces" value="{{.To}}" required></label>
<datalist id="move-ifaces">{{range .Interfaces}}<option value="{{.}}">{{end}}</datalist>
<button type="submit">Check the move</button>
</form>
{{with .Plan}}
<h2>Check: {{len .Rows}} scope(s) from {{.From}} to {{.To}}</h2>
<p>{{if .Conflicts}}<span class="crit">{{.Conflicts}} conflict(s) — resolve them by hand first (move that scope alone to a free VLAN ID, or change it); nothing can be staged.</span>
{{else if .Warnings}}<span class="warn">no conflicts, {{.Warnings}} scope(s) with a note.</span>
{{else}}<span class="ok">no conflicts.</span>{{end}}</p>
<div class="table-wrap"><table border="1" cellpadding="4">
<tr><th>Scope</th><th>VLAN</th><th>Result</th><th>Details</th></tr>
{{range .Rows}}<tr><td><a href="/scopes/{{.Scope}}">{{.Scope}}</a>{{if .Disabled}} <span class="dim">(disabled)</span>{{end}}</td><td>{{if .VLAN}}{{.VLAN}}{{else}}untagged{{end}}</td>
<td><span class="{{.Class}}">{{.Verdict}}</span></td><td>{{range .Details}}{{.}}<br>{{end}}</td></tr>{{end}}
</table></div>
{{if not .Conflicts}}<form method="post" action="/scopes/move-all/apply" onsubmit="return confirm('Stage the move of {{len .Rows}} scope(s) as a pending change? Nothing is applied until you commit it.')">
<input type="hidden" name="from" value="{{.From}}"><input type="hidden" name="to" value="{{.To}}">
<button type="submit">Stage this move as a pending change</button>
</form>{{end}}
{{end}}`))

func moveAllInterfaces(c config.Cluster) []string {
	if c.Platform == nil {
		return nil
	}
	return parentChoices(c)
}

func renderMoveAll(w http.ResponseWriter, data moveAllPageData, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := moveAllTmpl.Execute(w, data); err != nil {
		fmt.Fprintf(w, "render error: %v", err)
	}
}

// handleMoveAllForm serves GET /scopes/move-all.
func handleMoveAllForm(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, _, _, err := currentEditableConfig(nodesIncludingSelf(ref.Load()))
		if err != nil {
			http.Error(w, "fetch current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		renderMoveAll(w, moveAllPageData{Interfaces: moveAllInterfaces(c)}, http.StatusOK)
	}
}

// handleMoveAllCheck serves POST /scopes/move-all/check: it changes nothing.
func handleMoveAllCheck(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		c, _, _, err := currentEditableConfig(nodesIncludingSelf(ref.Load()))
		if err != nil {
			http.Error(w, "fetch current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		from, to := strings.TrimSpace(r.PostForm.Get("from")), strings.TrimSpace(r.PostForm.Get("to"))
		data := moveAllPageData{Interfaces: moveAllInterfaces(c), From: from, To: to}
		plan, err := planMoveAll(c, from, to)
		if err != nil {
			data.Error = err.Error()
			renderMoveAll(w, data, http.StatusOK)
			return
		}
		data.Plan = &plan
		renderMoveAll(w, data, http.StatusOK)
	}
}

// handleMoveAllApply serves POST /scopes/move-all/apply. It checks again on
// the current config and refuses on any conflict, so the form's earlier check
// is never trusted.
func handleMoveAllApply(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		c, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "fetch current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		plan, err := planMoveAll(c, strings.TrimSpace(r.PostForm.Get("from")), strings.TrimSpace(r.PostForm.Get("to")))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if plan.Conflicts > 0 {
			http.Error(w, fmt.Sprintf("%d conflict(s): run the check again and resolve them first", plan.Conflicts), http.StatusConflict)
			return
		}
		newScopes := make(map[string]config.ScopeConfig, len(c.Scopes))
		for name, sc := range c.Scopes {
			newScopes[name] = sc
		}
		for name, sc := range plan.Moved {
			newScopes[name] = sc
		}
		payload := clusterPushPayloadFrom(c)
		payload.Scopes = newScopes
		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/scopes", "back to scopes")
	}
}
