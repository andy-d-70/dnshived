// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"html/template"
	"net/http"
	"sort"
	"strings"

	"dnshived/internal/config"
)

// This file is the CRUD editor + membership-driven propagation for
// ScopeGroup (templates_store.go).

type scopeGroupScopeRow struct {
	Name     string
	Selected bool
}

type scopeGroupPageData struct {
	ID             string // "" for a brand-new group
	Name           string
	Color          string
	AssignedSource string
	Sources        []rolloutSource
	Scopes         []scopeGroupScopeRow
	Error          string
}

type scopeGroupListRow struct {
	ScopeGroup
	SourceLabel string
	EditHref    string
	DeleteHref  string
}

func handleScopeGroups(store *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		groups := store.SortedScopeGroups()
		sources := buildRolloutSources(store)
		labelByValue := make(map[string]string, len(sources))
		for _, s := range sources {
			labelByValue[s.Value] = s.Label
		}
		rows := make([]scopeGroupListRow, 0, len(groups))
		for _, g := range groups {
			rows = append(rows, scopeGroupListRow{
				ScopeGroup:  g,
				SourceLabel: labelByValue[g.AssignedSource],
				EditHref:    "/groups/" + g.ID + "/edit",
				DeleteHref:  "/groups/" + g.ID + "/delete",
			})
		}
		renderTemplate(w, scopeGroupListTmpl, rows, "groups-list")
	}
}

func buildScopeGroupScopeRows(names []string, members map[string]bool) []scopeGroupScopeRow {
	rows := make([]scopeGroupScopeRow, len(names))
	for i, n := range names {
		rows[i] = scopeGroupScopeRow{Name: n, Selected: members[n]}
	}
	return rows
}

func handleScopeGroupNew(ref *configRef, store *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		c, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		names := make([]string, 0, len(c.Scopes))
		for name := range c.Scopes {
			names = append(names, name)
		}
		sort.Strings(names)

		if r.Method != http.MethodPost {
			renderTemplate(w, scopeGroupEditTmpl, scopeGroupPageData{
				Sources: buildRolloutSources(store), Scopes: buildScopeGroupScopeRows(names, nil),
			}, "group-new")
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		name := r.PostForm.Get("name")
		color := r.PostForm.Get("color")
		source := r.PostForm.Get("assigned_source")
		members := r.PostForm["members"]
		memberSet := make(map[string]bool, len(members))
		for _, m := range members {
			memberSet[m] = true
		}
		data := scopeGroupPageData{Name: name, Color: color, AssignedSource: source,
			Sources: buildRolloutSources(store), Scopes: buildScopeGroupScopeRows(names, memberSet)}
		if strings.TrimSpace(name) == "" {
			data.Error = "name is required"
			renderTemplate(w, scopeGroupEditTmpl, data, "group-new")
			return
		}
		id := store.UpsertScopeGroup("", name, color, members, source)
		if err := store.Save(cfg.TemplatesFile); err != nil {
			http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		applyScopeGroupIfAssigned(w, r, cfg, store, c, id, false, nil)
	}
}

func handleScopeGroupEdit(ref *configRef, store *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		id := r.PathValue("id")
		g, ok := store.ScopeGroupByID(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		c, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		names := make([]string, 0, len(c.Scopes))
		for name := range c.Scopes {
			names = append(names, name)
		}
		sort.Strings(names)

		if r.Method != http.MethodPost {
			memberSet := make(map[string]bool, len(g.Members))
			for _, m := range g.Members {
				memberSet[m] = true
			}
			renderTemplate(w, scopeGroupEditTmpl, scopeGroupPageData{
				ID: g.ID, Name: g.Name, Color: g.Color, AssignedSource: g.AssignedSource,
				Sources: buildRolloutSources(store), Scopes: buildScopeGroupScopeRows(names, memberSet),
			}, "group-edit")
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}

		if r.PostForm.Get("confirmed") == "1" {
			applyScopeGroupIfAssigned(w, r, cfg, store, c, id, true, parseForceOverwrite(r.PostForm))
			return
		}

		name := r.PostForm.Get("name")
		color := r.PostForm.Get("color")
		source := r.PostForm.Get("assigned_source")
		members := r.PostForm["members"]
		memberSet := make(map[string]bool, len(members))
		for _, m := range members {
			memberSet[m] = true
		}
		data := scopeGroupPageData{ID: id, Name: name, Color: color, AssignedSource: source,
			Sources: buildRolloutSources(store), Scopes: buildScopeGroupScopeRows(names, memberSet)}
		if strings.TrimSpace(name) == "" {
			data.Error = "name is required"
			renderTemplate(w, scopeGroupEditTmpl, data, "group-edit")
			return
		}
		store.UpsertScopeGroup(id, name, color, members, source)
		if err := store.Save(cfg.TemplatesFile); err != nil {
			http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		applyScopeGroupIfAssigned(w, r, cfg, store, c, id, false, nil)
	}
}

func handleScopeGroupDelete(ref *configRef, store *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		id := r.PathValue("id")
		store.DeleteScopeGroup(id)
		if err := store.Save(cfg.TemplatesFile); err != nil {
			http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/groups", http.StatusSeeOther)
	}
}

func applyScopeGroupIfAssigned(w http.ResponseWriter, r *http.Request, cfg *WebConfig, store *TemplateStore, c config.Cluster, id string, confirmed bool, forceOverwrite map[string]bool) {
	g, ok := store.ScopeGroupByID(id)
	if !ok {
		http.Redirect(w, r, "/groups", http.StatusSeeOther)
		return
	}
	links, ok := linksForSource(g.AssignedSource, store)
	if !ok || len(g.Members) == 0 {
		http.Redirect(w, r, "/groups", http.StatusSeeOther)
		return
	}
	target := make(map[string]bool, len(g.Members))
	for _, m := range g.Members {
		target[m] = true
	}
	hidden := template.HTML(`<input type="hidden" name="group_id" value="` + template.HTMLEscapeString(id) + `">`)
	applyLinksWithCollisionGate(w, r, cfg, store, c, target, links, confirmed, forceOverwrite,
		hidden, "/groups", "/groups", "back to scope groups")
}

var scopeGroupListTmpl = template.Must(template.New("groups-list").Parse(`<!doctype html>
<title>dnshived-web — Scope groups</title>
` + styleHTML + `
<h1>Scope groups</h1>
` + navHTML + `
<p class="dim">A named group of scopes with its own
<a href="/config/dns#templates">Template</a>/<a href="/optionsets">Option
set</a> assignment — assign once to the group instead of every member
scope individually. A scope added to the group later inherits the
assignment the next time this group is saved. A scope can belong to
more than one group. For a one-off apply that doesn't need an ongoing
group, see <a href="/rollout">mass-rollout</a>.</p>
<table><tr><th>name</th><th>members</th><th>applies</th><th></th></tr>
{{range .}}
<tr><td><span class="name-dot" style="background:{{.Color}}"></span>{{.Name}}</td>
<td>{{len .Members}}</td>
<td class="dim">{{if .SourceLabel}}{{.SourceLabel}}{{else}}(nothing assigned yet){{end}}</td>
<td><a href="{{.EditHref}}">edit</a>
<form method="post" action="{{.DeleteHref}}" style="display:inline" onsubmit="return confirm('Delete group {{.Name}}? Member scopes keep whatever they last resolved to — deleting a group never touches scope content.')"><button type="submit">delete</button></form></td></tr>
{{else}}<tr><td colspan="4" class="dim">none yet</td></tr>{{end}}
</table>
<p><a href="/groups/new">+ New scope group</a></p>
`))

var scopeGroupEditTmpl = template.Must(template.New("group-edit").Parse(`<!doctype html>
<title>dnshived-web — Scope group</title>
` + styleHTML + `
<h1>{{if .ID}}Edit{{else}}New{{end}} scope group</h1>
` + navHTML + `
{{if .Error}}<p class="crit">{{.Error}}</p>{{end}}
<form method="post">
<p><label>name <input name="name" value="{{.Name}}" required></label>
<label>color <input type="color" name="color" value="{{if .Color}}{{.Color}}{{else}}` + scopeColorUnset + `{{end}}"></label></p>
<p><label>assigned option set / template:
<select name="assigned_source">
<option value="">— none yet —</option>
{{$cur := .AssignedSource}}{{range .Sources}}<option value="{{.Value}}" {{if eq .Value $cur}}selected{{end}}>{{.Label}}</option>{{end}}
</select>
</label></p>
<p>members:</p>
<div class="table-wrap"><table>
{{range .Scopes}}<tr><td><label><input type="checkbox" name="members" value="{{.Name}}" {{if .Selected}}checked{{end}}> {{.Name}}</label></td></tr>
{{else}}<tr><td class="dim">no scopes configured yet</td></tr>{{end}}
</table></div>
<button type="submit">{{if .ID}}Save{{else}}Create{{end}}</button>
<a href="/groups">cancel</a>
</form>
`))
