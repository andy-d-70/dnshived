// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"html/template"
	"log"
	"net/http"
	"strings"
)

// optionSetKindOrder fixes a stable display/form order for the three
// kinds.
var optionSetKindOrder = []TemplateKind{
	TemplateKindDHCP, TemplateKindDNS, TemplateKindClientDNS,
}

func optionSetKindLabel(k TemplateKind) string {
	switch k {
	case TemplateKindDHCP:
		return "DHCP options"
	case TemplateKindDNS:
		return "DNS records"
	case TemplateKindClientDNS:
		return "DNS server for clients"
	default:
		return string(k)
	}
}

// optionSetKindRow backs one of the four kind-scoped dropdowns on the
// option-set edit form.
type optionSetKindRow struct {
	Kind      TemplateKind
	Label     string
	FieldName string // e.g. "ref_dhcp" — the posted form field name
	Options   []templateRow
	Selected  string // currently-referenced Template.ID, "" = none
}

type optionSetPageData struct {
	ID       string // "" for a brand-new set
	Name     string
	Color    string
	KindRows []optionSetKindRow
	Error    string
}

// optionSetListRow backs the plain list page.
type optionSetListRow struct {
	OptionSet
	// RefLabels is "DHCP options: dante-dhcp, Upstream DNS servers:
	// dante-upstream" style, one entry per non-empty reference.
	RefLabels  []string
	EditHref   string
	DeleteHref string
}

func buildOptionSetKindRows(store *TemplateStore, selected map[TemplateKind]string) []optionSetKindRow {
	rows := make([]optionSetKindRow, 0, len(optionSetKindOrder))
	for _, k := range optionSetKindOrder {
		rows = append(rows, optionSetKindRow{
			Kind:      k,
			Label:     optionSetKindLabel(k),
			FieldName: "ref_" + string(k),
			Options:   buildTemplateRows(store.ByKind(k)),
			Selected:  selected[k],
		})
	}
	return rows
}

func parseOptionSetRefs(f map[string][]string) map[TemplateKind]string {
	refs := make(map[TemplateKind]string)
	for _, k := range optionSetKindOrder {
		if v := strings.TrimSpace(first(f["ref_"+string(k)])); v != "" {
			refs[k] = v
		}
	}
	return refs
}

func handleOptionSets(store *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sets := store.SortedOptionSets()
		rows := make([]optionSetListRow, 0, len(sets))
		for _, s := range sets {
			var labels []string
			for _, k := range optionSetKindOrder {
				id := s.TemplateRefs[k]
				if id == "" {
					continue
				}
				if t, ok := store.Get(id); ok {
					labels = append(labels, optionSetKindLabel(k)+": "+t.Name)
				}
			}
			rows = append(rows, optionSetListRow{
				OptionSet:  s,
				RefLabels:  labels,
				EditHref:   "/optionsets/" + s.ID + "/edit",
				DeleteHref: "/optionsets/" + s.ID + "/delete",
			})
		}
		renderTemplate(w, optionSetListTmpl, rows, "optionsets-list")
	}
}

func handleOptionSetNew(ref *configRef, store *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		data := optionSetPageData{KindRows: buildOptionSetKindRows(store, nil)}

		if r.Method != http.MethodPost {
			renderTemplate(w, optionSetEditTmpl, data, "optionset-new")
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		data.Name = r.PostForm.Get("name")
		data.Color = r.PostForm.Get("color")
		refs := parseOptionSetRefs(r.PostForm)
		data.KindRows = buildOptionSetKindRows(store, refs)
		if strings.TrimSpace(data.Name) == "" {
			data.Error = "name is required"
			renderTemplate(w, optionSetEditTmpl, data, "optionset-new")
			return
		}
		store.UpsertOptionSet("", data.Name, data.Color, refs)
		if err := store.Save(cfg.TemplatesFile); err != nil {
			log.Printf("[ERROR] save templates: %v", err)
			http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/optionsets", http.StatusSeeOther)
	}
}

func handleOptionSetEdit(ref *configRef, store *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		id := r.PathValue("id")
		s, ok := store.OptionSetByID(id)
		if !ok {
			http.NotFound(w, r)
			return
		}

		if r.Method != http.MethodPost {
			data := optionSetPageData{ID: s.ID, Name: s.Name, Color: s.Color, KindRows: buildOptionSetKindRows(store, s.TemplateRefs)}
			renderTemplate(w, optionSetEditTmpl, data, "optionset-edit")
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		name := r.PostForm.Get("name")
		color := r.PostForm.Get("color")
		refs := parseOptionSetRefs(r.PostForm)
		if strings.TrimSpace(name) == "" {
			data := optionSetPageData{ID: id, Name: name, Color: color, KindRows: buildOptionSetKindRows(store, refs), Error: "name is required"}
			renderTemplate(w, optionSetEditTmpl, data, "optionset-edit")
			return
		}
		store.UpsertOptionSet(id, name, color, refs)
		if err := store.Save(cfg.TemplatesFile); err != nil {
			log.Printf("[ERROR] save templates: %v", err)
			http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if propagateAndMaybeStage(w, r, store, cfg, "/optionsets", "back to Option sets") {
			return
		}
		http.Redirect(w, r, "/optionsets", http.StatusSeeOther)
	}
}

func handleOptionSetDelete(ref *configRef, store *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		id := r.PathValue("id")
		store.DeleteOptionSet(id)
		if err := store.Save(cfg.TemplatesFile); err != nil {
			log.Printf("[ERROR] save templates: %v", err)
			http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/optionsets", http.StatusSeeOther)
	}
}

var optionSetListTmpl = template.Must(template.New("optionsets-list").Parse(`<!doctype html>
<title>dnshived-web — Option sets</title>
` + styleHTML + `
<h1>Option sets</h1>
` + navHTML + `
<p class="dim">A named bundle of <a href="/config/dns#templates">Templates</a>
— up to one per kind. Applying a set applies every referenced
template's own kind at once. Editing a set (or any template it
references) live-propagates into every scope currently linked to it —
see <a href="/rollout">mass-rollout</a> or <a href="/groups">scope
groups</a> to create those links across many scopes at once.</p>
<table><tr><th>name</th><th>applies</th><th></th></tr>
{{range .}}
<tr><td><span class="name-dot" style="background:{{.Color}}"></span>{{.Name}}</td>
<td class="dim">{{range $i, $l := .RefLabels}}{{if $i}}, {{end}}{{$l}}{{else}}(nothing referenced yet){{end}}</td>
<td><a href="{{.EditHref}}">edit</a>
<form method="post" action="{{.DeleteHref}}" style="display:inline" onsubmit="return confirm('Delete option set {{.Name}}? Scopes linked to it stop resolving further (their current content stays as last resolved).')"><button type="submit">delete</button></form></td></tr>
{{else}}<tr><td colspan="3" class="dim">none yet</td></tr>{{end}}
</table>
<p><a href="/optionsets/new">+ New option set</a></p>
`))

var optionSetEditTmpl = template.Must(template.New("optionset-edit").Parse(`<!doctype html>
<title>dnshived-web — Option set</title>
` + styleHTML + `
<h1>{{if .ID}}Edit{{else}}New{{end}} option set</h1>
` + navHTML + `
{{if .Error}}<p class="crit">{{.Error}}</p>{{end}}
<form method="post">
<table>
<tr><td>name</td><td><input name="name" value="{{.Name}}" required></td></tr>
<tr><td>color</td><td><input type="color" name="color" value="{{if .Color}}{{.Color}}{{else}}` + scopeColorUnset + `{{end}}"></td></tr>
{{range .KindRows}}
<tr><td>{{.Label}}<br><small class="dim">optional — leave as "(none)" to skip this kind entirely</small></td><td>
<select name="{{.FieldName}}">
<option value="">(none)</option>
{{$cur := .Selected}}{{range .Options}}<option value="{{.ID}}" {{if eq .ID $cur}}selected{{end}}>{{.Name}}</option>{{end}}
</select>
</td></tr>
{{end}}
</table>
<button type="submit">{{if .ID}}Save{{else}}Create{{end}}</button>
<a href="/optionsets">cancel</a>
</form>
`))
