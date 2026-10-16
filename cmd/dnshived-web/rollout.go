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

// kindFieldKeys is contentLinkFieldKinds' own reverse — given a
// TemplateKind, which ScopeConfig content field (by its JSON key) does it
// drive.
var kindFieldKeys = map[TemplateKind]string{
	TemplateKindDHCP:      "dhcp_options",
	TemplateKindDNS:       "dns_records",
	TemplateKindClientDNS: "client_dns_server",
}

// rolloutSource is one selectable entry in the mass-rollout form's source
// dropdown.
type rolloutSource struct {
	Value string // "template:<id>" or "optionset:<id>"
	Label string
}

func buildRolloutSources(store *TemplateStore) []rolloutSource {
	var out []rolloutSource
	for _, k := range optionSetKindOrder {
		for _, t := range store.ByKind(k) {
			out = append(out, rolloutSource{Value: ContentLinkKindTemplate + ":" + t.ID, Label: "Template: " + t.Name + " (" + optionSetKindLabel(k) + ")"})
		}
	}
	for _, s := range store.SortedOptionSets() {
		out = append(out, rolloutSource{Value: ContentLinkKindOptionSet + ":" + s.ID, Label: "Option set: " + s.Name})
	}
	return out
}

// linksForSource resolves one rolloutSource value into the set of
// ScopeConfig.ContentLinks entries applying it means.
func linksForSource(value string, store *TemplateStore) (map[string]config.ContentLink, bool) {
	kind, id, found := strings.Cut(value, ":")
	if !found || id == "" {
		return nil, false
	}
	links := make(map[string]config.ContentLink)
	switch kind {
	case ContentLinkKindTemplate:
		t, ok := store.Get(id)
		if !ok {
			return nil, false
		}
		fieldKey, ok := kindFieldKeys[t.Kind]
		if !ok {
			return nil, false
		}
		links[fieldKey] = config.ContentLink{Kind: ContentLinkKindTemplate, SourceID: id}
	case ContentLinkKindOptionSet:
		s, ok := store.OptionSetByID(id)
		if !ok {
			return nil, false
		}
		for refKind, refID := range s.TemplateRefs {
			if refID == "" {
				continue
			}
			fieldKey, ok := kindFieldKeys[refKind]
			if !ok {
				continue
			}
			links[fieldKey] = config.ContentLink{Kind: ContentLinkKindOptionSet, SourceID: id}
		}
	default:
		return nil, false
	}
	if len(links) == 0 {
		return nil, false
	}
	return links, true
}

type rolloutScopeRow struct {
	Name     string
	Selected bool
}

type rolloutPageData struct {
	Sources        []rolloutSource
	SelectedSource string
	Scopes         []rolloutScopeRow
	Error          string
}

func handleRollout(ref *configRef, store *TemplateStore) http.HandlerFunc {
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
			rows := make([]rolloutScopeRow, len(names))
			for i, n := range names {
				rows[i] = rolloutScopeRow{Name: n}
			}
			renderTemplate(w, rolloutTmpl, rolloutPageData{Sources: buildRolloutSources(store), Scopes: rows}, "rollout")
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		source := r.PostForm.Get("source")
		selected := make(map[string]bool, len(r.PostForm["scopes"]))
		for _, s := range r.PostForm["scopes"] {
			selected[s] = true
		}
		confirmed := r.PostForm.Get("confirmed") == "1"
		forceOverwrite := parseForceOverwrite(r.PostForm)
		rows := make([]rolloutScopeRow, len(names))
		for i, n := range names {
			rows[i] = rolloutScopeRow{Name: n, Selected: selected[n]}
		}
		data := rolloutPageData{Sources: buildRolloutSources(store), SelectedSource: source, Scopes: rows}

		links, ok := linksForSource(source, store)
		if !ok {
			data.Error = "pick a template or option set that actually references something"
			renderTemplate(w, rolloutTmpl, data, "rollout")
			return
		}
		if len(selected) == 0 {
			data.Error = "select at least one scope"
			renderTemplate(w, rolloutTmpl, data, "rollout")
			return
		}

		var hidden strings.Builder
		hidden.WriteString(`<input type="hidden" name="source" value="` + template.HTMLEscapeString(source) + `">`)
		for name := range selected {
			hidden.WriteString(`<input type="hidden" name="scopes" value="` + template.HTMLEscapeString(name) + `">`)
		}
		applyLinksWithCollisionGate(w, r, cfg, store, c, selected, links, confirmed, forceOverwrite,
			template.HTML(hidden.String()), "/rollout", "/rollout", "back to mass-rollout")
	}
}

var rolloutTmpl = template.Must(template.New("rollout").Parse(`<!doctype html>
<title>dnshived-web — Mass-rollout</title>
` + styleHTML + `
<h1>Mass-rollout</h1>
` + navHTML + `
<p class="dim">Apply one <a href="/config/dns#templates">Template</a> or
<a href="/optionsets">Option set</a> to many scopes at once. This LINKS
each selected scope's own field(s) to the source — editing the
template/option set later re-applies here automatically, unlike a
single scope's own "+ apply" button (a one-shot copy, no ongoing
link). For a set of scopes you'll keep adding to over time, a
<a href="/groups">scope group</a> does this automatically instead of
repeating a rollout every time.</p>
{{if .Error}}<p class="crit">{{.Error}}</p>{{end}}
<form method="post">
<p><label>Apply:
<select name="source" required>
<option value="">— pick one —</option>
{{$cur := .SelectedSource}}{{range .Sources}}<option value="{{.Value}}" {{if eq .Value $cur}}selected{{end}}>{{.Label}}</option>{{end}}
</select>
</label></p>
<p>to these scopes:</p>
<div class="table-wrap"><table>
{{range .Scopes}}<tr><td><label><input type="checkbox" name="scopes" value="{{.Name}}" {{if .Selected}}checked{{end}}> {{.Name}}</label></td></tr>
{{else}}<tr><td class="dim">no scopes configured yet</td></tr>{{end}}
</table></div>
<button type="submit">Apply — stage as pending change</button>
</form>
`))
