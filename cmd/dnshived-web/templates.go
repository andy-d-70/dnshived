// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"

	"dnshived/internal/config"
)

// validateTemplateBody runs the same syntax check a template's body would
// eventually face once applied into a real scope, so a mistake is caught
// here.
func validateTemplateBody(kind TemplateKind, body string) error {
	switch kind {
	case TemplateKindDNS:
		_, err := parseDNSRecordLines(body)
		return err
	case TemplateKindDHCP:
		return config.ValidateDHCPOptions(splitLines(body), "template")
	case TemplateKindClientDNS:
		return validateClientDNSServerValue(body)
	default:
		return fmt.Errorf("unknown template kind %q", kind)
	}
}

func validateClientDNSServerValue(body string) error {
	for _, part := range strings.Split(strings.TrimSpace(body), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if net.ParseIP(part) == nil {
			return fmt.Errorf("client DNS server: %q is not a valid IP address", part)
		}
	}
	return nil
}

type templateRow struct {
	Template
	EditHref   string
	DeleteHref string
}

func buildTemplateRows(list []Template) []templateRow {
	rows := make([]templateRow, len(list))
	for i, t := range list {
		rows[i] = templateRow{Template: t, EditHref: "/templates/" + t.ID + "/edit", DeleteHref: "/templates/" + t.ID + "/delete"}
	}
	return rows
}

var newTemplateWizardTmpl = template.Must(template.New("template-new-wizard").Funcs(template.FuncMap{
	"dnsBuilder":  dnsRecordBuilderHTML,
	"dhcpBuilder": dhcpOptionBuilderHTML,
}).Parse(`<!doctype html>
<title>dnshived-web — new template</title>
` + styleHTML + templateBuilderStyleHTML + `
<h1>New template — step {{.Step}} of 2</h1>
` + navHTML + `

{{if eq .Step 1}}
<form method="post" action="/templates/new">
<input type="hidden" name="action" value="step2">
<table>
<tr><td>name</td><td><input name="name" value="{{.Name}}" required></td></tr>
<tr><td>color</td><td><input type="color" name="color" value="{{if .Color}}{{.Color}}{{else}}` + scopeColorUnset + `{{end}}"></td></tr>
<tr><td>kind</td><td>
<select name="kind">
<option value="dhcp" {{if eq .Kind "dhcp"}}selected{{end}}>dhcp option set</option>
<option value="dns" {{if eq .Kind "dns"}}selected{{end}}>dns record set</option>
<option value="client-dns" {{if eq .Kind "client-dns"}}selected{{end}}>DNS server for clients</option>
</select></td></tr>
</table>
<button type="submit">Next &rarr;</button>
</form>
{{end}}

{{if eq .Step 2}}
<form method="post" action="/templates/new">
<input type="hidden" name="name" value="{{.Name}}">
<input type="hidden" name="color" value="{{.Color}}">
<input type="hidden" name="kind" value="{{.Kind}}">
<p><strong>{{.Name}}</strong> ({{if eq .Kind "dhcp"}}dhcp option set{{else if eq .Kind "dns"}}dns record set{{else}}DNS server for clients{{end}})</p>
{{if eq .Kind "dhcp"}}
<p class="dim">Pick an option and fill in its value, or type a raw dnsmasq
<code>dhcp-option</code> line directly below (e.g. <code>6,8.8.8.8</code>).</p>
{{dhcpBuilder "tpl_body"}}
{{else if eq .Kind "dns"}}
<p class="dim">Pick a record type and fill in its fields, or type a raw
<code>TYPE|NAME|...</code> line directly below.</p>
{{dnsBuilder "tpl_body" .Existing}}
<h3>Insert from a local domain</h3>
{{.DomainInsert}}
{{else}}
<p class="dim">A single DNS server IP, or a comma-separated list for
redundancy (e.g. <code>8.8.8.8,1.1.1.1</code>) — what DHCP clients on a
scope using this template are told to use, instead of dnshived's own
built-in default.</p>
{{end}}
{{if .Error}}<p class="crit">{{.Error}}</p>{{end}}
<textarea name="body" id="tpl_body" rows="8" cols="60">{{.Body}}</textarea>
<p><button type="submit" name="action" value="step1">&larr; Back</button>
<button type="submit" name="action" value="create">Create</button></p>
</form>
{{end}}
`))

type newTemplateWizardData struct {
	Step              int
	Name, Color, Kind string
	Body, Error       string
	Existing          []dnsExistingRecord
	DomainInsert      template.HTML
}

var templateEditTmpl = template.Must(template.New("template-edit").Funcs(template.FuncMap{
	"dnsBuilder":  dnsRecordBuilderHTML,
	"dhcpBuilder": dhcpOptionBuilderHTML,
}).Parse(`<!doctype html>
<title>dnshived-web — edit template</title>
` + styleHTML + templateBuilderStyleHTML + `
<h1>Edit template</h1>
` + navHTML + `
{{if .Error}}<p class="crit">{{.Error}}</p>{{end}}
<form method="post" action="/templates/{{.Template.ID}}/edit">
<table>
<tr><td>name</td><td><input name="name" value="{{.Template.Name}}" required></td></tr>
<tr><td>color</td><td><input type="color" name="color" value="{{.Template.Color}}"></td></tr>
<tr><td>kind</td><td>
<select name="kind">
<option value="dhcp" {{if eq .Template.Kind "dhcp"}}selected{{end}}>dhcp option set</option>
<option value="dns" {{if eq .Template.Kind "dns"}}selected{{end}}>dns record set</option>
<option value="client-dns" {{if eq .Template.Kind "client-dns"}}selected{{end}}>DNS server for clients</option>
</select> <span class="dim">(changing kind here doesn't switch the builder below until you save and reopen)</span></td></tr>
</table>
{{if eq .Template.Kind "dhcp"}}{{dhcpBuilder "tpl_edit_body"}}{{else if eq .Template.Kind "dns"}}{{dnsBuilder "tpl_edit_body" .Existing}}<h3>Insert from a local domain</h3>{{.DomainInsert}}{{else}}<p class="dim">A single DNS server IP, or a comma-separated list for redundancy.</p>{{end}}
<textarea name="body" id="tpl_edit_body" rows="8" cols="60">{{.Template.Body}}</textarea>
<button type="submit">save</button>
<a href="/config/dns#templates">cancel</a>
</form>
`))

type templateEditPageData struct {
	Template     Template
	Error        string
	Existing     []dnsExistingRecord
	DomainInsert template.HTML
}

// localDomainInsertHTML renders a "+ insert into this template" picker
// sourced from Cluster.LocalDomains.
func localDomainInsertHTML(textareaID string, domains []config.LocalDomain) template.HTML {
	if len(domains) == 0 {
		return template.HTML(`<p class="dim">no local domains configured yet — see <a href="/config/dns#domains">DHCP &amp; DNS &rarr; Local domains</a>.</p>`)
	}
	var b strings.Builder
	b.WriteString(`<script>function domainInsert_` + textareaID + `(body){var ta=document.getElementById('` + textareaID + `');if(!ta)return;var have=ta.value.split("\n").filter(function(l){return l!=='';});var add=body.split("\n");add.forEach(function(line){if(line!=='' && have.indexOf(line)===-1){have.push(line);}});ta.value=have.join("\n");}</script>`)
	sorted := append([]config.LocalDomain(nil), domains...)
	sortLocalDomains(sorted)
	for _, d := range sorted {
		body := formatDNSRecordLines(d.ExpandedRecords())
		b.WriteString(`<details class="tpl-picker-item"><summary>` + template.HTMLEscapeString(d.Name) + ` (` + fmt.Sprintf("%d", len(d.Records)) + ` host(s))</summary>`)
		b.WriteString(`<pre style="margin:.3rem 0;white-space:pre-wrap">` + template.HTMLEscapeString(body) + `</pre>`)
		b.WriteString(`<button type="button" onclick="domainInsert_` + textareaID + `(` + template.HTMLEscapeString(templateJS(body)) + `)">+ insert into this template</button>`)
		b.WriteString(`</details>`)
	}
	return template.HTML(b.String())
}

func fetchExistingDNSRecords(nodes []NodeConfig) []dnsExistingRecord {
	c, _, _, err := currentEditableConfig(nodes)
	if err != nil {
		return nil
	}
	return collectExistingDNSRecords(c)
}

// fetchLocalDomains is fetchExistingDNSRecords' sibling for
// localDomainInsertHTML.
func fetchLocalDomains(nodes []NodeConfig) []config.LocalDomain {
	c, _, _, err := currentEditableConfig(nodes)
	if err != nil {
		return nil
	}
	return c.LocalDomains
}

func handleTemplateNew(ref *configRef, store *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		data := newTemplateWizardData{Step: 1, Kind: "dhcp"}

		if r.Method != http.MethodPost {
			renderTemplate(w, newTemplateWizardTmpl, data, "template-new-wizard")
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		data.Name = r.PostForm.Get("name")
		data.Color = r.PostForm.Get("color")
		if k := r.PostForm.Get("kind"); k != "" {
			data.Kind = k
		}
		data.Body = r.PostForm.Get("body")

		switch r.PostForm.Get("action") {
		case "step1":
			data.Step = 1
		case "step2":
			data.Step = 2
		case "create":
			data.Step = 2
			if err := validateTemplateBody(TemplateKind(data.Kind), data.Body); err != nil {
				data.Error = err.Error()
				if data.Kind == "dns" {
					data.Existing = fetchExistingDNSRecords(nodesIncludingSelf(cfg))
					data.DomainInsert = localDomainInsertHTML("tpl_body", fetchLocalDomains(nodesIncludingSelf(cfg)))
				}
				renderTemplate(w, newTemplateWizardTmpl, data, "template-new-wizard")
				return
			}
			store.Upsert("", data.Name, data.Color, TemplateKind(data.Kind), data.Body)
			if err := store.Save(cfg.TemplatesFile); err != nil {
				log.Printf("[ERROR] save templates: %v", err)
				http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/config/dns#templates", http.StatusSeeOther)
			return
		default:
			data.Step = 1
		}
		if data.Step == 2 && data.Kind == "dns" {
			data.Existing = fetchExistingDNSRecords(nodesIncludingSelf(cfg))
			data.DomainInsert = localDomainInsertHTML("tpl_body", fetchLocalDomains(nodesIncludingSelf(cfg)))
		}
		renderTemplate(w, newTemplateWizardTmpl, data, "template-new-wizard")
	}
}

func handleTemplateEditGet(ref *configRef, store *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		id := r.PathValue("id")
		t, ok := store.Get(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		data := templateEditPageData{Template: t}
		if t.Kind == TemplateKindDNS {
			data.Existing = fetchExistingDNSRecords(nodesIncludingSelf(cfg))
			data.DomainInsert = localDomainInsertHTML("tpl_edit_body", fetchLocalDomains(nodesIncludingSelf(cfg)))
		}
		renderTemplate(w, templateEditTmpl, data, "template-edit")
	}
}

func handleTemplateEditPost(ref *configRef, store *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		id := r.PathValue("id")
		if _, ok := store.Get(id); !ok {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		kind := TemplateKind(r.PostForm.Get("kind"))
		name := r.PostForm.Get("name")
		color := r.PostForm.Get("color")
		body := r.PostForm.Get("body")
		if err := validateTemplateBody(kind, body); err != nil {
			data := templateEditPageData{
				Template: Template{ID: id, Name: name, Color: color, Kind: kind, Body: body},
				Error:    err.Error(),
			}
			if kind == TemplateKindDNS {
				data.Existing = fetchExistingDNSRecords(nodesIncludingSelf(cfg))
			}
			renderTemplate(w, templateEditTmpl, data, "template-edit")
			return
		}
		store.Upsert(id, name, color, kind, body)
		if err := store.Save(cfg.TemplatesFile); err != nil {
			log.Printf("[ERROR] save templates: %v", err)
			http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if propagateAndMaybeStage(w, r, store, cfg, "/config/dns#templates", "back to Templates") {
			return
		}
		http.Redirect(w, r, "/config/dns#templates", http.StatusSeeOther)
	}
}

// propagateAndMaybeStage is the shared "did this template/option-set save
// actually change any live-linked scope's own content" step.
func propagateAndMaybeStage(w http.ResponseWriter, r *http.Request, store *TemplateStore, cfg *WebConfig, backLink, backText string) bool {
	c, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
	if err != nil {
		return false
	}
	updated, changed := propagateLinkedScopes(c.Scopes, store)
	if !changed {
		return false
	}
	payload := clusterPushPayloadFrom(c)
	payload.Scopes = updated
	user, _ := userFromContext(r)
	pushCandidateAndRenderResult(w, cfg, payload, user, backLink, backText)
	return true
}

func handleTemplateDelete(ref *configRef, store *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		id := r.PathValue("id")
		store.Delete(id)
		if err := store.Save(cfg.TemplatesFile); err != nil {
			log.Printf("[ERROR] save templates: %v", err)
			http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/config/dns#templates", http.StatusSeeOther)
	}
}
