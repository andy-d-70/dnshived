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

// collisionRow is one (scope, field) pair a bulk apply (rollout or a
// group) is about to touch that ALREADY has real content.
type collisionRow struct {
	Scope         string
	FieldLabel    string
	Detail        string
	CheckboxValue string // "<scope>|<fieldKey>" — force_overwrite's own posted value shape
}

// fieldHasContent reports whether one of a scope's own content fields (by
// its ContentLinks-style key) currently holds real, non-empty content.
func fieldHasContent(sc config.ScopeConfig, fieldKey string) bool {
	switch fieldKey {
	case "dhcp_options":
		return len(sc.DHCPOptions) > 0
	case "dns_records":
		return len(sc.DNSRecords) > 0
	case "client_dns_server":
		return sc.ClientDNSServer != ""
	default:
		return false
	}
}

// fieldPreview renders a short, human preview of a field's current
// content, for the collision confirm page.
func fieldPreview(sc config.ScopeConfig, fieldKey string) string {
	switch fieldKey {
	case "dhcp_options":
		return strings.Join(sc.DHCPOptions, "; ")
	case "dns_records":
		return strings.ReplaceAll(strings.TrimSpace(formatDNSRecordLines(sc.DNSRecords)), "\n", "; ")
	case "client_dns_server":
		return sc.ClientDNSServer
	default:
		return ""
	}
}

// describeContentLink renders a short, human label for an EXISTING link,
// for the "currently linked to X" collision detail.
func describeContentLink(link config.ContentLink, store *TemplateStore) string {
	switch link.Kind {
	case ContentLinkKindTemplate:
		if t, ok := store.Get(link.SourceID); ok {
			return "template " + t.Name
		}
	case ContentLinkKindOptionSet:
		if s, ok := store.OptionSetByID(link.SourceID); ok {
			return "option set " + s.Name
		}
	}
	return "an unknown source"
}

// detectCollisions is the safety check itself: for every targeted scope
// and every field the new links would touch, flag anything that ALREADY
// has real content.
func detectCollisions(scopes map[string]config.ScopeConfig, target map[string]bool, links map[string]config.ContentLink, store *TemplateStore) []collisionRow {
	var out []collisionRow
	for name, sc := range scopes {
		if !target[name] {
			continue
		}
		for fieldKey, newLink := range links {
			existing, hasExisting := sc.ContentLinks[fieldKey]
			label := optionSetKindLabel(contentLinkFieldKinds[fieldKey])
			switch {
			case hasExisting && existing == newLink:
				// Re-applying the identical link — not a collision.
			case hasExisting:
				out = append(out, collisionRow{Scope: name, FieldLabel: label,
					Detail:        "currently linked to " + describeContentLink(existing, store),
					CheckboxValue: name + "|" + fieldKey})
			case fieldHasContent(sc, fieldKey):
				out = append(out, collisionRow{Scope: name, FieldLabel: label,
					Detail:        "manually set: " + fieldPreview(sc, fieldKey),
					CheckboxValue: name + "|" + fieldKey})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return out[i].FieldLabel < out[j].FieldLabel
	})
	return out
}

// parseForceOverwrite reads the confirm page's own posted checkbox set.
func parseForceOverwrite(f map[string][]string) map[string]bool {
	out := make(map[string]bool, len(f["force_overwrite"]))
	for _, v := range f["force_overwrite"] {
		out[v] = true
	}
	return out
}

type collisionConfirmData struct {
	Collisions   []collisionRow
	HiddenFields template.HTML
	CancelHref   string
}

// applyLinksWithCollisionGate is the ONE place the two-phase "detect,
// confirm, apply" flow is implemented — used identically by mass-
// rollout and scope groups.
func applyLinksWithCollisionGate(
	w http.ResponseWriter, r *http.Request, cfg *WebConfig, store *TemplateStore,
	c config.Cluster, target map[string]bool, links map[string]config.ContentLink,
	confirmed bool, forceOverwrite map[string]bool,
	confirmHiddenFields template.HTML, confirmCancelHref string,
	backLink, backText string,
) {
	var remaining []collisionRow
	for _, col := range detectCollisions(c.Scopes, target, links, store) {
		if !forceOverwrite[col.CheckboxValue] {
			remaining = append(remaining, col)
		}
	}
	if len(remaining) > 0 && !confirmed {
		renderTemplate(w, collisionConfirmTmpl, collisionConfirmData{
			Collisions: remaining, HiddenFields: confirmHiddenFields, CancelHref: confirmCancelHref,
		}, "collision-confirm")
		return
	}
	skip := make(map[string]bool, len(remaining))
	for _, col := range remaining {
		skip[col.CheckboxValue] = true
	}

	candidate := make(map[string]config.ScopeConfig, len(c.Scopes))
	for name, sc := range c.Scopes {
		if target[name] {
			merged := make(map[string]config.ContentLink, len(sc.ContentLinks)+len(links))
			for k, v := range sc.ContentLinks {
				merged[k] = v
			}
			for fieldKey, link := range links {
				if skip[name+"|"+fieldKey] {
					continue // keep the operator's own existing content for this field
				}
				merged[fieldKey] = link
			}
			sc.ContentLinks = merged
		}
		candidate[name] = sc
	}
	resolved, _ := propagateLinkedScopes(candidate, store)

	payload := clusterPushPayloadFrom(c)
	payload.Scopes = resolved
	user, _ := userFromContext(r)
	pushCandidateAndRenderResult(w, cfg, payload, user, backLink, backText)
}

var collisionConfirmTmpl = template.Must(template.New("collision-confirm").Parse(`<!doctype html>
<title>dnshived-web — existing content found</title>
` + styleHTML + `
<h1>Existing content found</h1>
` + navHTML + `
<p class="warn">These fields already have real content — manually set,
or linked to something else. They're left exactly as-is (kept) unless
you tick "overwrite" for that one. Nothing has been applied yet.</p>
<div class="table-wrap"><table><tr><th>scope</th><th>field</th><th>what's there now</th><th>overwrite?</th></tr>
{{range .Collisions}}<tr><td>{{.Scope}}</td><td>{{.FieldLabel}}</td><td class="dim">{{.Detail}}</td>
<td><label><input type="checkbox" name="force_overwrite" value="{{.CheckboxValue}}"> overwrite</label></td></tr>
{{end}}
</table></div>
<form method="post" onsubmit="var n=this.querySelectorAll('input[name=force_overwrite]:checked').length;return n===0||confirm('This will overwrite '+n+' existing entr'+(n===1?'y':'ies')+' with manual or differently-linked content. Proceed?');">
{{.HiddenFields}}
<input type="hidden" name="confirmed" value="1">
<button type="submit">Apply — keeping everything left unchecked above</button>
</form>
<p><a href="{{.CancelHref}}">cancel, start over</a></p>
`))
