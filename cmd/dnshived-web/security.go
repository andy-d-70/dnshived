// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"html/template"
	"net/http"
)

// securityFormTmpl renders the API tokens section of the Security tab.
var securityFormTmpl = template.Must(template.New("security").Parse(`<!doctype html>
<title>dnshived-web — security</title>
` + styleHTML + `
<h1>Security</h1>
` + navHTML + pendingBannerHTML + `
<p>Snapshot from node: <strong>{{.SourceNode}}</strong>. Saving stages a
PENDING change on every configured node — nothing is applied until you
commit it from <a href="/pending">pending changes</a>. Cluster-wide
settings (PSK, TLS, platform, management VIP, ...) live on their own
page: <a href="/config">cluster config &rarr;</a>. To change your own
login password: <a href="/password">change password &rarr;</a>.</p>

<form method="post" action="/security" onsubmit="return confirm('This will stage these API tokens as a pending change on every configured node — nothing is applied until you commit from Pending changes. Continue?')">
<h2>API tokens</h2>
<p>Existing tokens fill the first rows (values hidden; leave the token field blank to keep it, clear the name to remove the row). A few extra blank rows are always added for new ones.</p>
<input type="hidden" name="__token_row_count__" value="{{.TokenRowCount}}">
<table border="1" cellpadding="4">
<tr><th>Name</th><th>Token</th><th>Role</th><th>Expires (RFC3339, blank = never)</th></tr>
{{range .Tokens}}
<tr>
  <td><input name="token_name_{{.Index}}" value="{{.Name}}"></td>
  <td><input type="password" name="token_value_{{.Index}}" value="" size="30" autocomplete="new-password" placeholder="{{if .HasToken}}unchanged{{else}}new token{{end}}" title="Token values are never sent to the browser. Leave blank to keep an existing token; clear its name to remove it."></td>
  <td>
    <select name="token_role_{{.Index}}">
      <option value="readonly" {{if eq .Role "readonly"}}selected{{end}}>readonly</option>
      <option value="admin" {{if eq .Role "admin"}}selected{{end}}>admin</option>
      <option value="probe" {{if eq .Role "probe"}}selected{{end}}>probe</option>
      <option value="probe-admin" {{if eq .Role "probe-admin"}}selected{{end}}>probe-admin</option>
    </select>
  </td>
  <td><input name="token_expires_{{.Index}}" value="{{.Expires}}"></td>
</tr>
{{end}}
</table>

<p><input type="submit" value="Stage as pending change"></p>
</form>

<h2>Users</h2>
<p>Web-UI logins, roles (admin, scopeadmin, readonly) and email addresses for password reset:
<a href="/users">manage users &rarr;</a> (admins only). Users are replicated to every core.
Reset emails need the mail settings: <a href="/config/mail">mail &rarr;</a>. Console fallback on any core:
<code>dnshived-web -reset-user &lt;name&gt; [-role admin|scopeadmin|readonly] [-email &lt;address&gt;]</code>.</p>
`))

func handleSecurityGet(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		c, node, isPending, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read config from any node: "+err.Error(), http.StatusBadGateway)
			return
		}
		data := buildClusterFormData(c, node, nodesIncludingSelf(cfg))
		data.Pending = isPending
		renderTemplate(w, securityFormTmpl, data, "security")
	}
}

// handleSecurityPost mirrors every sibling split-off page's save pattern:
// start from clusterPushPayloadFrom(current).
func handleSecurityPost(ref *configRef) http.HandlerFunc {
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
		payload.APITokens = parseTokenSlots(r.PostForm, current.APITokens)

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/security", "back to security")
	}
}
