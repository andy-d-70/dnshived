// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"dnshived/internal/config"
)

type parkedRow struct {
	Name         string
	VLAN         int
	VIP          string
	Reservations int
	Records      int
}

func buildParkedRows(parked map[string]config.ScopeConfig) []parkedRow {
	rows := make([]parkedRow, 0, len(parked))
	for name, sc := range parked {
		rows = append(rows, parkedRow{Name: name, VLAN: sc.VLANID, VIP: sc.VIP, Reservations: len(sc.Reservations), Records: len(sc.DNSRecords)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows
}

// moveParkedScopes returns the live and parked maps after enabling the named scopes
// (all of them when names is empty and all is set). A scope that is also live is refused.
func moveParkedScopes(live, parked map[string]config.ScopeConfig, names []string, all bool) (newLive, newParked map[string]config.ScopeConfig, moved []string, err error) {
	if all {
		names = names[:0]
		for name := range parked {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	newLive = make(map[string]config.ScopeConfig, len(live)+len(names))
	for k, v := range live {
		newLive[k] = v
	}
	newParked = make(map[string]config.ScopeConfig, len(parked))
	for k, v := range parked {
		newParked[k] = v
	}
	for _, name := range names {
		sc, ok := newParked[name]
		if !ok {
			return nil, nil, nil, fmt.Errorf("scope %q is not parked", name)
		}
		if _, dup := newLive[name]; dup {
			return nil, nil, nil, fmt.Errorf("a live scope named %q exists already", name)
		}
		sc.NodeIP = ""
		newLive[name] = sc
		delete(newParked, name)
		moved = append(moved, name)
	}
	return newLive, newParked, moved, nil
}

func handleParkedEnable(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		cfg := ref.Load()
		current, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		all := r.PostForm.Get("all") != ""
		var names []string
		for _, n := range r.PostForm["name"] {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
		if !all && len(names) == 0 {
			http.Error(w, "no parked scope chosen", http.StatusBadRequest)
			return
		}
		live, parked, moved, err := moveParkedScopes(current.Scopes, current.ParkedScopes, names, all)
		if err != nil {
			http.Error(w, "not staged: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(moved) == 0 {
			http.Redirect(w, r, "/scopes", http.StatusSeeOther)
			return
		}
		payload := clusterPushPayloadFrom(current)
		payload.Scopes = live
		payload.ParkedScopes = &parked
		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/scopes", "back to scopes")
	}
}

func handleParkedRemove(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		cfg := ref.Load()
		current, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		name := strings.TrimSpace(r.PostForm.Get("name"))
		if _, ok := current.ParkedScopes[name]; !ok {
			http.Error(w, fmt.Sprintf("scope %q is not parked", name), http.StatusNotFound)
			return
		}
		parked := make(map[string]config.ScopeConfig, len(current.ParkedScopes))
		for k, v := range current.ParkedScopes {
			if k != name {
				parked[k] = v
			}
		}
		payload := clusterPushPayloadFrom(current)
		payload.Scopes = current.Scopes
		payload.ParkedScopes = &parked
		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/scopes", "back to scopes")
	}
}

const parkedSectionHTML = `{{if .Parked}}
<h2 id="parked" style="margin-top:1.4rem">Parked scopes <span class="count-badge">{{len .Parked}}</span></h2>
<p class="dim">Kept in the configuration, but nothing is built or served for them: no VLAN interface, no VRRP, no DHCP or DNS. Enabling stages them as pending changes; nothing changes until you commit.</p>
<div class="table-wrap"><table class="list-table" border="1" cellpadding="4" cellspacing="0">
<tr><th>Scope</th><th>VLAN</th><th>VIP</th><th>Reservations</th><th>DNS records</th><th style="width:14rem"></th></tr>
{{range .Parked}}<tr><td>{{.Name}}</td><td>{{.VLAN}}</td><td>{{.VIP}}</td><td>{{.Reservations}}</td><td>{{.Records}}</td>
<td><form method="post" action="/scopes/parked/enable" style="display:inline"><input type="hidden" name="name" value="{{.Name}}"><button type="submit">Enable</button></form>
<form method="post" action="/scopes/parked/remove" style="display:inline" onsubmit="return confirm('Remove the parked scope {{.Name}} from the configuration?')"><input type="hidden" name="name" value="{{.Name}}"><button type="submit" class="btn-danger">Remove</button></form></td></tr>
{{end}}</table></div>
<form method="post" action="/scopes/parked/enable" onsubmit="return confirm('Enable every parked scope? This stages {{len .Parked}} scope(s) to be built on the cores: VLAN interfaces, VRRP and DHCP/DNS serving start after the commit.')"><input type="hidden" name="all" value="1"><button type="submit" class="btn-primary" style="margin-top:.6rem">Enable all</button></form>
{{end}}`
