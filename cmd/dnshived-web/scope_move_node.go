// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"dnshived/internal/config"
)

// reachableCoreRoles lists the core roles that answered the status fetch.
func reachableCoreRoles(rows []statusRow) []string {
	var roles []string
	for _, row := range rows {
		if row.FetchError == "" && isCoreRole(row.Status.Role) {
			roles = append(roles, row.Status.Role)
		}
	}
	sort.Strings(roles)
	return roles
}

// moveTargetsFor are the cores a scope can be moved to from its row menu: every
// reachable core except the one serving it now.
func moveTargetsFor(cores []string, serving string) []string {
	var out []string
	for _, c := range cores {
		if c != serving {
			out = append(out, c)
		}
	}
	return out
}

// moveToNodeScopes returns scopes with the named scope's preferred worker set to
// node and the rebalance approved, so that after the commit the scope moves there
// once that core is alive and stable. The input map is not changed.
func moveToNodeScopes(scopes map[string]config.ScopeConfig, scope, node string, cores []string, now int64) (map[string]config.ScopeConfig, error) {
	sc, ok := scopes[scope]
	if !ok {
		return nil, fmt.Errorf("scope %q is not in the cluster configuration", scope)
	}
	if !isCoreRole(node) {
		return nil, fmt.Errorf("%q is not a core role", node)
	}
	known := false
	for _, c := range cores {
		if c == node {
			known = true
		}
	}
	if !known {
		return nil, fmt.Errorf("%s is not a configured core of this cluster", node)
	}
	out := make(map[string]config.ScopeConfig, len(scopes))
	for name, s := range scopes {
		out[name] = s
	}
	sc.PreferredWorker = node
	sc.RebalanceApprovedAt = now
	out[scope] = sc
	return out, nil
}

// handleScopeMoveToNode serves POST /scopes/{name}/move-to-node (form field node).
func handleScopeMoveToNode(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		scope := r.PathValue("name")
		node := strings.TrimSpace(r.FormValue("node"))

		c, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "fetch current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		var cores []string
		for _, n := range nodesIncludingSelf(cfg) {
			if isCoreRole(n.Name) {
				cores = append(cores, n.Name)
			}
		}
		newScopes, err := moveToNodeScopes(c.Scopes, scope, node, cores, time.Now().Unix())
		if err != nil {
			status := http.StatusBadRequest
			if _, exists := c.Scopes[scope]; !exists {
				status = http.StatusNotFound
			}
			http.Error(w, err.Error(), status)
			return
		}
		payload := clusterPushPayloadFrom(c)
		payload.Scopes = newScopes

		user, _ := userFromContext(r)
		back, backText := returnTargetOr(r, "/scopes", "back to scopes")
		pushCandidateAndRenderResult(w, cfg, payload, user, back, backText)
	}
}
