// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"path/filepath"
	"strings"

	"dnshived/internal/dhcpcentralrender"
	"dnshived/internal/dhcplease"
	"dnshived/internal/neighbors"
)

const maxHostsViewScopes = 512

type hostsViewScope struct {
	Leases      []dhcplease.Lease    `json:"leases"`
	Neighbors   []neighbors.Neighbor `json:"neighbors"`
	NeighborsOK bool                 `json:"neighbors_ok"`
}

// registerHostsViewRoutes answers the leases and the neighbour table of many
// scopes in one call, so the hosts page asks a core once instead of twice per scope.
func registerHostsViewRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/hosts-view", func(w http.ResponseWriter, r *http.Request) {
		cfg := currentConfig.Load()
		names := strings.Split(r.URL.Query().Get("scopes"), ",")
		if len(names) > maxHostsViewScopes {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "too many scopes"})
			return
		}
		all, err := dhcplease.ParseFile(filepath.Join(dataDir(cfg), dhcpcentralrender.CoreDHCPLeaseFileName))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out := make(map[string]hostsViewScope, len(names))
		for _, name := range names {
			sc, ok := cfg.Scopes[name]
			if !ok {
				continue
			}
			v := hostsViewScope{Leases: []dhcplease.Lease{}, Neighbors: []neighbors.Neighbor{}}
			if sc.DHCPRange[0] != "" && sc.DHCPRange[1] != "" {
				for _, l := range all {
					if dhcplease.InRange(l.IP, sc.DHCPRange[0], sc.DHCPRange[1]) {
						v.Leases = append(v.Leases, l)
					}
				}
			}
			if iface, _, _, ok := scopeNeighborView(sc); ok {
				if list, err := neighbors.List(iface); err == nil {
					v.NeighborsOK = true
					if list != nil {
						v.Neighbors = list
					}
				}
			}
			out[name] = v
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"scopes": out})
	})
}
