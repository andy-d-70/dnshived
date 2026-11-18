// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"dnshived/internal/auth"
	"dnshived/internal/config"
	"dnshived/internal/neighbors"
)

const neighborProbeGap = 2 * time.Second

var (
	neighborProbeMu sync.Mutex
	neighborProbeAt = map[string]time.Time{}
)

// neighborProbeAllowed lets one probe per scope through every neighborProbeGap.
func neighborProbeAllowed(scope string, now time.Time) bool {
	neighborProbeMu.Lock()
	defer neighborProbeMu.Unlock()
	if now.Sub(neighborProbeAt[scope]) < neighborProbeGap {
		return false
	}
	neighborProbeAt[scope] = now
	return true
}

// scopeNeighborView names the interface of a scope on this node, its network and an address of this node on it.
func scopeNeighborView(sc config.ScopeConfig) (iface string, network netip.Prefix, local netip.Addr, ok bool) {
	if sc.Parent == "" || sc.VLANID == 0 || sc.VIP == "" {
		return "", netip.Prefix{}, netip.Addr{}, false
	}
	p, err := netip.ParsePrefix(sc.VIP)
	if err != nil || !p.Addr().Is4() {
		return "", netip.Prefix{}, netip.Addr{}, false
	}
	iface = sc.Parent + "." + strconv.Itoa(sc.VLANID)
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return "", netip.Prefix{}, netip.Addr{}, false
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return "", netip.Prefix{}, netip.Addr{}, false
	}
	network = p.Masked()
	for _, a := range addrs {
		ipn, isNet := a.(*net.IPNet)
		if !isNet {
			continue
		}
		ip, good := netip.AddrFromSlice(ipn.IP.To4())
		if good && network.Contains(ip) && ip != p.Addr() {
			return iface, network, ip, true
		}
	}
	return "", netip.Prefix{}, netip.Addr{}, false
}

func registerNeighborRoutes(mux *http.ServeMux, authMw *auth.Middleware) {
	mux.HandleFunc("GET /api/v1/neighbors/{scope}", func(w http.ResponseWriter, r *http.Request) {
		sc, found := currentConfig.Load().Scopes[r.PathValue("scope")]
		iface, _, _, ok := scopeNeighborView(sc)
		if !found || !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "this node has no interface for that scope"})
			return
		}
		list, err := neighbors.List(iface)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if list == nil {
			list = []neighbors.Neighbor{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"neighbors": list})
	})

	mux.HandleFunc("POST /api/v1/neighbors/{scope}/probe", authMw.RequireAdmin(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("scope")
		sc, found := currentConfig.Load().Scopes[name]
		iface, network, local, ok := scopeNeighborView(sc)
		if !found || !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "this node has no interface for that scope"})
			return
		}
		var body struct {
			IPs []string `json:"ips"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request body"})
			return
		}
		targets, err := neighbors.CheckTargets(network, body.IPs)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if !neighborProbeAllowed(name, time.Now()) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "probe again in a moment"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		got, err := neighbors.Probe(ctx, iface, local, targets, time.Second)
		if err != nil && len(got) == 0 {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if got == nil {
			got = []neighbors.Neighbor{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"neighbors": got})
	}))
}
