// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"sync"

	"dnshived/internal/activation"
	"dnshived/internal/cluster"
)

// peerIdentity is the part of a node's /api/v1/status the activation check reads.
type peerIdentity struct {
	NodeID  string `json:"node_id"`
	Role    string `json:"role"`
	Version string `json:"version"`
}

// activationMembers turns the fetched snapshots into members. A snapshot
// with an error, or a status that does not decode, counts as unreachable.
func activationMembers(selfName, selfRole, selfVersion string, peers []string, snaps []nodeSnapshot) []activation.Member {
	members := make([]activation.Member, 0, len(peers)+1)
	members = append(members, activation.Member{Name: selfName, Role: selfRole, Version: selfVersion, Reachable: true})
	for i, addr := range peers {
		m := activation.Member{Name: addr}
		var id peerIdentity
		if snaps[i].Error == "" && json.Unmarshal(snaps[i].Status, &id) == nil {
			m.Reachable = true
			m.Role = id.Role
			m.Version = id.Version
			if id.NodeID != "" {
				m.Name = id.NodeID
			}
		}
		members = append(members, m)
	}
	return members
}

// clusterActivationHandler builds GET /api/v1/cluster/activation: whether
// every configured core member runs at least activation.FeatureVersion.
func clusterActivationHandler(observer *cluster.Observer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fresh := currentConfig.Load()
		scheme := "http"
		if fresh.TLSEnabled() {
			scheme = "https"
		}
		token := anyAPIToken(fresh.APITokens)
		peers := fresh.Peers
		snaps := make([]nodeSnapshot, len(peers))
		var wg sync.WaitGroup
		for i, addr := range peers {
			wg.Add(1)
			go func(i int, addr string) {
				defer wg.Done()
				snaps[i] = fetchPeerSnapshot(scheme, addr, token, observer)
			}(i, addr)
		}
		wg.Wait()
		members := activationMembers(fresh.NodeID, fresh.Role, version, peers, snaps)
		writeJSON(w, http.StatusOK, activation.Evaluate(activation.FeatureVersion, members))
	}
}
