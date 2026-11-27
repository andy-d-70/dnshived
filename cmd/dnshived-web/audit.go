// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"io"
	"net/http"
	"sync"
)

// nodeAuditSection is one node's own fetched audit-log body.
type nodeAuditSection struct {
	Node   NodeConfig
	Body   string
	Err    error
	Merged bool
}

func fetchNodeAuditSections(nodes []NodeConfig) []nodeAuditSection {
	results := make([]nodeAuditSection, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n NodeConfig) {
			defer wg.Done()
			results[i].Node = n
			req, err := http.NewRequest(http.MethodGet, n.baseURL()+"/api/v1/audit", nil)
			if err != nil {
				results[i].Err = err
				return
			}
			if n.AdminToken != "" {
				req.Header.Set("Authorization", "Bearer "+n.AdminToken)
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				results[i].Err = err
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				results[i].Err = err
				return
			}
			results[i].Body = string(body)
			results[i].Merged = resp.Header.Get("X-Audit-Merged") == "1"
		}(i, n)
	}
	wg.Wait()
	return results
}

// handleAudit exports the audit log as one plain text page: the cores' shared log once (every core that keeps it
// holds the same entries), then the own file of each older node, one section each.
func handleAudit(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		mergedShown := false
		for _, sec := range fetchNodeAuditSections(cfg.Nodes) {
			if sec.Err == nil && sec.Merged {
				if mergedShown {
					continue
				}
				mergedShown = true
				fmt.Fprintf(w, "==== cluster (shared by the cores, served by %s) ====\n", sec.Node.Name)
				fmt.Fprint(w, sec.Body)
				fmt.Fprintln(w)
				continue
			}
			fmt.Fprintf(w, "==== %s (%s) ====\n", sec.Node.Name, sec.Node.Addr)
			if sec.Err != nil {
				fmt.Fprintf(w, "unreachable: %v\n\n", sec.Err)
				continue
			}
			fmt.Fprint(w, sec.Body)
			fmt.Fprintln(w)
		}
	}
}
