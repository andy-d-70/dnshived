// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

func handleReliabilityResetPost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		role := r.PostForm.Get("role")
		parent := r.PostForm.Get("parent")
		if role == "" || parent == "" {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		var wg sync.WaitGroup
		var mu sync.Mutex
		var ok int
		var failed []string
		for _, n := range nodesIncludingSelf(cfg) {
			wg.Add(1)
			go func(n NodeConfig) {
				defer wg.Done()
				err := resetReliabilityOnNode(n, role, parent)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					failed = append(failed, n.displayName())
				} else {
					ok++
				}
			}(n)
		}
		wg.Wait()

		q := url.Values{}
		q.Set("reset_target", role+" / "+parent)
		q.Set("reset_ok", strconv.Itoa(ok))
		if len(failed) > 0 {
			q.Set("reset_failed", strings.Join(failed, ","))
		}
		http.Redirect(w, r, "/?"+q.Encode(), http.StatusSeeOther)
	}
}

// resetReliabilityOnNode POSTs a reset request to n's own POST
// /api/v1/reliability/reset — mirrors createBackupOnNode's own request
// shape (backup.go).
func resetReliabilityOnNode(n NodeConfig, role, parent string) error {
	body, err := json.Marshal(map[string]string{"role": role, "parent": parent})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, n.baseURL()+"/api/v1/reliability/reset", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if n.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.AdminToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// resetResultBanner renders handleReliabilityResetPost's own redirect
// query params (reset_target/reset_ok/reset_failed) into the Overview
// page's one-line banner.
func resetResultBanner(q url.Values) (text, class string) {
	target := q.Get("reset_target")
	if target == "" {
		return "", ""
	}
	ok := q.Get("reset_ok")
	failed := q.Get("reset_failed")
	if failed == "" {
		return "Reset trust-index history for " + target + " on " + ok + " node(s).", "ok"
	}
	return "Reset trust-index history for " + target + " on " + ok + " node(s); failed on: " + failed, "warn"
}
