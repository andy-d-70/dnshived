// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"dnshived/internal/config"
	"dnshived/internal/webauth"
)

// candidateResponse mirrors cmd/dnshived's GET /api/v1/candidate wire
// shape.
type candidateResponse struct {
	Exists    bool           `json:"exists"`
	Candidate config.Cluster `json:"candidate"`
}

// fetchCandidate reads one node's staged, not-yet-applied candidate —
// exists is false (Candidate zero-valued) when nothing is pending there.
func fetchCandidate(node NodeConfig) (config.Cluster, bool, error) {
	req, err := http.NewRequest(http.MethodGet, node.baseURL()+"/api/v1/candidate", nil)
	if err != nil {
		return config.Cluster{}, false, err
	}
	if node.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+node.AdminToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return config.Cluster{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return config.Cluster{}, false, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	var cr candidateResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return config.Cluster{}, false, err
	}
	return cr.Candidate, cr.Exists, nil
}

// firstReachableCandidate returns the first reachable node's candidate and
// whether one actually exists there — the Pending Changes page's own
// read path.
func firstReachableCandidate(nodes []NodeConfig) (c config.Cluster, exists bool, node NodeConfig, err error) {
	var lastErr error
	sawReachableWithNoCandidate := false
	var noCandidateNode NodeConfig
	for _, n := range nodes {
		cand, ex, cerr := fetchCandidate(n)
		if cerr != nil {
			lastErr = cerr
			continue
		}
		if ex {
			return cand, true, n, nil
		}
		if !sawReachableWithNoCandidate {
			sawReachableWithNoCandidate, noCandidateNode = true, n
		}
	}
	if sawReachableWithNoCandidate {
		return config.Cluster{}, false, noCandidateNode, nil
	}
	return config.Cluster{}, false, NodeConfig{}, fmt.Errorf("no node reachable, last error: %w", lastErr)
}

// currentEditableConfig is what every edit FORM reads its baseline from.
func currentEditableConfig(nodes []NodeConfig) (c config.Cluster, node NodeConfig, isPending bool, err error) {
	var lastErr error
	liveFallback, haveLiveFallback := config.Cluster{}, false
	var liveNode NodeConfig
	for _, n := range nodes {
		cand, exists, cerr := fetchCandidate(n)
		if cerr != nil {
			lastErr = cerr
			continue
		}
		if exists {
			live, lerr := fetchConfig(n)
			if lerr == nil {
				hasRealDiff := len(diffClusterFields(live, cand)) > 0 ||
					len(diffScopes(live.Scopes, cand.Scopes, cand.GlobalDNSRecords, cand.DefaultDHCPOptions)) > 0
				if hasRealDiff {
					return cand, n, true, nil
				}
				if !haveLiveFallback {
					liveFallback, liveNode, haveLiveFallback = live, n, true
				}
				continue
			}
			return cand, n, true, nil
		}
		if !haveLiveFallback {
			live, lerr := fetchConfig(n)
			if lerr != nil {
				lastErr = lerr
				continue
			}
			liveFallback, liveNode, haveLiveFallback = live, n, true
		}
	}
	if haveLiveFallback {
		return liveFallback, liveNode, false, nil
	}
	return config.Cluster{}, NodeConfig{}, false, fmt.Errorf("no node reachable, last error: %w", lastErr)
}

// pushCandidate calls POST /api/v1/candidate on node — the staged-save
// half of the workflow, mirroring pushConfig exactly except for the target
// path.
func pushCandidate(node NodeConfig, payload []byte) (status int, respBody []byte, err error) {
	req, err := http.NewRequest(http.MethodPost, node.baseURL()+"/api/v1/candidate", bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if node.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+node.AdminToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, err = io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, err
}

// discardCandidate calls DELETE /api/v1/candidate on node — reverts
// every pending change on that one node at once.
func discardCandidate(node NodeConfig) error {
	req, err := http.NewRequest(http.MethodDelete, node.baseURL()+"/api/v1/candidate", nil)
	if err != nil {
		return err
	}
	if node.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+node.AdminToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// discardCandidateScope calls DELETE /api/v1/candidate/scopes/<name> on
// node — reverts just one scope's pending edit back to its live value.
func discardCandidateScope(node NodeConfig, scope string) error {
	req, err := http.NewRequest(http.MethodDelete, node.baseURL()+"/api/v1/candidate/scopes/"+url.PathEscape(scope), nil)
	if err != nil {
		return err
	}
	if node.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+node.AdminToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// pushCandidateAndRenderResult is pushConfigAndRenderResult's staged-save
// counterpart.
func pushCandidateAndRenderResult(w http.ResponseWriter, cfg *WebConfig, payload configPushPayload, user webauth.User, backLink, backText string) {
	nodes := nodesIncludingSelf(cfg)

	type candidateSaveResult struct {
		Node          NodeConfig
		Unreachable   bool
		CheckOK       bool
		CheckErrors   []string
		CheckWarnings []string
		RawBody       string
	}

	results := make([]candidateSaveResult, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Add(1)
		go func(i int, n NodeConfig) {
			defer wg.Done()
			res := candidateSaveResult{Node: n}
			body, err := json.Marshal(payloadForNode(payload, n))
			if err != nil {
				res.Unreachable = true
				res.RawBody = err.Error()
				results[i] = res
				return
			}
			status, respBody, err := pushCandidate(n, body)
			if err != nil {
				res.Unreachable = true
				res.RawBody = err.Error()
				results[i] = res
				return
			}
			var check configCheckResponse
			if jsonErr := json.Unmarshal(respBody, &check); jsonErr != nil {
				res.RawBody = string(respBody)
				results[i] = res
				return
			}
			res.CheckErrors, res.CheckWarnings = check.Errors, check.Warnings
			res.CheckOK = status == http.StatusOK && check.OK
			results[i] = res

			summary := "staged a pending config change via dnshived-web"
			if !res.CheckOK {
				summary += " — REJECTED by config check"
			}
			pushAudit(n, user.Name, "candidate.save", summary)
		}(i, n)
	}
	wg.Wait()

	allOK := true
	for _, res := range results {
		if res.Unreachable || !res.CheckOK {
			allOK = false
			break
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<!doctype html><title>dnshived-web — pending change saved</title>\n"+styleHTML+navHTML+"\n")
	if allOK {
		fmt.Fprintf(w, "<h1 class=\"ok\">Staged on all %d node(s) — nothing applied yet</h1>\n"+
			"<p>Review and commit (or discard) from <a href=\"/pending\">Pending changes</a>.</p>\n", len(nodes))
	} else {
		fmt.Fprint(w, "<h1 class=\"crit\">Partial or full failure staging this change</h1>\n"+
			"<p>Nothing was applied to the live cluster either way — a rejected/unreachable stage attempt "+
			"never reaches Commit. Check the per-node results below, fix the problem, and re-submit.</p>\n")
	}
	fmt.Fprintf(w, "<p><a href=\"%s\">%s</a> &nbsp;|&nbsp; <a href=\"/pending\">go to pending changes &rarr;</a></p>\n", backLink, backText)
	fmt.Fprint(w, `<table border="1" cellpadding="4"><tr><th>Node</th><th>Result</th></tr>`+"\n")
	for _, res := range results {
		cell := `<span class="ok">staged</span>`
		switch {
		case res.Unreachable:
			cell = fmt.Sprintf(`<span class="crit">unreachable: %s</span>`, template.HTMLEscapeString(res.RawBody))
		case len(res.CheckErrors) > 0:
			var b strings.Builder
			b.WriteString(`<span class="crit">rejected:</span><ul>`)
			for _, e := range res.CheckErrors {
				fmt.Fprintf(&b, "<li>%s</li>", template.HTMLEscapeString(e))
			}
			b.WriteString("</ul>")
			cell = b.String()
		case res.RawBody != "":
			cell = fmt.Sprintf(`<span class="warn">unexpected response: %s</span>`, template.HTMLEscapeString(res.RawBody))
		}
		if len(res.CheckWarnings) > 0 {
			var b strings.Builder
			b.WriteString(cell + `<br><span class="warn">warnings:</span><ul>`)
			for _, wtext := range res.CheckWarnings {
				fmt.Fprintf(&b, "<li>%s</li>", template.HTMLEscapeString(wtext))
			}
			b.WriteString("</ul>")
			cell = b.String()
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td></tr>\n", res.Node.Name, cell)
	}
	fmt.Fprintf(w, "</table>\n<p><a href=\"%s\">%s</a> &nbsp;|&nbsp; <a href=\"/pending\">go to pending changes &rarr;</a></p>\n", backLink, backText)
}

const pendingBannerHTML = `{{if .Pending}}<p class="warn">Editing a PENDING change, not what's currently live — see <a href="/pending">pending changes</a> to review, discard, or commit it.</p>{{end}}`
