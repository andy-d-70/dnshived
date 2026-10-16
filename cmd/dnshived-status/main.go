// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// dnshived-status queries a dnshived cluster and reports health.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"dnshived/internal/clientrc"
)

var version = "0.9.7-dev"

var (
	scheme   = "http"
	apiToken = ""
)

// nodeStatus is the subset of /api/v1/status we consume.
type nodeStatus struct {
	NodeID      string            `json:"node_id"`
	Role        string            `json:"role"`
	ClusterID   string            `json:"cluster_id"`
	State       string            `json:"state"`
	Epoch       uint64            `json:"epoch"`
	Generation  uint64            `json:"generation"`
	Incarnation uint64            `json:"incarnation"`
	Healthy     bool              `json:"healthy"`
	Serving     []string          `json:"serving"`
	Watermark   map[string]uint64 `json:"watermark"`
	Version     string            `json:"version"`
}

// clusterView is /api/v1/cluster.
type clusterView struct {
	Self         nodeIdentity `json:"self"`
	SelfAddr     string       `json:"self_addr"`
	PeerCount    int          `json:"peer_count"`
	ReachableNow int          `json:"reachable_now"`
	Peers        []peerState  `json:"peers"`
}

type nodeIdentity struct {
	NodeID    string `json:"node_id"`
	Role      string `json:"role"`
	ClusterID string `json:"cluster_id"`
}

type peerState struct {
	Addr      string        `json:"addr"`
	Reachable bool          `json:"reachable"`
	Identity  *nodeIdentity `json:"identity,omitempty"`
}

// tokenStatus is /api/v1/token/status (arbiter only).
type tokenStatus map[string]struct {
	Owner     string `json:"owner"`
	ExpiresAt string `json:"expires_at"`
	Expired   bool   `json:"expired"`
}

// clusterReport is the assembled view across all reachable nodes.
type clusterReport struct {
	ReportVersion  int          `json:"report_version"`
	GeneratedAt    string       `json:"generated_at"`
	ClusterID      string       `json:"cluster_id"`
	Nodes          []nodeReport `json:"nodes"`
	Tokens         tokenStatus  `json:"tokens,omitempty"`
	ExitCode       int          `json:"exit_code"`
	Summary        string       `json:"summary"`
	VersionWarning string       `json:"version_warning,omitempty"`
}

type nodeReport struct {
	Addr      string            `json:"addr"`
	NodeID    string            `json:"node_id"`
	Role      string            `json:"role"`
	State     string            `json:"state"`
	StateInfo string            `json:"state_info,omitempty"`
	Serving   []string          `json:"serving"`
	Epoch     uint64            `json:"epoch,omitempty"`
	Gen       uint64            `json:"generation,omitempty"`
	Watermark map[string]uint64 `json:"watermark,omitempty"`
	Version   string            `json:"version,omitempty"`
	Reachable bool              `json:"reachable"`
}

var client = &http.Client{
	Timeout: 3 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:      10,
		MaxConnsPerHost:   2,
		IdleConnTimeout:   30 * time.Second,
		DisableKeepAlives: false,
	},
}

// doGetJSON performs one authenticated GET against addr+path and decodes
// the JSON response into v.
func doGetJSON(addr, path string, v interface{}) (reason string, err error) {
	req, _ := http.NewRequest("GET", scheme+"://"+addr+path, nil)
	if apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+apiToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return classifyError(err), err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Sprintf("HTTP %d (auth failed)", resp.StatusCode), fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("HTTP %d", resp.StatusCode), fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return "bad response body", err
	}
	return "", nil
}

func fetchStatus(addr string) (*nodeStatus, string, error) {
	var s nodeStatus
	reason, err := doGetJSON(addr, "/api/v1/status", &s)
	if err != nil {
		return nil, reason, err
	}
	return &s, "", nil
}

func fetchCluster(addr string) (*clusterView, error) {
	var c clusterView
	if _, err := doGetJSON(addr, "/api/v1/cluster", &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func fetchTokens(addr string) (tokenStatus, error) {
	var t tokenStatus
	if _, err := doGetJSON(addr, "/api/v1/token/status", &t); err != nil {
		return nil, err
	}
	return t, nil
}

// classifyError extracts a human-readable reason from a network error.
func classifyError(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "connection refused"):
		return "connection refused"
	case strings.Contains(s, "i/o timeout") || strings.Contains(s, "context deadline exceeded"):
		return "timeout"
	case strings.Contains(s, "no such host"):
		return "DNS resolution failed"
	case strings.Contains(s, "connection reset"):
		return "connection reset"
	case strings.Contains(s, "tls"):
		return "TLS error"
	default:
		return "unreachable"
	}
}

func roleOrder(role string) int {
	switch role {
	case "core-1":
		return 0
	case "core-2":
		return 1
	case "core-3":
		return 2
	default:
		return 99
	}
}

// isCoreRole reports whether role is one of the 3 real core roles.
func isCoreRole(role string) bool {
	switch role {
	case "core-1", "core-2", "core-3":
		return true
	default:
		return false
	}
}

// fetchNodeResult holds the result of a parallel node fetch.
type fetchNodeResult struct {
	addr   string
	status *nodeStatus
	reason string
	err    error
}

func buildReport(entryAddr string) clusterReport {
	report := clusterReport{
		ReportVersion: 1,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		ExitCode:      0,
	}

	// Query the entry node for cluster topology.
	cv, err := fetchCluster(entryAddr)
	if err != nil {
		report.ExitCode = 2
		report.Summary = fmt.Sprintf("CRITICAL - cannot reach %s: %v", entryAddr, err)
		return report
	}

	// Collect all addresses: self + peers.
	addrs := []string{cv.SelfAddr}
	for _, p := range cv.Peers {
		addrs = append(addrs, p.Addr)
	}

	// Query all nodes in parallel.
	results := make([]fetchNodeResult, len(addrs))
	var wg sync.WaitGroup
	for i, addr := range addrs {
		wg.Add(1)
		go func(idx int, a string) {
			defer wg.Done()
			st, reason, err := fetchStatus(a)
			results[idx] = fetchNodeResult{addr: a, status: st, reason: reason, err: err}
		}(i, addr)
	}
	wg.Wait()

	// Assemble node reports from parallel results.
	for _, r := range results {
		if r.err != nil {
			report.Nodes = append(report.Nodes, nodeReport{
				Addr:      r.addr,
				State:     "UNREACHABLE",
				StateInfo: r.reason,
				Reachable: false,
			})
			if report.ExitCode < 2 {
				report.ExitCode = 2
			}
			continue
		}
		st := r.status
		report.ClusterID = st.ClusterID
		nr := nodeReport{
			Addr:      r.addr,
			NodeID:    st.NodeID,
			Role:      st.Role,
			State:     st.State,
			Serving:   st.Serving,
			Epoch:     st.Epoch,
			Gen:       st.Generation,
			Watermark: st.Watermark,
			Version:   st.Version,
			Reachable: true,
		}
		report.Nodes = append(report.Nodes, nr)

		switch st.State {
		case "STABLE":
			// ok
		case "DEGRADED":
			if report.ExitCode < 1 {
				report.ExitCode = 1
			}
		default:
			if report.ExitCode < 2 {
				report.ExitCode = 2
			}
		}
	}

	// Sort by role for consistent display.
	sort.Slice(report.Nodes, func(i, j int) bool {
		return roleOrder(report.Nodes[i].Role) < roleOrder(report.Nodes[j].Role)
	})

	// Try to fetch tokens from a reachable core node.
	var preferredAddr, fallbackAddr string
	for _, n := range report.Nodes {
		if !n.Reachable || !isCoreRole(n.Role) {
			continue
		}
		if n.Role == "core-3" {
			preferredAddr = n.Addr
		} else if fallbackAddr == "" {
			fallbackAddr = n.Addr
		}
	}
	for _, addr := range []string{preferredAddr, fallbackAddr} {
		if addr == "" {
			continue
		}
		tokens, err := fetchTokens(addr)
		if err == nil && len(tokens) > 0 {
			report.Tokens = tokens
			break
		}
	}

	// Build summary.
	total := len(report.Nodes)
	stable := 0
	reachable := 0
	for _, n := range report.Nodes {
		if n.State == "STABLE" {
			stable++
		}
		if n.Reachable {
			reachable++
		}
	}

	// Check for unserved scopes.
	if len(report.Tokens) > 0 {
		servedScopes := make(map[string]bool)
		for _, n := range report.Nodes {
			for _, s := range n.Serving {
				servedScopes[s] = true
			}
		}
		for scopeName, tok := range report.Tokens {
			if (!servedScopes[scopeName] || tok.Expired) && report.ExitCode < 1 {
				report.ExitCode = 1
			}
		}
	}

	// Check for mixed software versions.
	versions := make(map[string]bool)
	for _, n := range report.Nodes {
		if n.Reachable && n.Version != "" {
			versions[n.Version] = true
		}
	}
	if len(versions) > 1 {
		if report.ExitCode < 1 {
			report.ExitCode = 1
		}
		vList := make([]string, 0, len(versions))
		for v := range versions {
			vList = append(vList, v)
		}
		sort.Strings(vList)
		report.VersionWarning = "mixed versions: " + strings.Join(vList, ", ")
	}

	var servingParts []string
	for _, n := range report.Nodes {
		for _, s := range n.Serving {
			servingParts = append(servingParts, fmt.Sprintf("%s→%s", s, n.Role))
		}
	}
	sort.Strings(servingParts)
	servingStr := strings.Join(servingParts, " ")
	if servingStr == "" {
		servingStr = "(none)"
	}

	prefix := "OK"
	if report.ExitCode == 1 {
		prefix = "WARNING"
	} else if report.ExitCode >= 2 {
		prefix = "CRITICAL"
	}

	report.Summary = fmt.Sprintf("%s - cluster %s: %d/%d STABLE (%d reachable) | %s",
		prefix, report.ClusterID, stable, total, reachable, servingStr)
	if report.VersionWarning != "" {
		report.Summary += " [" + report.VersionWarning + "]"
	}

	return report
}

func printDefault(r clusterReport) {
	fmt.Println(r.Summary)
	if r.VersionWarning != "" {
		fmt.Printf("  WARNING: %s\n", r.VersionWarning)
	}
}

func printVerbose(r clusterReport, level int) {
	total := len(r.Nodes)
	stable := 0
	reachable := 0
	for _, n := range r.Nodes {
		if n.State == "STABLE" {
			stable++
		}
		if n.Reachable {
			reachable++
		}
	}

	fmt.Printf("CLUSTER %s — %d/%d STABLE (%d reachable)\n", r.ClusterID, stable, total, reachable)
	if r.VersionWarning != "" {
		fmt.Printf("  WARNING: %s\n", r.VersionWarning)
	}

	for _, n := range r.Nodes {
		serving := ""
		if len(n.Serving) > 0 {
			serving = "serving=[" + strings.Join(n.Serving, ",") + "]"
		}

		if !n.Reachable {
			fmt.Printf("  %-10s %-20s UNREACHABLE (%s)\n", n.Role, n.Addr, n.StateInfo)
			continue
		}

		if level >= 2 {
			wmStr := ""
			if wm, ok := n.Watermark["epoch"]; ok {
				wmStr = fmt.Sprintf(" wm=%d/%d", wm, n.Watermark["generation"])
			}
			fmt.Printf("  %-10s %-20s %-10s %-24s epoch=%d gen=%d%s v=%s\n",
				n.Role, n.Addr, n.State, serving, n.Epoch, n.Gen, wmStr, n.Version)
		} else {
			fmt.Printf("  %-10s %-20s %-10s %s\n",
				n.Role, n.Addr, n.State, serving)
		}
	}

	if level >= 2 && len(r.Tokens) > 0 {
		fmt.Println("\nTOKENS:")
		for _, scope := range sortedTokenScopes(r.Tokens) {
			tok := r.Tokens[scope]
			status := "active"
			if tok.Expired {
				status = "EXPIRED"
			}
			fmt.Printf("  %-16s owner=%-16s %s\n", scope, tok.Owner, status)
		}
	}
}

func printJSON(r clusterReport) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		fmt.Fprintf(os.Stderr, "error encoding JSON: %v\n", err)
		os.Exit(2)
	}
}

// sortedTokenScopes returns scope names from a tokenStatus map in
// deterministic order.
func sortedTokenScopes(t tokenStatus) []string {
	scopes := make([]string, 0, len(t))
	for s := range t {
		scopes = append(scopes, s)
	}
	sort.Strings(scopes)
	return scopes
}

// watchLoop runs buildReport in a loop, presenting a live operator
// console.
func watchLoop(addr string, level int) {
	for {
		fmt.Print("\033[H\033[2J") // clear screen

		report := buildReport(addr)
		now := time.Now().Format("15:04:05 MST")

		// Banner
		fmt.Println("═══════════════════════════════════════════════════")
		switch {
		case report.ExitCode == 0:
			fmt.Println("")
			fmt.Println("  ✔  PRODUCTION ACTIVE")
			fmt.Println("")
		case report.ExitCode == 1:
			fmt.Println("")
			fmt.Println("  ⚠  WARNING")
			fmt.Println("")
		default:
			fmt.Println("")
			fmt.Println("  ✖  CRITICAL")
			fmt.Println("")
		}

		fmt.Printf("  Cluster  : %s\n", report.ClusterID)
		if report.VersionWarning != "" {
			fmt.Printf("  Versions : %s\n", report.VersionWarning)
		} else {
			ver := "unknown"
			for _, n := range report.Nodes {
				if n.Reachable && n.Version != "" {
					ver = n.Version
					break
				}
			}
			fmt.Printf("  Version  : %s\n", ver)
		}
		fmt.Printf("  Time     : %s\n", now)
		fmt.Println("═══════════════════════════════════════════════════")

		// Node table
		fmt.Println("")
		total := len(report.Nodes)
		stable := 0
		reachable := 0
		for _, n := range report.Nodes {
			if n.State == "STABLE" {
				stable++
			}
			if n.Reachable {
				reachable++
			}
		}
		fmt.Printf("  Nodes: %d/%d STABLE (%d reachable)\n\n", stable, total, reachable)

		for _, n := range report.Nodes {
			serving := "—"
			if len(n.Serving) > 0 {
				serving = strings.Join(n.Serving, ", ")
			}

			stateIcon := "✔"
			switch {
			case !n.Reachable:
				stateIcon = "✖"
			case n.State != "STABLE":
				stateIcon = "⚠"
			}

			if !n.Reachable {
				reason := n.StateInfo
				if reason == "" {
					reason = "unreachable"
				}
				fmt.Printf("  %s %-10s %-20s %-12s %s\n",
					stateIcon, n.Role, n.Addr, "DOWN", reason)
			} else if level >= 2 {
				wmStr := ""
				if wm, ok := n.Watermark["epoch"]; ok {
					wmStr = fmt.Sprintf("wm=%d/%d", wm, n.Watermark["generation"])
				}
				fmt.Printf("  %s %-10s %-20s %-12s %-20s epoch=%d gen=%d %s\n",
					stateIcon, n.Role, n.Addr, n.State, serving, n.Epoch, n.Gen, wmStr)
			} else {
				fmt.Printf("  %s %-10s %-20s %-12s %s\n",
					stateIcon, n.Role, n.Addr, n.State, serving)
			}
		}

		// Tokens
		if len(report.Tokens) > 0 {
			fmt.Println("")
			fmt.Println("  Tokens:")
			for _, scope := range sortedTokenScopes(report.Tokens) {
				tok := report.Tokens[scope]
				status := "✔ active"
				if tok.Expired {
					status = "✖ EXPIRED"
				}
				fmt.Printf("    %-16s → %-16s %s\n", scope, tok.Owner, status)
			}
		}

		fmt.Printf("\n  [refreshing every 2s — Ctrl-C to exit]\n")

		time.Sleep(2 * time.Second)
	}
}

// tailLogs continuously fetches and displays events from the cluster.
func tailLogs(target, entryAddr string) {
	type event struct {
		ID        int64  `json:"id"`
		Timestamp string `json:"ts"`
		Level     string `json:"level"`
		Prefix    string `json:"prefix"`
		Message   string `json:"message"`
		NodeID    string `json:"node_id"`
	}

	// Resolve target addresses.
	var addrs []string
	if target == "all" {
		// Discover from entry address.
		if cv, err := fetchCluster(entryAddr); err == nil {
			addrs = append(addrs, cv.SelfAddr)
			for _, p := range cv.Peers {
				addrs = append(addrs, p.Addr)
			}
		} else {
			addrs = []string{entryAddr}
		}
	} else {
		addrs = []string{target}
	}

	fmt.Printf("Tailing events from %d node(s): %s\n", len(addrs), strings.Join(addrs, ", "))
	fmt.Printf("[Ctrl-C to stop]\n\n")

	lastID := make(map[string]int64)
	lastIncarnation := make(map[string]uint64)

	// logFetchResult holds one node's new-events poll, fetched in its own
	// goroutine below.
	type logFetchResult struct {
		addr        string
		evts        []event
		incarnation uint64
		gotStatus   bool
	}

	for {
		results := make([]logFetchResult, len(addrs))
		var wg sync.WaitGroup
		for i, a := range addrs {
			since := lastID[a]
			wg.Add(1)
			go func(idx int, a string, since int64) {
				defer wg.Done()
				// incarnation, fetched fresh every tick: eventlog.Ring's own event IDs
				// reset to 1 on every process restart, but this tool's since_id cursor
				// never did.
				var st struct {
					Incarnation uint64 `json:"incarnation"`
				}
				gotStatus := false
				if _, err := doGetJSON(a, "/api/v1/status", &st); err == nil {
					gotStatus = true
				}

				var evts []event
				path := fmt.Sprintf("/api/v1/events?since_id=%d", since)
				if _, err := doGetJSON(a, path, &evts); err != nil {
					return
				}
				results[idx] = logFetchResult{addr: a, evts: evts, incarnation: st.Incarnation, gotStatus: gotStatus}
			}(i, a, since)
		}
		wg.Wait()

		for _, res := range results {
			if !res.gotStatus {
				continue
			}
			if prev, seen := lastIncarnation[res.addr]; seen && res.incarnation != prev {
				lastID[res.addr] = 0
			}
			lastIncarnation[res.addr] = res.incarnation
		}

		for _, res := range results {
			for _, e := range res.evts {
				ts := e.Timestamp
				if t, err := time.Parse(time.RFC3339Nano, e.Timestamp); err == nil {
					ts = t.Local().Format("15:04:05")
				}
				fmt.Printf("%s  %-14s  [%-12s]  %s\n", ts, e.Prefix, e.NodeID, e.Message)
				if e.ID > lastID[res.addr] {
					lastID[res.addr] = e.ID
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
}

func main() {
	rc, rcErr := clientrc.Load()
	if rcErr != nil {
		fmt.Fprintln(os.Stderr, rcErr)
		os.Exit(2)
	}
	addrDefault := "127.0.0.1:9443"
	if rc.Addr != "" {
		addrDefault = rc.Addr
	}

	addr := flag.String("addr", addrDefault, "address of any cluster node")
	verbose := flag.Int("v", 0, "verbosity: 0=summary, 1=nodes, 2=detailed")
	jsonOut := flag.Bool("json", false, "output JSON")
	watch := flag.Bool("watch", false, "live dashboard, refresh every 2s")
	logs := flag.String("logs", "", "tail event log (node address or 'all' for all nodes via --addr)")
	useTLS := flag.Bool("tls", rc.TLS, "use HTTPS (TLS)")
	tlsSkipVerify := flag.Bool("tls-skip-verify", rc.TLSSkipVerify, "skip TLS certificate verification")
	tokenFile := flag.String("token-file", "", "path to file containing API bearer token")
	showVersion := flag.Bool("version", false, "print version")

	// Support -v and -vv as flags without values.
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "-vv" {
			os.Args[i] = "-v=2"
		} else if os.Args[i] == "-v" && (i+1 >= len(os.Args) || strings.HasPrefix(os.Args[i+1], "-")) {
			os.Args[i] = "-v=1"
		}
	}

	flag.Parse()

	if *showVersion {
		fmt.Println("dnshived-status", version)
		os.Exit(0)
	}

	// Configure TLS and auth on the shared HTTP client.
	if *useTLS || *tlsSkipVerify {
		scheme = "https"
		if *tlsSkipVerify {
			if t, ok := client.Transport.(*http.Transport); ok {
				t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			} else {
				fmt.Fprintln(os.Stderr, "warning: -tls-skip-verify has no effect — client.Transport is not *http.Transport")
			}
		}
	}
	// Load API token from file or environment.
	if *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading token file: %v\n", err)
			os.Exit(2)
		}
		apiToken = strings.TrimSpace(string(data))
	} else if t := os.Getenv("DNSHIVED_TOKEN"); t != "" {
		apiToken = t
	} else if rc.Token != "" {
		apiToken = rc.Token
	}

	if *watch {
		watchLoop(*addr, *verbose)
		return // unreachable, watchLoop loops forever
	}

	if *logs != "" {
		tailLogs(*logs, *addr)
		return
	}

	report := buildReport(*addr)

	if *jsonOut {
		printJSON(report)
	} else if *verbose > 0 {
		printVerbose(report, *verbose)
	} else {
		printDefault(report)
	}

	os.Exit(report.ExitCode)
}
