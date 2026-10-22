// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// dnshived-helper — privileged helper for dnshived.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"dnshived/internal/nftgate"
	"dnshived/internal/rpfilter"
	"dnshived/internal/vrrpstate"
)

var version = "0.9.7-dev"

// keepalivedPIDFile is the consolidated keepalived unit's PID file —
// fixed path, not configurable, matching the systemd unit rendered for it.
const keepalivedPIDFile = "/run/dnshived/keepalived.pid"

// Request is a command from the daemon.
type Request struct {
	Command   string   `json:"command"`
	Scope     string   `json:"scope"`            // scope name (must be in allowlist) — empty for ensure-keepalived
	Parent    string   `json:"parent"`           // parent interface (e.g. "ens19")
	VLANID    int      `json:"vlan_id"`          // VLAN ID
	VIP       string   `json:"vip"`              // VIP address (CIDR)
	NodeIP    string   `json:"node_ip"`          // node IP address (CIDR)
	GateState string   `json:"gate_state"`       // "open" or "closed" — set-dhcp-gate only
	Scopes    []string `json:"scopes,omitempty"` // add-scopes only — names to grow the allowlist with
	Unit      string   `json:"unit,omitempty"`   // journal-tail only — must be in allowedJournalUnits
	Lines     int      `json:"lines,omitempty"`  // journal-tail only — how many recent lines
	Action    string   `json:"action,omitempty"` // manage-unit only
	Iface     string   `json:"iface,omitempty"`  // link-up, remove-gate-rule-unscoped
}

// Response is the result sent back to the daemon.
type Response struct {
	OK           bool            `json:"ok"`
	Error        string          `json:"error,omitempty"`
	GateState    string          `json:"gate_state,omitempty"`    // get-dhcp-gate only
	GateDump     map[string]bool `json:"gate_dump,omitempty"`     // dhcp-gate-dump only — iface -> true if closed, every gated iface
	VRRPState    string          `json:"vrrp_state,omitempty"`    // get-vrrp-state only
	VRRPDump     string          `json:"vrrp_dump,omitempty"`     // vrrp-dump only — raw SIGDATA text, every instance
	Throttled    bool            `json:"throttled,omitempty"`     // reload-keepalived/restart-dnsmasq only — rate-limited, NOT applied
	JournalLines []string        `json:"journal_lines,omitempty"` // journal-tail only
}

var (
	allowedScopes   map[string]bool
	allowedScopesMu sync.RWMutex
)

// scopedCommands are commands that take a scope and must be validated
// against the allowlist.
var scopedCommands = map[string]bool{
	"create-interface": true,
	"delete-interface": true,
	"stop-dnsmasq":     true,
	"restart-dnsmasq":  true,
	"set-dhcp-gate":    true,
	"get-dhcp-gate":    true,
	"get-vrrp-state":   true,
}

// allowedJournalUnits is journal-tail's own fixed allowlist.
var allowedJournalUnits = map[string]bool{
	"dnshived.service":                 true,
	"dnshived-web.service":             true,
	"dnshived-helper.service":          true,
	"dnshived-relay.service":           true,
	"dnshived-dnsrelay.service":        true,
	"dnshived-keepalived.service":      true,
	"dnshived-keepalived-mgmt.service": true,
}

// manageUnitAllowed is manage-unit's fixed action -> unit allowlist, used
// at adopt and self-decommission. disable-now also takes any
// dnshived-dnsmasq@ instance (dnsmasqUnitPattern).
var manageUnitAllowed = map[string]map[string]bool{
	"enable-now": {"dnshived-web.service": true},
	"enable":     {"dnshived-helper.service": true},
	"disable-now": {
		"dnshived-probe.service":           true,
		"dnshived-probe-helper.service":    true,
		"dnshived-relay.service":           true,
		"dnshived-dnsrelay.service":        true,
		"dnshived-keepalived.service":      true,
		"dnshived-keepalived-mgmt.service": true,
		"dnshived-web.service":             true,
		"dnshived-web-helper.service":      true,
	},
}

var dnsmasqUnitPattern = regexp.MustCompile(`^dnshived-dnsmasq@[a-zA-Z0-9_-]+\.service$`)

// parseScopeAllowlist turns the --scopes flag's comma-separated value into
// the lookup map scoped-command dispatch checks.
func parseScopeAllowlist(scopeList string) map[string]bool {
	allowed := make(map[string]bool)
	for _, s := range strings.Split(scopeList, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			allowed[s] = true
		}
	}
	return allowed
}

// stateDir holds this helper's own small persisted-fact directory
// (--state-dir) — currently just persistedScopesFile below.
var stateDir string

// flagScopes is the --scopes allowlist, kept so reset-scope-state can
// return to it.
var flagScopes string

// scopeNamePattern mirrors internal/config's own scopeNamePattern exactly
// (`^[a-zA-Z0-9_-]+$`).
var scopeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// loadPersistedScopes reads back whatever addScopes has persisted so far.
func loadPersistedScopes(dir string) map[string]bool {
	data, err := os.ReadFile(filepath.Join(dir, "allowed-scopes.json"))
	if err != nil {
		return nil
	}
	var names []string
	if err := json.Unmarshal(data, &names); err != nil {
		log.Printf("[HELPER:WARN] persisted allowed-scopes.json corrupt, ignoring: %v", err)
		return nil
	}
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out
}

// savePersistedScopes atomically overwrites the persisted allowlist.
func savePersistedScopes(dir string, names map[string]bool) error {
	list := make([]string, 0, len(names))
	for n := range names {
		list = append(list, n)
	}
	sort.Strings(list)
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal allowed scopes: %w", err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	path := filepath.Join(dir, "allowed-scopes.json")
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// addScopes grows the in-memory + persisted allowlist to include
// req.Scopes.
func addScopes(req Request) error {
	var bad []string
	for _, name := range req.Scopes {
		if !scopeNamePattern.MatchString(name) {
			bad = append(bad, name)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("invalid scope name(s), refusing all: %v", bad)
	}

	allowedScopesMu.Lock()
	var added []string
	for _, name := range req.Scopes {
		if !allowedScopes[name] {
			allowedScopes[name] = true
			added = append(added, name)
		}
	}
	snapshot := make(map[string]bool, len(allowedScopes))
	for name := range allowedScopes {
		snapshot[name] = true
	}
	allowedScopesMu.Unlock()

	if len(added) == 0 {
		return nil // every requested name was already allowed — harmless no-op
	}
	if err := savePersistedScopes(stateDir, snapshot); err != nil {
		log.Printf("[HELPER:WARN] persist allowed-scopes.json: %v", err)
	}
	log.Printf("[HELPER:ALLOWLIST] added %d scope(s): %v", len(added), added)
	return nil
}

func main() {
	socketPath := flag.String("socket", "/run/dnshived/helper.sock", "Unix socket path")
	scopeList := flag.String("scopes", "", "comma-separated list of allowed scope names")
	stateDirFlag := flag.String("state-dir", "/var/lib/dnshived-helper", "directory for this helper's own persisted state (currently: dynamically add-scopes'd names — see addScopes)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("dnshived-helper", version)
		os.Exit(0)
	}

	stateDir = *stateDirFlag
	flagScopes = *scopeList
	allowedScopes = parseScopeAllowlist(*scopeList)
	for name := range loadPersistedScopes(stateDir) {
		allowedScopes[name] = true
	}
	if len(allowedScopes) == 0 {
		log.Printf("[HELPER:INIT] no scopes in allowlist — every scope-parameterized command will be rejected until one is configured")
	} else {
		names := make([]string, 0, len(allowedScopes))
		for name := range allowedScopes {
			names = append(names, name)
		}
		sort.Strings(names)
		log.Printf("[HELPER:INIT] allowed scopes (--scopes flag + persisted add-scopes state): %v", names)
	}

	if err := nftgate.EnsureChain(); err != nil {
		log.Fatalf("[HELPER:INIT] nftables gate setup failed: %v", err)
	}
	log.Printf("[HELPER:INIT] nftables gate ready (table=%s chain=%s)", nftgate.Table, nftgate.Chain)

	if err := prepareSocket(*socketPath); err != nil {
		log.Fatalf("[HELPER:INIT] %v", err)
	}

	oldUmask := syscall.Umask(0o117)
	ln, err := net.Listen("unix", *socketPath)
	syscall.Umask(oldUmask)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	if err := os.Chmod(*socketPath, 0o660); err != nil {
		log.Fatalf("[HELPER:INIT] chmod socket %s: %v", *socketPath, err)
	}

	log.Printf("[HELPER:INIT] listening on %s", *socketPath)

	sem := make(chan struct{}, helperMaxConns)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed") {
					return
				}
				log.Printf("[HELPER:ERROR] accept: %v", err)
				continue
			}
			sem <- struct{}{}
			connWG.Add(1)
			go func() {
				defer connWG.Done()
				defer func() { <-sem }()
				handleConn(conn)
			}()
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("[HELPER] shutting down, draining in-flight requests")
	ln.Close()
	drained := make(chan struct{})
	go func() {
		connWG.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(helperDrainTimeout):
		log.Printf("[HELPER:WARN] %v drain timeout reached, exiting with requests still in flight", helperDrainTimeout)
	}
	os.Remove(*socketPath)
	log.Printf("[HELPER] shutdown complete")
	os.Exit(0)
}

// connWG tracks handleConn goroutines currently in flight — see the
// shutdown sequence in main() for why this must be waited on before the
// process exits.
var connWG sync.WaitGroup

var (
	helperConnDeadline   = 60 * time.Second
	helperDrainTimeout   = 45 * time.Second
	helperMaxConns       = 64
	helperMaxRequestSize = int64(64 << 10)
)

// prepareSocket removes only a stale socket, never another file at the path.
func prepareSocket(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("socket directory: %w", err)
	}
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat socket %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket, refusing to remove it", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	return nil
}

// peerCred is for the log only; the socket's group still gates access.
func peerCred(conn net.Conn) string {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return "unknown"
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return "unknown"
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credErr != nil {
		return "unknown"
	}
	return fmt.Sprintf("uid=%d pid=%d", cred.Uid, cred.Pid)
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(helperConnDeadline))
	caller := peerCred(conn)

	var req Request
	if err := json.NewDecoder(io.LimitReader(conn, helperMaxRequestSize)).Decode(&req); err != nil {
		log.Printf("[HELPER:DENY] %s: invalid request: %v", caller, err)
		respond(conn, Response{OK: false, Error: "invalid request: " + err.Error()})
		return
	}
	if req.Command == "restart-helper" || req.Command == "finish-decommission" {
		log.Printf("[HELPER:PEER] %s requested %s", caller, req.Command)
	}

	// Validate scope — only for commands that take one.
	if scopedCommands[req.Command] {
		allowedScopesMu.RLock()
		ok := allowedScopes[req.Scope]
		allowedScopesMu.RUnlock()
		if !ok {
			log.Printf("[HELPER:DENY] %s: scope %q not in allowlist", caller, req.Scope)
			respond(conn, Response{OK: false, Error: "scope not allowed: " + req.Scope})
			return
		}
	}

	if req.Command == "finish-decommission" {
		if err := spawnBootstrapRestart(); err != nil {
			log.Printf("[HELPER:ERROR] finish-decommission: %v", err)
			respond(conn, Response{OK: false, Error: err.Error()})
			return
		}
		log.Printf("[HELPER:OK] finish-decommission — restart into bootstrap scheduled, stopping helper")
		respond(conn, Response{OK: true})
		go func() {
			time.Sleep(300 * time.Millisecond)
			if err := stopHelperSelf(); err != nil {
				log.Printf("[HELPER:ERROR] finish-decommission stop helper: %v", err)
			}
		}()
		return
	}

	if req.Command == "restart-helper" {
		throttled := helperSelfRestartThrottled()
		log.Printf("[HELPER:OK] restart-helper throttled=%v", throttled)
		respond(conn, Response{OK: true, Throttled: throttled})
		if !throttled {
			go triggerHelperSelfRestart()
		}
		return
	}

	var (
		err          error
		gate         string
		gateDump     map[string]bool
		vrrp         string
		vrrpDump     string
		throttled    bool
		journalLines []string
	)
	switch req.Command {
	case "create-interface":
		err = createInterface(req)
	case "delete-interface":
		err = deleteInterface(req)
	case "delete-interface-unscoped":
		err = deleteInterface(req)
	case "stop-dnsmasq":
		err = stopDnsmasq(req)
	case "stop-dnsmasq-unscoped":
		err = stopDnsmasq(req)
	case "restart-dnsmasq":
		throttled, err = restartDnsmasq(req)
	case "ensure-keepalived":
		err = ensureKeepalived()
	case "reload-keepalived":
		throttled, err = reloadKeepalived()
	case "restart-relay":
		throttled, err = restartRelay()
	case "reload-relay":
		throttled, err = reloadRelay()
	case "stop-relay":
		err = stopRelay()
	case "restart-dnsrelay":
		throttled, err = restartDNSRelay()
	case "reload-dnsrelay":
		throttled, err = reloadDNSRelay()
	case "stop-dnsrelay":
		err = stopDNSRelay()
	case "restart-core-dns":
		throttled, err = restartCoreDNS()
	case "restart-core-dhcp":
		throttled, err = restartCoreDHCP()
	case "reload-core-dhcp":
		throttled, err = reloadCoreDHCP()
	case "reload-core-dns":
		throttled, err = reloadCoreDNS()
	case "set-dhcp-gate":
		err = setDHCPGate(req)
	case "get-dhcp-gate":
		gate, err = getDHCPGate(req)
	case "dhcp-gate-dump":
		gateDump, err = getDHCPGateDump()
	case "get-vrrp-state":
		vrrp, err = getVRRPState(req)
	case "vrrp-dump":
		vrrpDump, err = getVRRPDump()
	case "get-mgmt-vrrp-state":
		vrrp, err = getMgmtVRRPState()
	case "stop-mgmt-keepalived":
		err = stopMgmtKeepalived()
	case "restart-daemon":
		throttled, err = restartDaemon()
	case "restart-mgmt-keepalived":
		throttled, err = restartMgmtKeepalived()
	case "ensure-mgmt-keepalived":
		err = ensureMgmtKeepalived()
	case "reload-mgmt-keepalived":
		err = reloadMgmtKeepalived()
	case "restart-web":
		throttled, err = restartWeb()
	case "add-scopes":
		err = addScopes(req)
	case "journal-tail":
		journalLines, err = getJournalTail(req)
	case "link-up":
		err = linkUp(req)
	case "remove-gate-rule-unscoped":
		err = removeGateRuleUnscoped(req)
	case "manage-unit":
		err = manageUnit(req)
	case "reset-scope-state":
		err = resetScopeState()
	default:
		log.Printf("[HELPER:DENY] %s: unknown command %q", caller, req.Command)
		respond(conn, Response{OK: false, Error: "unknown command: " + req.Command})
		return
	}

	if err != nil {
		log.Printf("[HELPER:ERROR] %s %s: %v", req.Command, requestTarget(req), err)
		respond(conn, Response{OK: false, Error: err.Error()})
		return
	}

	log.Printf("[HELPER:OK] %s %s", req.Command, requestTarget(req))
	respond(conn, Response{
		OK:           true,
		GateState:    gate,
		GateDump:     gateDump,
		VRRPState:    vrrp,
		VRRPDump:     vrrpDump,
		Throttled:    throttled,
		JournalLines: journalLines,
	})
}

func respond(conn net.Conn, resp Response) {
	json.NewEncoder(conn).Encode(resp)
}

func requestTarget(req Request) string {
	switch {
	case req.Unit != "":
		return strings.TrimSpace(req.Action + " " + req.Unit)
	case req.Iface != "":
		return req.Iface
	}
	return req.Scope
}

// --- Privileged operations: commands that let dnshived run unprivileged ---

// linkUp only ever brings an existing interface up, never down.
func linkUp(req Request) error {
	if err := nftgate.CheckIfaceName(req.Iface); err != nil {
		return err
	}
	if _, err := os.Stat("/sys/class/net/" + req.Iface); err != nil {
		return fmt.Errorf("interface %s does not exist", req.Iface)
	}
	if err := run("ip", "link", "set", req.Iface, "up"); err != nil {
		return err
	}
	// An address-less trunk receives peer broadcasts with a source routed via
	// mgmt; rp_filter 1 or 2 drops them there.
	iface, err := net.InterfaceByName(req.Iface)
	if err != nil {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil || hasIPv4(addrs) {
		return nil
	}
	if err := rpfilter.DisableOnTrunk(req.Iface); err != nil {
		log.Printf("[HELPER:WARN] %v", err)
	}
	return nil
}

func hasIPv4(addrs []net.Addr) bool {
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			return true
		}
	}
	return false
}

func removeGateRuleUnscoped(req Request) error {
	if err := nftgate.CheckIfaceName(req.Iface); err != nil {
		return err
	}
	return nftgate.RemoveRule(req.Iface)
}

func manageUnit(req Request) error {
	allowed := manageUnitAllowed[req.Action]
	if allowed == nil {
		return fmt.Errorf("unknown manage-unit action %q", req.Action)
	}
	if !allowed[req.Unit] && !(req.Action == "disable-now" && dnsmasqUnitPattern.MatchString(req.Unit)) {
		return fmt.Errorf("unit not allowed for %s: %s", req.Action, req.Unit)
	}
	switch req.Action {
	case "enable-now":
		return run("systemctl", "enable", "--now", req.Unit)
	case "enable":
		return run("systemctl", "enable", req.Unit)
	default:
		return run("systemctl", "disable", "--now", req.Unit)
	}
}

// resetScopeState drops every add-scopes name, in memory and on disk,
// back to the --scopes flag list.
func resetScopeState() error {
	allowedScopesMu.Lock()
	allowedScopes = parseScopeAllowlist(flagScopes)
	allowedScopesMu.Unlock()
	if err := os.RemoveAll(stateDir); err != nil {
		return fmt.Errorf("remove %s: %w", stateDir, err)
	}
	log.Printf("[HELPER:ALLOWLIST] reset to the --scopes list, %s removed", stateDir)
	return nil
}

var stopHelperSelf = func() error {
	return run("systemctl", "disable", "--now", "dnshived-helper.service")
}

var spawnBootstrapRestart = func() error {
	return run("systemd-run",
		"--unit=dnshived-decommission-restart",
		"--description=restart dnshived.service into bootstrap mode after self-decommission",
		"/bin/sh", "-c", "sleep 3; systemctl start dnshived.service")
}

// --- Privileged operations: interfaces ---

// reconcileInterfaceAddrs ensures iface's only IPv4 addresses are nodeIP
// and vip (both CIDR strings, either may be empty).
func reconcileInterfaceAddrs(iface, nodeIP, vip string, untagged bool) {
	parseIP := func(cidr string) net.IP {
		if cidr == "" {
			return nil
		}
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil
		}
		return ip
	}
	wantNode, wantVIP := parseIP(nodeIP), parseIP(vip)

	if !untagged {
		if link, err := net.InterfaceByName(iface); err == nil {
			if addrs, err := link.Addrs(); err == nil {
				for _, a := range addrs {
					ipNet, ok := a.(*net.IPNet)
					if !ok || ipNet.IP.To4() == nil {
						continue // IPv6/not-IPv4 — not this project's concern here
					}
					if (wantNode != nil && ipNet.IP.Equal(wantNode)) || (wantVIP != nil && ipNet.IP.Equal(wantVIP)) {
						continue // wanted — keep
					}
					log.Printf("[HELPER:RECONCILE] %s: removing stale address %s (neither node_ip nor vip)", iface, ipNet.String())
					run("ip", "addr", "del", ipNet.String(), "dev", iface)
				}
			}
		}
	}

	if nodeIP != "" {
		run("ip", "addr", "add", nodeIP, "dev", iface)
	}
}

func createInterface(req Request) error {
	iface := nftgate.InterfaceName(req.Parent, req.VLANID)
	untagged := req.VLANID == 0

	if !untagged {
		run("ip", "link", "set", req.Parent, "up")
		if err := rpfilter.DisableOnTrunk(req.Parent); err != nil {
			log.Printf("[HELPER:WARN] %v", err)
		}
	}

	// If interface exists, try to bring it up.
	if _, err := os.Stat("/sys/class/net/" + iface); err == nil {
		if err := nftgate.EnsureClosed(iface); err != nil {
			log.Printf("[HELPER:WARN] ensure gate closed for existing interface %s: %v (continuing)", iface, err)
		}
		if err := run("ip", "link", "set", iface, "up"); err != nil {
			if untagged {
				return fmt.Errorf("bring up untagged parent interface %s: %w (never deleting real hardware to retry)", iface, err)
			}
			log.Printf("[HELPER:WARN] stale interface %s — deleting and recreating", iface)
			run("ip", "link", "delete", iface)
		} else {
			reconcileInterfaceAddrs(iface, req.NodeIP, req.VIP, untagged)
			return nftgate.EnsureClosed(iface)
		}
	}

	if untagged {
		return fmt.Errorf("parent interface %s (untagged scope) does not exist on this host — check cabling/driver/bridge assignment before retrying", req.Parent)
	}

	if stale := vlanOnParent(req.Parent, req.VLANID); stale != "" && stale != iface {
		log.Printf("[HELPER:RENAME] %s carries VLAN %d on %s under the old name %s — removing it to recreate as %s", req.Parent, req.VLANID, req.Parent, stale, iface)
		if err := nftgate.RemoveRule(stale); err != nil {
			log.Printf("[HELPER:WARN] remove gate rule for %s: %v", stale, err)
		}
		if err := run("ip", "link", "delete", stale); err != nil {
			return fmt.Errorf("remove stale %s: %w", stale, err)
		}
	}

	// Create fresh — admin-down until "ip link set up" below.
	if err := run("ip", "link", "add", "link", req.Parent, "name", iface, "type", "vlan", "id", fmt.Sprintf("%d", req.VLANID)); err != nil {
		return fmt.Errorf("create vlan: %w", err)
	}
	if err := nftgate.EnsureClosed(iface); err != nil {
		return fmt.Errorf("ensure gate closed before interface up: %w", err)
	}
	if err := run("ip", "link", "set", iface, "up"); err != nil {
		return fmt.Errorf("link up: %w", err)
	}

	// Only assign node IP — VIP is managed by keepalived.
	if req.NodeIP != "" {
		run("ip", "addr", "add", req.NodeIP, "dev", iface)
	}

	// Closed by default — never a window where the interface exists but
	// no gate rule has been created yet.
	return nftgate.EnsureClosed(iface)
}

var vlanConfigPath = "/proc/net/vlan/config"

// vlanOnParent returns the name of an existing VLAN device with id on
// parent (a kernel only allows one), or "".
func vlanOnParent(parent string, id int) string {
	data, err := os.ReadFile(vlanConfigPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, "|")
		if len(f) != 3 {
			continue
		}
		name, vid, par := strings.TrimSpace(f[0]), strings.TrimSpace(f[1]), strings.TrimSpace(f[2])
		if par == parent && vid == strconv.Itoa(id) {
			return name
		}
	}
	return ""
}

func deleteInterface(req Request) error {
	iface := nftgate.InterfaceName(req.Parent, req.VLANID)

	if err := nftgate.RemoveRule(iface); err != nil {
		log.Printf("[HELPER:WARN] remove gate rule for %s: %v (continuing with interface deletion)", iface, err)
	}

	if req.VLANID == 0 {
		if req.NodeIP != "" {
			run("ip", "addr", "del", req.NodeIP, "dev", iface)
		}
		return nil
	}

	if _, err := os.Stat("/sys/class/net/" + iface); err != nil {
		return nil // already gone
	}
	return run("ip", "link", "delete", iface)
}

// --- Privileged operations: dnsmasq (per-scope) ---

// stopDnsmasq is for genuine scope removal, not the routine authority-loss
// path.
func stopDnsmasq(req Request) error {
	unit := "dnshived-dnsmasq@" + req.Scope
	run("systemctl", "stop", unit) // best-effort
	run("systemctl", "reset-failed", unit)
	return nil
}

// restartMu/lastRestartAt rate-limit restartDnsmasq to at most once per 5s
// PER SCOPE.
var (
	restartMu     sync.Mutex
	lastRestartAt = make(map[string]time.Time)
)

// restartDnsmasq restarts a scope's dnsmasq unit so it picks up config
// content the daemon already wrote to disk directly.
func restartDnsmasq(req Request) (throttled bool, err error) {
	return restartDnsmasqNamed(req.Scope)
}

func restartDnsmasqNamed(name string) (throttled bool, err error) {
	restartMu.Lock()
	defer restartMu.Unlock()
	if time.Since(lastRestartAt[name]) < 5*time.Second {
		log.Printf("[HELPER:RATE_LIMIT] restart-dnsmasq %s suppressed (< 5s since last restart)", name)
		return true, nil
	}
	unit := "dnshived-dnsmasq@" + name
	if err := run("systemctl", "restart", unit); err != nil {
		return false, fmt.Errorf("restart %s: %w", unit, err)
	}
	lastRestartAt[name] = time.Now()
	return false, nil
}

// restartCoreDNS/restartCoreDHCP restart the two consolidated,
// reserved-instance-name dnsmasq units.
func restartCoreDNS() (throttled bool, err error) {
	return restartDnsmasqNamed("core-dns")
}

func restartCoreDHCP() (throttled bool, err error) {
	return restartDnsmasqNamed("core-dhcp")
}

// coreDHCPReloadMu/lastCoreDHCPReloadAt rate-limit reloadCoreDHCP to at
// most once per second.
var (
	coreDHCPReloadMu     sync.Mutex
	lastCoreDHCPReloadAt time.Time
)

func reloadCoreDHCP() (throttled bool, err error) {
	coreDHCPReloadMu.Lock()
	defer coreDHCPReloadMu.Unlock()
	if time.Since(lastCoreDHCPReloadAt) < time.Second {
		log.Printf("[HELPER:RATE_LIMIT] reload-core-dhcp suppressed (< 1s since last reload)")
		return true, nil
	}
	if err := run("systemctl", "reload", "dnshived-dnsmasq@core-dhcp.service"); err != nil {
		return false, fmt.Errorf("reload dnshived-dnsmasq@core-dhcp.service: %w", err)
	}
	lastCoreDHCPReloadAt = time.Now()
	return false, nil
}

// coreDNSReloadMu/lastCoreDNSReloadAt rate-limit reloadCoreDNS to at most
// once per second.
var (
	coreDNSReloadMu     sync.Mutex
	lastCoreDNSReloadAt time.Time
)

func reloadCoreDNS() (throttled bool, err error) {
	coreDNSReloadMu.Lock()
	defer coreDNSReloadMu.Unlock()
	if time.Since(lastCoreDNSReloadAt) < time.Second {
		log.Printf("[HELPER:RATE_LIMIT] reload-core-dns suppressed (< 1s since last reload)")
		return true, nil
	}
	if err := run("systemctl", "reload", "dnshived-dnsmasq@core-dns.service"); err != nil {
		return false, fmt.Errorf("reload dnshived-dnsmasq@core-dns.service: %w", err)
	}
	lastCoreDNSReloadAt = time.Now()
	return false, nil
}

// restartMu2/lastDaemonRestartAt rate-limit restartDaemon to at most once
// per 10s.
var (
	daemonRestartMu     sync.Mutex
	lastDaemonRestartAt time.Time
)

// restartDaemon restarts dnshived.service itself, on an operator's
// explicit request.
func restartDaemon() (throttled bool, err error) {
	daemonRestartMu.Lock()
	defer daemonRestartMu.Unlock()
	if time.Since(lastDaemonRestartAt) < 10*time.Second {
		log.Printf("[HELPER:RATE_LIMIT] restart-daemon suppressed (< 10s since last restart)")
		return true, nil
	}
	if err := run("systemctl", "restart", "dnshived.service"); err != nil {
		return false, fmt.Errorf("restart dnshived.service: %w", err)
	}
	lastDaemonRestartAt = time.Now()
	return false, nil
}

// helperRestartMu/lastHelperRestartAt rate-limit the helper's own
// self-restart, same 10s tier as restart-daemon.
var (
	helperRestartMu     sync.Mutex
	lastHelperRestartAt time.Time
)

// helperSelfRestartThrottled checks (and, if allowed, records) the
// self-restart rate limit.
func helperSelfRestartThrottled() bool {
	helperRestartMu.Lock()
	defer helperRestartMu.Unlock()
	if time.Since(lastHelperRestartAt) < 10*time.Second {
		log.Printf("[HELPER:RATE_LIMIT] restart-helper suppressed (< 10s since last restart)")
		return true
	}
	lastHelperRestartAt = time.Now()
	return false
}

func triggerHelperSelfRestart() {
	time.Sleep(300 * time.Millisecond)
	if err := run("systemctl", "restart", "dnshived-helper.service"); err != nil {
		log.Printf("[HELPER:ERROR] restart-helper: %v", err)
	}
}

var (
	mgmtRestartMu     sync.Mutex
	lastMgmtRestartAt time.Time
)

// restartMgmtKeepalived restarts the management-VIP keepalived unit.
func restartMgmtKeepalived() (throttled bool, err error) {
	mgmtRestartMu.Lock()
	defer mgmtRestartMu.Unlock()
	if time.Since(lastMgmtRestartAt) < 5*time.Second {
		log.Printf("[HELPER:RATE_LIMIT] restart-mgmt-keepalived suppressed (< 5s since last restart)")
		return true, nil
	}
	unit := "dnshived-keepalived-mgmt.service"
	if err := run("systemctl", "enable", unit); err != nil {
		return false, fmt.Errorf("enable %s: %w", unit, err)
	}
	if err := run("systemctl", "restart", unit); err != nil {
		return false, fmt.Errorf("restart %s: %w", unit, err)
	}
	lastMgmtRestartAt = time.Now()
	return false, nil
}

// ensureMgmtKeepalived enables and starts the management-VIP keepalived
// unit without restarting a running one.
func ensureMgmtKeepalived() error {
	unit := "dnshived-keepalived-mgmt.service"
	if err := run("systemctl", "enable", unit); err != nil {
		return fmt.Errorf("enable %s: %w", unit, err)
	}
	if err := run("systemctl", "start", unit); err != nil {
		return fmt.Errorf("start %s: %w", unit, err)
	}
	return nil
}

// reloadMgmtKeepalived applies a changed keepalived-mgmt.conf without a
// full restart (which dropped the mgmt VIP on every core at once).
func reloadMgmtKeepalived() error {
	unit := "dnshived-keepalived-mgmt.service"
	if run("systemctl", "is-active", "--quiet", unit) != nil {
		return ensureMgmtKeepalived()
	}
	if err := run("systemctl", "reload", unit); err != nil {
		log.Printf("[HELPER:WARN] reload %s failed (%v) — restarting instead", unit, err)
		if err := run("systemctl", "restart", unit); err != nil {
			return fmt.Errorf("restart %s: %w", unit, err)
		}
	}
	return nil
}

// webRestartMu/lastWebRestartAt rate-limit restartWeb, same 5s tier as
// restartMgmtKeepalived.
var (
	webRestartMu     sync.Mutex
	lastWebRestartAt time.Time
)

func restartWeb() (throttled bool, err error) {
	webRestartMu.Lock()
	defer webRestartMu.Unlock()
	if time.Since(lastWebRestartAt) < 5*time.Second {
		log.Printf("[HELPER:RATE_LIMIT] restart-web suppressed (< 5s since last restart)")
		return true, nil
	}
	unit := "dnshived-web.service"
	if err := run("systemctl", "restart", unit); err != nil {
		return false, fmt.Errorf("restart %s: %w", unit, err)
	}
	lastWebRestartAt = time.Now()
	return false, nil
}

// stopMgmtKeepalived is for genuine mgmt_vip removal from config, not a
// routine path.
func stopMgmtKeepalived() error {
	unit := "dnshived-keepalived-mgmt.service"
	run("systemctl", "stop", unit) // best-effort
	run("systemctl", "disable", unit)
	run("systemctl", "reset-failed", unit)
	return nil
}

// --- Privileged operations: keepalived (consolidated, per node) ---

// ensureKeepalived idempotently starts the single consolidated keepalived
// unit covering every scope's vrrp_instance.
func ensureKeepalived() error {
	if err := run("systemctl", "start", "dnshived-keepalived.service"); err != nil {
		return fmt.Errorf("start dnshived-keepalived.service: %w", err)
	}
	return nil
}

// dnsRelayRestartMu/lastDNSRelayRestartAt rate-limit restartDNSRelay to at
// most once per 5s — same tier and reasoning as relayRestartMu.
var (
	dnsRelayRestartMu     sync.Mutex
	lastDNSRelayRestartAt time.Time
)

// restartDNSRelay restarts the single consolidated dnshived-dnsrelay unit
// after the daemon has re-rendered dnsrelay.json directly.
func restartDNSRelay() (throttled bool, err error) {
	dnsRelayRestartMu.Lock()
	defer dnsRelayRestartMu.Unlock()
	if time.Since(lastDNSRelayRestartAt) < 5*time.Second {
		log.Printf("[HELPER:RATE_LIMIT] restart-dnsrelay suppressed (< 5s since last restart)")
		return true, nil
	}
	if err := run("systemctl", "enable", "dnshived-dnsrelay.service"); err != nil {
		return false, fmt.Errorf("enable dnshived-dnsrelay.service: %w", err)
	}
	if err := run("systemctl", "restart", "dnshived-dnsrelay.service"); err != nil {
		return false, fmt.Errorf("restart dnshived-dnsrelay.service: %w", err)
	}
	lastDNSRelayRestartAt = time.Now()
	return false, nil
}

// dnsRelayReloadMu/lastDNSRelayReloadAt rate-limit reloadDNSRelay to at
// most once per second — same tier and reasoning as relayReloadMu.
var (
	dnsRelayReloadMu     sync.Mutex
	lastDNSRelayReloadAt time.Time
)

// reloadDNSRelay SIGHUPs the single consolidated dnshived-dnsrelay unit
// after the daemon has re-rendered dnsrelay.json directly.
func reloadDNSRelay() (throttled bool, err error) {
	dnsRelayReloadMu.Lock()
	defer dnsRelayReloadMu.Unlock()
	if time.Since(lastDNSRelayReloadAt) < time.Second {
		log.Printf("[HELPER:RATE_LIMIT] reload-dnsrelay suppressed (< 1s since last reload)")
		return true, nil
	}
	if unitRunsReplacedBinary("dnshived-dnsrelay.service") {
		log.Printf("[HELPER:RELAY] dnshived-dnsrelay runs a replaced binary — restarting instead of reloading")
		throttled, err := restartDNSRelay()
		if err == nil && !throttled {
			lastDNSRelayReloadAt = time.Now()
		}
		return throttled, err
	}
	if err := run("systemctl", "reload", "dnshived-dnsrelay.service"); err != nil {
		return false, fmt.Errorf("reload dnshived-dnsrelay.service: %w", err)
	}
	lastDNSRelayReloadAt = time.Now()
	return false, nil
}

// reloadMu/lastReloadAt rate-limit reloadKeepalived to at most once per
// second.
var (
	reloadMu     sync.Mutex
	lastReloadAt time.Time
)

func reloadKeepalived() (throttled bool, err error) {
	reloadMu.Lock()
	defer reloadMu.Unlock()
	if time.Since(lastReloadAt) < time.Second {
		log.Printf("[HELPER:RATE_LIMIT] reload-keepalived suppressed (< 1s since last reload)")
		return true, nil
	}
	if err := run("systemctl", "reload", "dnshived-keepalived.service"); err != nil {
		return false, fmt.Errorf("reload dnshived-keepalived.service: %w", err)
	}
	lastReloadAt = time.Now()
	return false, nil
}

// relayRestartMu/lastRelayRestartAt rate-limit restartRelay to at most
// once per 5s.
var (
	relayRestartMu     sync.Mutex
	lastRelayRestartAt time.Time
)

// restartRelay restarts the single consolidated dnshived-relay unit after
// the daemon has re-rendered relay.json directly.
func restartRelay() (throttled bool, err error) {
	relayRestartMu.Lock()
	defer relayRestartMu.Unlock()
	if time.Since(lastRelayRestartAt) < 5*time.Second {
		log.Printf("[HELPER:RATE_LIMIT] restart-relay suppressed (< 5s since last restart)")
		return true, nil
	}
	if err := run("systemctl", "enable", "dnshived-relay.service"); err != nil {
		return false, fmt.Errorf("enable dnshived-relay.service: %w", err)
	}
	if err := run("systemctl", "restart", "dnshived-relay.service"); err != nil {
		return false, fmt.Errorf("restart dnshived-relay.service: %w", err)
	}
	lastRelayRestartAt = time.Now()
	return false, nil
}

// stopRelay/stopDNSRelay stop the node-wide relay units and clear their
// failed state.
func stopRelay() error {
	run("systemctl", "stop", "dnshived-relay.service")
	run("systemctl", "reset-failed", "dnshived-relay.service")
	return nil
}

func stopDNSRelay() error {
	run("systemctl", "stop", "dnshived-dnsrelay.service")
	run("systemctl", "reset-failed", "dnshived-dnsrelay.service")
	return nil
}

// unitRunsReplacedBinary reports whether unit's main process still runs
// a binary that has since been replaced or removed on disk (an upgrade
// that only reloaded it), so a reload would keep the old code running.
func unitRunsReplacedBinary(unit string) bool {
	out, err := exec.Command("systemctl", "show", "-p", "MainPID", "--value", unit).Output()
	if err != nil {
		return false
	}
	pid := strings.TrimSpace(string(out))
	if pid == "" || pid == "0" {
		return false
	}
	target, err := os.Readlink("/proc/" + pid + "/exe")
	if err != nil {
		return false
	}
	return exeReplaced(target)
}

func exeReplaced(readlinkTarget string) bool {
	return strings.HasSuffix(readlinkTarget, " (deleted)")
}

// relayReloadMu/lastRelayReloadAt rate-limit reloadRelay to at most once
// per second.
var (
	relayReloadMu     sync.Mutex
	lastRelayReloadAt time.Time
)

// reloadRelay SIGHUPs the single consolidated dnshived-relay unit after
// the daemon has re-rendered relay.json directly.
func reloadRelay() (throttled bool, err error) {
	relayReloadMu.Lock()
	defer relayReloadMu.Unlock()
	if time.Since(lastRelayReloadAt) < time.Second {
		log.Printf("[HELPER:RATE_LIMIT] reload-relay suppressed (< 1s since last reload)")
		return true, nil
	}
	if unitRunsReplacedBinary("dnshived-relay.service") {
		log.Printf("[HELPER:RELAY] dnshived-relay runs a replaced binary — restarting instead of reloading")
		throttled, err := restartRelay()
		if err == nil && !throttled {
			lastRelayReloadAt = time.Now()
		}
		return throttled, err
	}
	if err := run("systemctl", "reload", "dnshived-relay.service"); err != nil {
		return false, fmt.Errorf("reload dnshived-relay.service: %w", err)
	}
	lastRelayReloadAt = time.Now()
	return false, nil
}

// --- Privileged operations: DHCP gate (nftables) ---

// setDHCPGate opens or closes the DHCP gate for a scope.
func setDHCPGate(req Request) error {
	iface := nftgate.InterfaceName(req.Parent, req.VLANID)
	switch req.GateState {
	case "closed":
		return nftgate.Close(iface)
	case "open":
		return nftgate.Open(iface)
	default:
		return fmt.Errorf("invalid gate_state %q (want open or closed)", req.GateState)
	}
}

// getDHCPGate reads back the current gate state for a scope.
func getDHCPGate(req Request) (string, error) {
	iface := nftgate.InterfaceName(req.Parent, req.VLANID)
	closed, err := nftgate.IsClosed(iface)
	if err != nil {
		return "", err
	}
	if closed {
		return "closed", nil
	}
	return "open", nil
}

// getDHCPGateDump reads back every gated interface's closed/open state in
// one nft round trip.
func getDHCPGateDump() (map[string]bool, error) {
	return nftgate.Dump()
}

// --- Privileged operations: VRRP state (keepalived SIGDATA dump) ---

// getVRRPState reads back a scope's current VRRP state (MASTER/BACKUP/
// FAULT/etc.) from the consolidated keepalived process.
func getVRRPState(req Request) (string, error) {
	return vrrpstate.InstanceState(keepalivedPIDFile, "DNSHIVED_"+req.Scope)
}

// mgmtKeepalivedPIDFile is the SEPARATE management-VIP keepalived
// instance's own PID file.
const mgmtKeepalivedPIDFile = "/run/dnshived/keepalived-mgmt.pid"

// getMgmtVRRPState reads back the management VIP's own current VRRP state
// (MASTER/BACKUP/FAULT/etc.).
func getMgmtVRRPState() (string, error) {
	return vrrpstate.InstanceState(mgmtKeepalivedPIDFile, "DNSHIVED_MGMT")
}

// getVRRPDump returns the consolidated keepalived process's raw SIGDATA
// dump (every vrrp_instance's state in one text blob), not scoped to a
// single instance.
func getVRRPDump() (string, error) {
	data, err := vrrpstate.Dump(keepalivedPIDFile)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// --- Privileged operations: journal tail ---

// getJournalTail returns the last req.Lines lines of req.Unit's own
// systemd journal.
func getJournalTail(req Request) ([]string, error) {
	if !allowedJournalUnits[req.Unit] {
		return nil, fmt.Errorf("unit not allowed: %s", req.Unit)
	}
	n := req.Lines
	if n <= 0 {
		n = 100
	}
	out, err := exec.Command("journalctl", "-u", req.Unit, "-n", strconv.Itoa(n), "--no-pager", "-o", "short-iso").Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("journalctl -u %s: %s", req.Unit, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("journalctl -u %s: %w", req.Unit, err)
	}
	trimmed := strings.TrimRight(string(out), "\n")
	if trimmed == "" {
		return nil, nil
	}
	return strings.Split(trimmed, "\n"), nil
}

// --- helpers ---

// selinuxDataDir is the one directory every dnsmasq/keepalived/relay
// config, lease, and log file this project renders actually lives under.
const selinuxDataDir = "/var/lib/dnshived"

// restoreconPath is resolved once, lazily, on the first (re)start/reload
// this process ever handles.
var (
	restoreconMu       sync.Mutex
	restoreconResolved bool
	restoreconPath     string
)

func relabelSELinuxDataDir() {
	restoreconMu.Lock()
	if !restoreconResolved {
		if p, err := exec.LookPath("restorecon"); err == nil {
			restoreconPath = p
		}
		restoreconResolved = true
	}
	path := restoreconPath
	restoreconMu.Unlock()
	if path == "" {
		return
	}
	cmd := exec.Command(path, "-R", selinuxDataDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[HELPER:SELINUX] restorecon -R %s: %v (%s)", selinuxDataDir, err, strings.TrimSpace(string(out)))
	}
}

func run(name string, args ...string) error {
	if name == "systemctl" && len(args) > 0 {
		switch args[0] {
		case "start", "restart", "reload":
			relabelSELinuxDataDir()
		}
	}
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %s (%w)", name, args, strings.TrimSpace(string(out)), err)
	}
	return nil
}
