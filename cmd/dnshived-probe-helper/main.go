// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// dnshived-probe-helper is a minimal privileged helper for
// cmd/dnshived-probe, mirroring dnshived-helper's Unix-socket model at a
// much smaller scale.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"dnshived/internal/cliguard"
	"dnshived/internal/instlock"
	"dnshived/internal/ownership"
	"dnshived/internal/unixsock"
)

var version = "0.9.7-dev"

// probeConfigPath is the ONE path write-config will ever write to.
var probeConfigPath = "/etc/dnshived/probe.json"

// probeStateDir is /var/lib/dnshived-probe.
var probeStateDir = "/var/lib/dnshived-probe"

// vlanIfaceRE matches "<parent>.<vlan_id>" VLAN sub-interface names.
var vlanIfaceRE = regexp.MustCompile(`^([a-zA-Z0-9._-]+)\.(\d{1,4})$`)

// Request matches internal/probehelper.Client's wire shape.
type Request struct {
	Command string `json:"command"`
	Content []byte `json:"content,omitempty"`
	Parent  string `json:"parent,omitempty"`
	VLANID  int    `json:"vlan_id,omitempty"`
	Addr    string `json:"addr,omitempty"` // CIDR — create-interface always, delete-interface only for vlan_id 0
	Unit    string `json:"unit,omitempty"` // journal-tail only — must be in allowedJournalUnits
	Lines   int    `json:"lines,omitempty"`
}

// Response matches internal/probehelper.Client's wire shape.
type Response struct {
	OK           bool     `json:"ok"`
	Error        string   `json:"error,omitempty"`
	Throttled    bool     `json:"throttled,omitempty"`
	JournalLines []string `json:"journal_lines,omitempty"`
}

var connWG sync.WaitGroup

// allowedTrunkParents gates create-interface/delete-interface's Parent
// field.
var (
	allowedTrunkParentsMu sync.RWMutex
	allowedTrunkParents   map[string]bool
	flagTrunkParents      map[string]bool
)

// isTrunkParentAllowed is the thread-safe read side of
// allowedTrunkParents.
func isTrunkParentAllowed(name string) bool {
	allowedTrunkParentsMu.RLock()
	defer allowedTrunkParentsMu.RUnlock()
	return allowedTrunkParents[name]
}

// refreshAllowedTrunkParents unions flagTrunkParents with fromFile and
// replaces allowedTrunkParents under the lock.
func refreshAllowedTrunkParents(fromFile map[string]bool) []string {
	merged := make(map[string]bool, len(flagTrunkParents)+len(fromFile))
	for k := range flagTrunkParents {
		merged[k] = true
	}
	for k := range fromFile {
		merged[k] = true
	}
	names := make([]string, 0, len(merged))
	for k := range merged {
		names = append(names, k)
	}
	allowedTrunkParentsMu.Lock()
	allowedTrunkParents = merged
	allowedTrunkParentsMu.Unlock()
	return names
}

// probeConfigTrunkParents is the one field this binary needs out of
// probe.json.
type probeConfigTrunkParents struct {
	TrunkParents []string `json:"trunk_parents"`
}

// trunkParentsFromContent parses trunk_parents out of raw probe.json
// bytes.
func trunkParentsFromContent(content []byte) map[string]bool {
	var pc probeConfigTrunkParents
	if err := json.Unmarshal(content, &pc); err != nil {
		return nil
	}
	if len(pc.TrunkParents) == 0 {
		return nil
	}
	mgmt := defaultRouteDevice()
	set := make(map[string]bool, len(pc.TrunkParents))
	for _, p := range pc.TrunkParents {
		p = strings.TrimSpace(p)
		switch {
		case p == "":
		case strings.Contains(p, "."):
			log.Printf("[PROBE-HELPER:DENY] trunk parent %q is a VLAN name, not a trunk — not added to the allowlist", p)
		case p == mgmt:
			log.Printf("[PROBE-HELPER:DENY] trunk parent %q carries the default route (management) — not added to the allowlist", p)
		default:
			set[p] = true
		}
	}
	return set
}

// defaultRouteDevice returns the interface of the default route, or "" if there is none.
var defaultRouteDevice = func() string {
	out, err := exec.Command("ip", "-o", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// staleIPv4Addrs returns the IPv4 addresses on an interface other than want. IPv6, link-local included, is not
// this helper's to change.
func staleIPv4Addrs(addrs []net.Addr, want string) []string {
	var stale []string
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.To4() == nil {
			continue
		}
		if cidr := a.String(); cidr != want {
			stale = append(stale, cidr)
		}
	}
	return stale
}

// trunkParentsFromConfigFile reads probeConfigPath and extracts
// trunk_parents the same way trunkParentsFromContent does.
func trunkParentsFromConfigFile(path string) map[string]bool {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return trunkParentsFromContent(content)
}

// allowedJournalUnits is journal-tail's own fixed allowlist.
var allowedJournalUnits = map[string]bool{
	"dnshived-probe.service":        true,
	"dnshived-probe-helper.service": true,
}

// parseTrunkParents mirrors dnshived-helper's parseScopeAllowlist exactly
// (comma-separated, trimmed, blank entries dropped).
func parseTrunkParents(list string) map[string]bool {
	allowed := make(map[string]bool)
	for _, s := range strings.Split(list, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			allowed[s] = true
		}
	}
	return allowed
}

func main() {
	socketPath := flag.String("socket", "/run/dnshived/probe-helper.sock", "Unix socket path")
	trunkParentList := flag.String("trunk-parents", "", "comma-separated list of trunk parent interfaces create-interface/delete-interface may touch (e.g. ens19,ens20)")
	showVersion := flag.Bool("version", false, "print version and exit")
	cliguard.Parse("dnshived-probe-helper", false)

	if *showVersion {
		fmt.Println("dnshived-probe-helper", version)
		os.Exit(0)
	}

	cliguard.CheckUser("dnshived-probe-helper", cliguard.RootHelper, "")
	if err := instlock.Hold("/run/dnshived/probe-helper.lock"); err != nil {
		cliguard.Exit("dnshived-probe-helper", err)
	}

	flagTrunkParents = parseTrunkParents(*trunkParentList)
	if names := refreshAllowedTrunkParents(trunkParentsFromConfigFile(probeConfigPath)); len(names) == 0 {
		log.Printf("[PROBE-HELPER:INIT] no trunk parents in allowlist — create-interface/delete-interface will be rejected until one is configured")
	} else {
		log.Printf("[PROBE-HELPER:INIT] allowed trunk parents: %v", names)
	}

	socketDir := filepath.Dir(*socketPath)
	os.MkdirAll(socketDir, 0o755)
	if err := unixsock.RemoveStale(*socketPath); err != nil {
		cliguard.Exit("dnshived-probe-helper", err)
	}

	ln, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	os.Chmod(*socketPath, 0o660)

	log.Printf("[PROBE-HELPER:INIT] listening on %s", *socketPath)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed") {
					return
				}
				log.Printf("[PROBE-HELPER:ERROR] accept: %v", err)
				continue
			}
			connWG.Add(1)
			go func() {
				defer connWG.Done()
				handleConn(conn)
			}()
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("[PROBE-HELPER] shutting down, draining in-flight requests")
	ln.Close()
	connWG.Wait()
	os.Remove(*socketPath)
	log.Printf("[PROBE-HELPER] shutdown complete")
	os.Exit(0)
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		log.Printf("[PROBE-HELPER:ERROR] decode: %v", err)
		return
	}

	switch req.Command {
	case "restart-self":
		throttled, err := restartSelf()
		if err != nil {
			log.Printf("[PROBE-HELPER:ERROR] restart-self: %v", err)
			respond(conn, Response{OK: false, Error: err.Error()})
			return
		}
		log.Printf("[PROBE-HELPER:OK] restart-self (throttled=%v)", throttled)
		respond(conn, Response{OK: true, Throttled: throttled})

	case "write-config":
		if err := writeConfig(req.Content); err != nil {
			log.Printf("[PROBE-HELPER:ERROR] write-config: %v", err)
			respond(conn, Response{OK: false, Error: err.Error()})
			return
		}
		log.Printf("[PROBE-HELPER:OK] write-config (%d bytes to %s)", len(req.Content), probeConfigPath)
		if names := refreshAllowedTrunkParents(trunkParentsFromContent(req.Content)); len(names) > 0 {
			log.Printf("[PROBE-HELPER:OK] trunk-parent allowlist refreshed from new config: %v", names)
		}
		respond(conn, Response{OK: true})

	case "create-interface":
		if err := validateInterfaceReq(req); err != nil {
			log.Printf("[PROBE-HELPER:DENY] create-interface: %v", err)
			respond(conn, Response{OK: false, Error: err.Error()})
			return
		}
		if err := createInterface(req); err != nil {
			log.Printf("[PROBE-HELPER:ERROR] create-interface %s.%d: %v", req.Parent, req.VLANID, err)
			respond(conn, Response{OK: false, Error: err.Error()})
			return
		}
		log.Printf("[PROBE-HELPER:OK] create-interface %s.%d (%s)", req.Parent, req.VLANID, req.Addr)
		respond(conn, Response{OK: true})

	case "delete-interface":
		if err := validateInterfaceReq(req); err != nil {
			log.Printf("[PROBE-HELPER:DENY] delete-interface: %v", err)
			respond(conn, Response{OK: false, Error: err.Error()})
			return
		}
		if err := deleteInterface(req); err != nil {
			log.Printf("[PROBE-HELPER:ERROR] delete-interface %s.%d: %v", req.Parent, req.VLANID, err)
			respond(conn, Response{OK: false, Error: err.Error()})
			return
		}
		log.Printf("[PROBE-HELPER:OK] delete-interface %s.%d", req.Parent, req.VLANID)
		respond(conn, Response{OK: true})

	case "journal-tail":
		lines, err := getJournalTail(req)
		if err != nil {
			log.Printf("[PROBE-HELPER:ERROR] journal-tail %s: %v", req.Unit, err)
			respond(conn, Response{OK: false, Error: err.Error()})
			return
		}
		log.Printf("[PROBE-HELPER:OK] journal-tail %s", req.Unit)
		respond(conn, Response{OK: true, JournalLines: lines})

	case "stop-core-daemons":
		stopCoreDaemons()
		log.Printf("[PROBE-HELPER:OK] stop-core-daemons")
		respond(conn, Response{OK: true})

	case "decommission":
		summary := decommissionProbe()
		log.Printf("[PROBE-HELPER:OK] decommission — %s", summary)
		respond(conn, Response{OK: true})

	default:
		log.Printf("[PROBE-HELPER:DENY] unknown command %q", req.Command)
		respond(conn, Response{OK: false, Error: "unknown command: " + req.Command})
	}
}

// writeConfig atomically writes content to probeConfigPath.
func writeConfig(content []byte) error {
	if len(content) == 0 {
		return fmt.Errorf("empty content")
	}
	tmp := probeConfigPath + ".tmp"
	if err := os.WriteFile(tmp, content, 0o640); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmp, probeConfigPath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename into place: %w", err)
	}
	return chownToDnshivedGroup(probeConfigPath)
}

func chownToDnshivedGroup(path string) error {
	return ownership.Dnshived(path)
}

func stopCoreDaemons() {
	for _, unit := range []string{"dnshived.service", "dnshived-helper.service"} {
		exec.Command("systemctl", "stop", unit).Run()
		if err := exec.Command("systemctl", "disable", unit).Run(); err != nil {
			log.Printf("[PROBE-HELPER:WARN] stop/disable %s (mutual exclusion with this host's new probe role): %v", unit, err)
		}
	}
}

func respond(conn net.Conn, resp Response) {
	json.NewEncoder(conn).Encode(resp)
}

func validateInterfaceReq(req Request) error {
	if !isTrunkParentAllowed(req.Parent) {
		return fmt.Errorf("trunk parent not allowed: %q", req.Parent)
	}
	if req.VLANID < 0 || req.VLANID > 4094 {
		return fmt.Errorf("vlan_id out of range: %d", req.VLANID)
	}
	return nil
}

// createInterface brings up a VLAN sub-interface for probe traffic.
func createInterface(req Request) error {
	if req.VLANID == 0 {
		return createUntaggedInterface(req)
	}
	iface := fmt.Sprintf("%s.%d", req.Parent, req.VLANID)

	run("ip", "link", "set", req.Parent, "up")

	if _, err := os.Stat("/sys/class/net/" + iface); err == nil {
		if err := run("ip", "link", "set", iface, "up"); err != nil {
			log.Printf("[PROBE-HELPER:WARN] stale interface %s — deleting and recreating", iface)
			run("ip", "link", "delete", iface)
		} else {
			if link, err := net.InterfaceByName(iface); err == nil {
				if addrs, aerr := link.Addrs(); aerr == nil {
					for _, cidr := range staleIPv4Addrs(addrs, req.Addr) {
						run("ip", "addr", "del", cidr, "dev", iface)
					}
				}
			}
			if req.Addr != "" {
				run("ip", "addr", "add", req.Addr, "dev", iface)
			}
			return nil
		}
	}

	if err := run("ip", "link", "add", "link", req.Parent, "name", iface, "type", "vlan", "id", fmt.Sprintf("%d", req.VLANID)); err != nil {
		return fmt.Errorf("create vlan: %w", err)
	}
	if err := run("ip", "link", "set", iface, "up"); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	if req.Addr != "" {
		if err := run("ip", "addr", "add", req.Addr, "dev", iface); err != nil {
			return fmt.Errorf("assign address: %w", err)
		}
	}
	return nil
}

// createUntaggedInterface handles vlan_id==0.
func createUntaggedInterface(req Request) error {
	run("ip", "link", "set", req.Parent, "up")
	if req.Addr != "" {
		run("ip", "addr", "add", req.Addr, "dev", req.Parent)
	}
	return nil
}

// deleteInterface tears down a VLAN sub-interface previously created
// above.
func deleteInterface(req Request) error {
	if req.VLANID == 0 {
		if req.Addr != "" {
			run("ip", "addr", "del", req.Addr, "dev", req.Parent)
		}
		return nil
	}
	iface := fmt.Sprintf("%s.%d", req.Parent, req.VLANID)
	if _, err := os.Stat("/sys/class/net/" + iface); err != nil {
		return nil
	}
	return run("ip", "link", "delete", iface)
}

func decommissionProbe() string {
	ifacesGone := 0
	if entries, err := os.ReadDir("/sys/class/net"); err == nil {
		for _, e := range entries {
			m := vlanIfaceRE.FindStringSubmatch(e.Name())
			if m == nil || !isTrunkParentAllowed(m[1]) {
				continue
			}
			if err := run("ip", "link", "delete", e.Name()); err != nil {
				log.Printf("[PROBE-HELPER:WARN] decommission: delete %s: %v", e.Name(), err)
				continue
			}
			ifacesGone++
		}
	}

	if out, err := exec.Command("systemctl", "list-unit-files", "--no-legend", "--plain", "dnshived-probe-vlans@*.service").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) > 0 && strings.HasPrefix(f[0], "dnshived-probe-vlans@") && !strings.HasSuffix(f[0], "@.service") {
				if e := exec.Command("systemctl", "disable", "--now", f[0]).Run(); e != nil {
					log.Printf("[PROBE-HELPER:WARN] decommission: disable %s: %v", f[0], e)
				}
			}
		}
	}

	cfgFilesGone := sweepDirContents(filepath.Dir(probeConfigPath))
	stateFilesGone := sweepDirContents(probeStateDir)

	return fmt.Sprintf("%d vlan interface(s) removed, %d config file(s) + %d state file(s) wiped",
		ifacesGone, cfgFilesGone, stateFilesGone)
}

func sweepDirContents(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if err := os.RemoveAll(p); err != nil {
			log.Printf("[PROBE-HELPER:WARN] decommission: remove %s: %v", p, err)
			continue
		}
		removed++
	}
	return removed
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %s (%w)", name, args, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// getJournalTail returns req.Unit's own last req.Lines journal lines.
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

// restartMu/lastRestartAt rate-limit restartSelf to at most once per 10s.
var (
	restartMu     sync.Mutex
	lastRestartAt time.Time
)

func restartSelf() (throttled bool, err error) {
	restartMu.Lock()
	defer restartMu.Unlock()
	if time.Since(lastRestartAt) < 10*time.Second {
		log.Printf("[PROBE-HELPER:RATE_LIMIT] restart-self suppressed (< 10s since last restart)")
		return true, nil
	}
	if err := exec.Command("systemctl", "restart", "dnshived-probe.service").Run(); err != nil {
		return false, fmt.Errorf("restart dnshived-probe.service: %w", err)
	}
	lastRestartAt = time.Now()
	return false, nil
}
