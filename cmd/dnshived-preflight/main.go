// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

var version = "0.9.8-dev"

var requiredBinaries = []string{"dnsmasq", "nft", "keepalived"}

type checkResult struct {
	name      string
	ok        bool
	remediate string
	fail      string
}

func pass(name string) checkResult         { return checkResult{name: name, ok: true} }
func fixed(name, what string) checkResult  { return checkResult{name: name, ok: true, remediate: what} }
func failure(name, why string) checkResult { return checkResult{name: name, ok: false, fail: why} }

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(version)
		return
	}

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "dnshived-preflight: must run as root")
		os.Exit(1)
	}

	results := []checkResult{
		checkRequiredBinaries(execLookPath),
		checkStockDnsmasq(runCmd, listListeningPorts),
	}

	ok := true
	for _, r := range results {
		switch {
		case !r.ok:
			fmt.Printf("[FAIL] %s: %s\n", r.name, r.fail)
			ok = false
		case r.remediate != "":
			fmt.Printf("[FIXED] %s: %s\n", r.name, r.remediate)
		default:
			fmt.Printf("[OK] %s\n", r.name)
		}
	}

	if !ok {
		fmt.Fprintln(os.Stderr, "dnshived-preflight: one or more checks failed, aborting install")
		os.Exit(1)
	}
}

// Package-level funcs, not inlined, so tests can swap in a fake.
func execLookPath(name string) error {
	_, err := exec.LookPath(name)
	return err
}

func runCmd(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// Never attempts to install anything itself.
func checkRequiredBinaries(lookPath func(string) error) checkResult {
	var missing []string
	for _, bin := range requiredBinaries {
		if err := lookPath(bin); err != nil {
			missing = append(missing, bin)
		}
	}
	if len(missing) == 0 {
		return pass("required binaries present")
	}
	return failure("required binaries present",
		fmt.Sprintf("missing: %s — install with %q",
			strings.Join(missing, ", "), installHint()))
}

func installHint() string {
	id, idLike := readOSRelease()
	family := id + " " + idLike
	switch {
	case strings.Contains(family, "debian") || strings.Contains(family, "ubuntu"):
		return "apt install dnsmasq-base nftables keepalived"
	case strings.Contains(family, "rhel") || strings.Contains(family, "centos") ||
		strings.Contains(family, "rocky") || strings.Contains(family, "fedora"):
		return "dnf install dnsmasq nftables keepalived"
	default:
		return "install dnsmasq, nftables, and keepalived using this distro's package manager"
	}
}

func readOSRelease() (id, idLike string) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "", ""
	}
	defer f.Close()
	return parseOSRelease(f)
}

func parseOSRelease(r io.Reader) (id, idLike string) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "ID="):
			id = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		case strings.HasPrefix(line, "ID_LIKE="):
			idLike = strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), `"`)
		}
	}
	return strings.ToLower(id), strings.ToLower(idLike)
}

// The distro's default dnsmasq.service wildcard-binds port 53, silently
// colliding with dnshived-dnsmasq@core-dns.
func checkStockDnsmasq(run func(string, ...string) ([]byte, error), listPorts func() ([]string, error)) checkResult {
	const unit = "dnsmasq.service"
	active := unitActiveOrEnabled(run, unit)
	if active {
		run("systemctl", "stop", unit)
		run("systemctl", "disable", unit)
		run("systemctl", "mask", unit)
	}

	ports, err := listPorts()
	if err != nil {
		return failure("no conflicting DNS/DHCP service on required ports",
			fmt.Sprintf("could not inspect listening sockets: %v", err))
	}
	if held := portsHeld(ports, "53"); held != "" {
		return failure("no conflicting DNS/DHCP service on required ports",
			fmt.Sprintf("port 53 is still held after remediation: %s", held))
	}

	if active {
		return fixed("no conflicting DNS/DHCP service on required ports",
			"stopped, disabled, and masked the distro's own "+unit)
	}
	return pass("no conflicting DNS/DHCP service on required ports")
}

func unitActiveOrEnabled(run func(string, ...string) ([]byte, error), unit string) bool {
	if out, _ := run("systemctl", "is-active", unit); strings.TrimSpace(string(out)) == "active" {
		return true
	}
	if out, _ := run("systemctl", "is-enabled", unit); strings.TrimSpace(string(out)) == "enabled" {
		return true
	}
	return false
}

func listListeningPorts() ([]string, error) {
	out, err := exec.Command("ss", "-lntu").CombinedOutput()
	if err != nil {
		return nil, err
	}
	return strings.Split(string(out), "\n"), nil
}

// Matches ONLY a wildcard bind (0.0.0.0:53, [::]:53).
func portsHeld(lines []string, port string) string {
	wildcards := map[string]bool{"0.0.0.0:" + port: true, "[::]:" + port: true}
	var hits []string
	for _, line := range lines {
		for _, f := range strings.Fields(line) {
			if wildcards[f] {
				hits = append(hits, strings.TrimSpace(line))
				break
			}
		}
	}
	return strings.Join(hits, " | ")
}
