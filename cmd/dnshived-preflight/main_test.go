// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckRequiredBinaries_AllPresent(t *testing.T) {
	r := checkRequiredBinaries(func(string) error { return nil })
	if !r.ok {
		t.Fatalf("expected ok, got fail: %s", r.fail)
	}
}

func TestCheckRequiredBinaries_SomeMissing(t *testing.T) {
	r := checkRequiredBinaries(func(name string) error {
		if name == "nft" {
			return errors.New("not found")
		}
		return nil
	})
	if r.ok {
		t.Fatal("expected failure when a required binary is missing")
	}
	if !strings.Contains(r.fail, "nft") {
		t.Fatalf("expected failure message to name the missing binary, got %q", r.fail)
	}
}

func TestParseOSRelease_DebianFamily(t *testing.T) {
	id, idLike := parseOSRelease(strings.NewReader("ID=debian\nID_LIKE=\n"))
	if id != "debian" {
		t.Fatalf("expected id=debian, got %q", id)
	}
	_ = idLike
}

func TestParseOSRelease_RHELFamily(t *testing.T) {
	id, idLike := parseOSRelease(strings.NewReader(`ID="rocky"` + "\n" + `ID_LIKE="rhel centos fedora"` + "\n"))
	if id != "rocky" {
		t.Fatalf("expected id=rocky, got %q", id)
	}
	if !strings.Contains(idLike, "rhel") {
		t.Fatalf("expected id_like to contain rhel, got %q", idLike)
	}
}

func TestPortsHeld_MatchesWildcardBind(t *testing.T) {
	lines := []string{
		"udp   UNCONN 0      0            0.0.0.0:53         0.0.0.0:*",
		"tcp   LISTEN 0      128          127.0.0.1:9443      0.0.0.0:*",
	}
	got := portsHeld(lines, "53")
	if got == "" {
		t.Fatal("expected a wildcard bind on :53 to be detected")
	}
	if strings.Contains(got, "9443") {
		t.Fatalf("unrelated port leaked into result: %q", got)
	}
}

func TestPortsHeld_IgnoresLiteralAddress(t *testing.T) {
	lines := []string{"udp UNCONN 0 0 127.0.0.42:53 0.0.0.0:*"}
	if got := portsHeld(lines, "53"); got != "" {
		t.Fatalf("expected a literal-address bind on :53 to be IGNORED (not a real conflict), got %q", got)
	}
}

func TestPortsHeld_MatchesIPv6WildcardBind(t *testing.T) {
	lines := []string{"tcp LISTEN 0 32 [::]:53 [::]:*"}
	if portsHeld(lines, "53") == "" {
		t.Fatal("expected an IPv6 wildcard bind on :53 to be detected")
	}
}

func TestPortsHeld_NothingListening(t *testing.T) {
	lines := []string{"tcp LISTEN 0 128 127.0.0.1:9443 0.0.0.0:*"}
	if got := portsHeld(lines, "53"); got != "" {
		t.Fatalf("expected no match, got %q", got)
	}
}

func TestUnitActiveOrEnabled_Active(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		if name == "systemctl" && len(args) == 2 && args[0] == "is-active" {
			return []byte("active\n"), nil
		}
		return []byte("disabled\n"), nil
	}
	if !unitActiveOrEnabled(run, "dnsmasq.service") {
		t.Fatal("expected active unit to be detected")
	}
}

func TestUnitActiveOrEnabled_EnabledButNotActive(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		if args[0] == "is-enabled" {
			return []byte("enabled\n"), nil
		}
		return []byte("inactive\n"), nil
	}
	if !unitActiveOrEnabled(run, "dnsmasq.service") {
		t.Fatal("expected enabled-but-inactive unit to still be detected")
	}
}

func TestUnitActiveOrEnabled_NeitherAbsentUnit(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		return []byte(""), errors.New("unit not found")
	}
	if unitActiveOrEnabled(run, "dnsmasq.service") {
		t.Fatal("expected an absent unit to report false")
	}
}

func TestCheckStockDnsmasq_InactiveUnitIsAPlainPass(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		return []byte("inactive\n"), nil
	}
	listPorts := func() ([]string, error) { return nil, nil }
	r := checkStockDnsmasq(run, listPorts)
	if !r.ok || r.remediate != "" {
		t.Fatalf("expected a plain pass, got ok=%v remediate=%q fail=%q", r.ok, r.remediate, r.fail)
	}
}

func TestCheckStockDnsmasq_ActiveUnitGetsRemediated(t *testing.T) {
	var calls []string
	run := func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "systemctl" && args[0] == "is-active" {
			return []byte("active\n"), nil
		}
		return []byte(""), nil
	}
	listPorts := func() ([]string, error) { return nil, nil }
	r := checkStockDnsmasq(run, listPorts)
	if !r.ok || r.remediate == "" {
		t.Fatalf("expected a remediated pass, got ok=%v remediate=%q fail=%q", r.ok, r.remediate, r.fail)
	}
	wantCalls := []string{"systemctl stop dnsmasq.service", "systemctl disable dnsmasq.service", "systemctl mask dnsmasq.service"}
	for _, want := range wantCalls {
		found := false
		for _, c := range calls {
			if c == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected call %q, got calls %v", want, calls)
		}
	}
}

func TestCheckStockDnsmasq_StillHeldAfterRemediationFailsHard(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		if args[0] == "is-active" {
			return []byte("active\n"), nil
		}
		return []byte(""), nil
	}
	listPorts := func() ([]string, error) {
		return []string{"udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*"}, nil
	}
	r := checkStockDnsmasq(run, listPorts)
	if r.ok {
		t.Fatal("expected a real failure when port 53 is still held after remediation")
	}
	if !strings.Contains(r.fail, "53") {
		t.Fatalf("expected failure message to mention port 53, got %q", r.fail)
	}
}

func TestCheckStockDnsmasq_PortListFailureIsAHardFailure(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) { return []byte("inactive\n"), nil }
	listPorts := func() ([]string, error) { return nil, errors.New("ss not found") }
	r := checkStockDnsmasq(run, listPorts)
	if r.ok {
		t.Fatal("expected a hard failure when port state can't be verified at all")
	}
}
