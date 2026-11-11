// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package vrrpstate

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestVerifyProcessIsKeepalived_WrongComm(t *testing.T) {
	// The test binary itself is definitely not named "keepalived".
	if err := verifyProcessIsKeepalived(os.Getpid()); err == nil {
		t.Error("expected an error for a pid whose comm is not keepalived")
	}
}

func TestVerifyProcessIsKeepalived_NonexistentPid(t *testing.T) {
	// PID 1 is always init/systemd, never keepalived, and always exists —
	// use an implausibly high PID instead to hit the "no such process" path.
	if err := verifyProcessIsKeepalived(1 << 30); err == nil {
		t.Error("expected an error for a nonexistent pid")
	}
}

func TestParseInstanceState(t *testing.T) {
	data, err := os.ReadFile("testdata/keepalived.data")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	cases := []struct {
		instance string
		want     string
		wantErr  bool
	}{
		{"DNSHIVED_office", "BACKUP", false},
		{"DNSHIVED_avdante", "MASTER", false},
		{"DNSHIVED_nonexistent", "", true},
		// A shorter name must not match as a prefix of a longer one.
		{"DNSHIVED_off", "", true},
	}

	for _, c := range cases {
		got, err := ParseInstanceState(data, c.instance)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected error, got state %q", c.instance, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error: %v", c.instance, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.instance, got, c.want)
		}
	}
}

// oldParseInstanceState is the regexp implementation ParseInstanceState used
// before ParseInstanceStates existed; it is the reference the single-pass
// parser is compared with.
func oldParseInstanceState(data []byte, instanceName string) (string, error) {
	re, err := regexp.Compile(`(?m)^\s*VRRP Instance = ` + regexp.QuoteMeta(instanceName) + `\s*$\n(?:.*\n)*?\s*State = (\S+)`)
	if err != nil {
		return "", err
	}
	m := re.FindSubmatch(data)
	if m == nil {
		return "", fmt.Errorf("instance %q not found in dump", instanceName)
	}
	return string(m[1]), nil
}

func fakeDump(n int) ([]byte, map[string]string) {
	var b strings.Builder
	b.WriteString("------< Global definitions >------\n Router ID = node-a.example\n------< VRRP Topology >------\n")
	want := make(map[string]string, n)
	states := []string{"MASTER", "BACKUP", "FAULT"}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("DNSHIVED_scope-%03d", i)
		state := states[i%3]
		want[name] = state
		fmt.Fprintf(&b, " VRRP Instance = %s\n   VRRP Version = 2\n   Wantstate = MASTER\n   Last transition = 1731283200 (Mon Nov 11 00:00:00 2026)\n   State = %s\n   Master router = (none)\n   Master priority = 0\n   Interface = ens19.%d\n   Virtual Router ID = %d\n   Priority = 100\n   Advert interval = 1 sec\n   Preempt = enabled\n   Promote_secondaries = disabled\n   Virtual IP = 1\n     10.%d.0.1/24 dev ens19.%d scope global\n", name, state, 100+i, 1+i%250, i, 100+i)
	}
	return []byte(b.String()), want
}

func TestParseInstanceStates_MatchesTheRegexpOracle(t *testing.T) {
	fixture, err := os.ReadFile("testdata/keepalived.data")
	if err != nil {
		t.Fatal(err)
	}
	big, want := fakeDump(102)
	tests := []struct {
		name  string
		data  []byte
		names []string
	}{
		{"fixture", fixture, []string{"DNSHIVED_office", "DNSHIVED_avdante", "DNSHIVED_off", "DNSHIVED_nope"}},
		{"102 instances", big, append(func() []string {
			var n []string
			for k := range want {
				n = append(n, k)
			}
			return n
		}(), "DNSHIVED_scope-1", "DNSHIVED_scope-0001")},
		{"windows line endings", []byte(strings.ReplaceAll(string(fixture), "\n", "\r\n")), []string{"DNSHIVED_office", "DNSHIVED_avdante"}},
		{"no trailing newline", bytes.TrimRight(fixture, "\n"), []string{"DNSHIVED_office", "DNSHIVED_avdante"}},
		{"regexp metacharacters in a name", []byte(" VRRP Instance = DNSHIVED_a.b+c\n   State = MASTER\n VRRP Instance = DNSHIVED_axbbc\n   State = BACKUP\n"), []string{"DNSHIVED_a.b+c", "DNSHIVED_axbbc"}},
		{"empty dump", nil, []string{"DNSHIVED_office"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			all := ParseInstanceStates(tt.data)
			for _, n := range tt.names {
				wantState, wantErr := oldParseInstanceState(tt.data, n)
				gotState, gotErr := ParseInstanceState(tt.data, n)
				if (wantErr != nil) != (gotErr != nil) || wantState != gotState {
					t.Errorf("%s: new %q %v, old %q %v", n, gotState, gotErr, wantState, wantErr)
				}
				if s, ok := all[n]; ok != (wantErr == nil) || s != wantState {
					t.Errorf("%s: map %q %v, old %q %v", n, s, ok, wantState, wantErr)
				}
			}
		})
	}
	all := ParseInstanceStates(big)
	if len(all) != len(want) {
		t.Fatalf("parsed %d instances, want %d", len(all), len(want))
	}
	for k, v := range want {
		if all[k] != v {
			t.Errorf("%s = %q, want %q", k, all[k], v)
		}
	}
}

// Where the old regexp read a later instance's State for an instance that has
// none of its own, the parser leaves that instance out.
func TestParseInstanceStates_InstanceWithoutStateIsLeftOut(t *testing.T) {
	data := []byte(" VRRP Instance = A\n   Priority = 1\n VRRP Instance = B\n   State = MASTER\n")
	got := ParseInstanceStates(data)
	if _, ok := got["A"]; ok || got["B"] != "MASTER" {
		t.Errorf("got %v, want only B=MASTER", got)
	}
	dup := ParseInstanceStates([]byte(" VRRP Instance = A\n State = MASTER\n VRRP Instance = A\n State = BACKUP\n"))
	if dup["A"] != "MASTER" {
		t.Errorf("the first of two equal names wins, got %q", dup["A"])
	}
}

func BenchmarkInstanceStates102(b *testing.B) {
	data, want := fakeDump(102)
	names := make([]string, 0, len(want))
	for k := range want {
		names = append(names, k)
	}
	b.Run("per scope regexp (before)", func(b *testing.B) {
		b.SetBytes(int64(len(data)))
		for b.Loop() {
			for _, n := range names {
				if _, err := oldParseInstanceState(data, n); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("one pass (after)", func(b *testing.B) {
		b.SetBytes(int64(len(data)))
		for b.Loop() {
			m := ParseInstanceStates(data)
			for _, n := range names {
				if _, ok := m[n]; !ok {
					b.Fatal("missing")
				}
			}
		}
	})
}
