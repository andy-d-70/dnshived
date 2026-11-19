// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package configimport

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"dnshived/internal/access"
	"dnshived/internal/backupcrypt"
	"dnshived/internal/config"
)

func fileCluster() config.Cluster {
	return config.Cluster{
		ClusterID: "old", NodeID: "node-x", Role: config.RoleCore1, ControlAddr: "192.0.2.1:9443",
		PSK: "file-psk", TrustedHosts: []string{"192.0.2.9"}, TLSCert: "c", TLSKey: "k",
		APITokens:      []config.APIToken{{Name: "t", Token: "tok", Role: "admin"}},
		BackupPassword: "pw", BackupEnabled: true, BackupIntervalHours: 6,
		LogLevel: "debug", ProbeIntervalMS: 500,
		Platform: &config.Platform{Mgmt: "eth0", Workers: []string{"eth1"}},
		Scopes: map[string]config.ScopeConfig{
			"office": {VLANID: 100, VIP: "192.168.100.1/24", NodeIP: "192.168.100.22/24", NodeIPOverrides: map[string]string{"core-1": "192.168.100.5/24"},
				Reservations: []config.Reservation{{MAC: "aa:bb:cc:00:00:01", IP: "192.168.100.50", Hostname: "nas"}}},
			"lab": {VLANID: 101, VIP: "192.168.101.1/24"},
		},
		LocalDomains: []config.LocalDomain{
			{Name: "office.lan", TTL: 60, Records: []config.LocalDomainHost{{Host: "nas", Type: "A", Value: "192.168.100.50"}, {Host: "cam", Type: "A", Value: "192.168.100.60"}}},
			{Name: "link.lan", ForkedFrom: "office.lan", Records: []config.LocalDomainHost{{Host: "nas", Type: "A", Value: "192.168.100.50"}}},
			{Name: "bad_name", Records: nil},
		},
		GlobalDNSRecords:   []config.DNSRecord{{Name: "g.lan.", Type: "A", Value: "192.168.100.8"}},
		DefaultDHCPOptions: []string{"option:42,192.0.2.1"},
		Access:             &access.Config{Mode: "enforce"},
	}
}

func mustParse(t *testing.T, c config.Cluster) *Source {
	t.Helper()
	b, _ := json.Marshal(c)
	s, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func allGroups(m Mode) Options {
	g := map[Group]Mode{}
	for _, x := range AllGroups {
		g[x] = m
	}
	return Options{Groups: g}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"empty", "", false},
		{"array", `[1]`, false},
		{"text", `hello`, false},
		{"empty object", `{}`, false},
		{"schema too new", `{"schema_version":99,"cluster_id":"x"}`, false},
		{"scopes export", `{"cluster_id":"x","source_node":"core-1","scopes":{"a":{"vlan_id":5}}}`, true},
		{"data without cluster id", `{"local_domains":[{"name":"a.lan"}]}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.in))
			if (err == nil) != tt.ok {
				t.Errorf("Parse(%q) err = %v, want ok=%v", tt.in, err, tt.ok)
			}
		})
	}
	s := mustParse(t, fileCluster())
	if len(s.IgnoredSecrets) != 4 {
		t.Errorf("IgnoredSecrets = %v, want key, tokens, TLS and backup password", s.IgnoredSecrets)
	}
	if c := s.Counts(); c[GroupScopes] != 2 || c[GroupDomains] != 3 || c[GroupAccess] != 1 || c[GroupPlatform] != 1 || c[GroupSettings] != 1 {
		t.Errorf("Counts = %v", c)
	}
}

func TestApply_NeverTakesTrustOrIdentity(t *testing.T) {
	live := config.Cluster{ClusterID: "new", NodeID: "node-y", Role: config.RoleCore2, ControlAddr: "192.0.2.77:9443", PSK: "live-psk",
		TrustedHosts: []string{"192.0.2.77"}, TLSCert: "lc", TLSKey: "lk", APITokens: []config.APIToken{{Name: "mine", Token: "m", Role: "admin"}}, HelperSocket: "/run/h"}
	for _, m := range []Mode{Merge, Replace} {
		out, _, err := Apply(live, mustParse(t, fileCluster()), allGroups(m))
		if err != nil {
			t.Fatal(err)
		}
		if out.PSK != "live-psk" || out.ClusterID != "new" || out.NodeID != "node-y" || out.Role != config.RoleCore2 || out.ControlAddr != "192.0.2.77:9443" ||
			out.TLSKey != "lk" || out.TLSCert != "lc" || len(out.APITokens) != 1 || out.APITokens[0].Token != "m" ||
			len(out.TrustedHosts) != 1 || out.TrustedHosts[0] != "192.0.2.77" || out.HelperSocket != "/run/h" || out.BackupPassword != "" {
			t.Errorf("mode %s changed trust or identity: %+v", m, out)
		}
	}
}

func TestApply_ScopesArriveParkedWithoutNodeAddresses(t *testing.T) {
	live := config.Cluster{Scopes: map[string]config.ScopeConfig{"office": {VLANID: 7}}}
	out, rep, err := Apply(live, mustParse(t, fileCluster()), Options{Groups: map[Group]Mode{GroupScopes: Merge}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Scopes) != 1 || out.Scopes["office"].VLANID != 7 {
		t.Error("a live scope must stay as it is")
	}
	if len(out.ParkedScopes) != 1 || out.ParkedScopes["lab"].VLANID != 101 {
		t.Errorf("parked = %v, want lab only (office is live)", out.ParkedScopes)
	}
	if len(rep.Groups[0].Skipped) != 1 || !strings.Contains(rep.Groups[0].Skipped[0], "office") {
		t.Errorf("skipped = %v", rep.Groups[0].Skipped)
	}

	out, _, _ = Apply(config.Cluster{}, mustParse(t, fileCluster()), Options{Groups: map[Group]Mode{GroupScopes: Merge}})
	if len(out.Scopes) != 0 || len(out.ParkedScopes) != 2 {
		t.Fatalf("live %d parked %d, want 0 and 2", len(out.Scopes), len(out.ParkedScopes))
	}
	if sc := out.ParkedScopes["office"]; sc.NodeIP != "" || sc.NodeIPOverrides != nil || len(sc.Reservations) != 1 {
		t.Errorf("office = %+v, want reservations kept and node addresses dropped", sc)
	}
}

func TestApply_ScopeFilterAndReplace(t *testing.T) {
	live := config.Cluster{ParkedScopes: map[string]config.ScopeConfig{"old": {VLANID: 1}, "lab": {VLANID: 9}}}
	src := mustParse(t, fileCluster())
	out, rep, _ := Apply(live, src, Options{Groups: map[Group]Mode{GroupScopes: Merge}, Scopes: []string{"lab"}})
	if len(out.ParkedScopes) != 2 || out.ParkedScopes["lab"].VLANID != 101 || len(rep.Groups[0].Changed) != 1 {
		t.Errorf("filtered merge: %v %+v", out.ParkedScopes, rep.Groups[0])
	}
	out, rep, _ = Apply(live, src, Options{Groups: map[Group]Mode{GroupScopes: Replace}})
	if _, kept := out.ParkedScopes["old"]; kept || len(rep.Groups[0].Removed) != 1 {
		t.Errorf("replace must drop parked scopes the file lacks: %v %+v", out.ParkedScopes, rep.Groups[0])
	}
	out, _, _ = Apply(live, src, Options{Groups: map[Group]Mode{GroupScopes: Replace}, Scopes: []string{"lab"}})
	if _, kept := out.ParkedScopes["old"]; !kept {
		t.Error("replace with a scope filter must not remove anything")
	}
}

func TestApply_DomainsMergeAndReplace(t *testing.T) {
	live := config.Cluster{LocalDomains: []config.LocalDomain{
		{Name: "office.lan", Records: []config.LocalDomainHost{{Host: "nas", Type: "A", Value: "192.168.100.50"}, {Host: "mine", Type: "A", Value: "10.9.9.9"}}},
		{Name: "extra.lan"},
	}}
	src := mustParse(t, fileCluster())
	out, rep, _ := Apply(live, src, Options{Groups: map[Group]Mode{GroupDomains: Merge}})
	byName := map[string]config.LocalDomain{}
	for _, d := range out.LocalDomains {
		byName[d.Name] = d
	}
	if got := byName["office.lan"]; len(got.Records) != 3 || got.TTL != 60 {
		t.Errorf("office.lan = %+v, want the file's new record added, its own kept, TTL taken from the file", got)
	}
	if _, ok := byName["extra.lan"]; !ok {
		t.Error("merge keeps domains the file lacks")
	}
	if _, ok := byName["bad_name"]; ok {
		t.Error("an invalid name must be skipped")
	}
	if l, ok := byName["link.lan"]; !ok || l.ForkedFrom != "office.lan" || len(l.Records) != 3 {
		t.Errorf("link.lan = %+v, want a link that follows its original", l)
	}
	if len(rep.Groups[0].Skipped) != 1 {
		t.Errorf("skipped = %v", rep.Groups[0].Skipped)
	}

	out, rep, _ = Apply(live, src, Options{Groups: map[Group]Mode{GroupDomains: Replace}})
	for _, d := range out.LocalDomains {
		if d.Name == "extra.lan" {
			t.Error("replace removes domains the file lacks")
		}
	}
	if len(rep.Groups[0].Removed) != 1 {
		t.Errorf("removed = %v", rep.Groups[0].Removed)
	}

	again, rep2, _ := Apply(out, src, Options{Groups: map[Group]Mode{GroupDomains: Replace}})
	if rep2.Changes() != 0 || len(again.LocalDomains) != len(out.LocalDomains) {
		t.Errorf("a second import of the same file must change nothing: %+v", rep2)
	}
}

func TestApply_DNSDHCPAccessSettingsPlatform(t *testing.T) {
	src := mustParse(t, fileCluster())
	live := config.Cluster{
		GlobalDNSRecords: []config.DNSRecord{{Name: "own.lan.", Type: "A", Value: "1.1.1.1"}},
		LogLevel:         "info", ProbeIntervalMS: 1000,
		Access:   &access.Config{Mode: "report"},
		Platform: &config.Platform{Mgmt: "ens18"},
	}
	out, _, _ := Apply(live, src, allGroups(Merge))
	if len(out.GlobalDNSRecords) != 2 {
		t.Errorf("merge unions the global records: %v", out.GlobalDNSRecords)
	}
	if out.LogLevel != "debug" || out.ProbeIntervalMS != 500 || out.BackupEnabled || out.BackupIntervalHours != 6 {
		t.Errorf("settings from the file not applied: %+v", out)
	}
	if out.Access.Mode != "report" || out.Platform.Mgmt != "ens18" {
		t.Error("merge keeps this cluster's own access list and platform")
	}
	if len(out.DefaultDHCPOptions) != 1 {
		t.Errorf("default options = %v", out.DefaultDHCPOptions)
	}

	out, _, _ = Apply(live, src, allGroups(Replace))
	if len(out.GlobalDNSRecords) != 1 || out.GlobalDNSRecords[0].Name != "g.lan." || out.Access.Mode != "enforce" || out.Platform.Mgmt != "eth0" {
		t.Errorf("replace takes the file's values: %+v", out)
	}

	blank := config.Cluster{LogLevel: "info", ProbeIntervalMS: 1000}
	out, _, _ = Apply(blank, mustParse(t, config.Cluster{ClusterID: "x", Scopes: map[string]config.ScopeConfig{"a": {VLANID: 1}}}), Options{Groups: map[Group]Mode{GroupSettings: Merge}})
	if out.LogLevel != "info" || out.ProbeIntervalMS != 1000 {
		t.Error("merge must not blank a setting the file does not have")
	}
}

func TestApply_RejectsBadOptions(t *testing.T) {
	src := mustParse(t, fileCluster())
	if _, _, err := Apply(config.Cluster{}, src, Options{Groups: map[Group]Mode{"nope": Merge}}); err == nil {
		t.Error("unknown group")
	}
	if _, _, err := Apply(config.Cluster{}, src, Options{Groups: map[Group]Mode{GroupScopes: "wipe"}}); err == nil {
		t.Error("unknown mode")
	}
}

func BenchmarkApplyDomains_MaxScale(b *testing.B) {
	var domains []config.LocalDomain
	for i := 0; i < 2500; i++ {
		d := config.LocalDomain{Name: "d" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + strings.Repeat("y", i/26%9) + ".lan"}
		for h := 0; h < 250; h++ {
			d.Records = append(d.Records, config.LocalDomainHost{Host: "h" + strings.Repeat("z", h%7) + string(rune('a'+h%26)), Type: "A", Value: "10.0.0.1", Port: h})
		}
		domains = append(domains, d)
	}
	src := &Source{Cluster: config.Cluster{ClusterID: "x", LocalDomains: domains}}
	live := config.Cluster{LocalDomains: domains[:1000]}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Apply(live, src, Options{Groups: map[Group]Mode{GroupDomains: Merge}})
	}
}

func TestApply_BackupSettingsNeedAPassword(t *testing.T) {
	src := mustParse(t, config.Cluster{ClusterID: "x", BackupEnabled: true, BackupIntervalHours: 6, LogLevel: "debug"})
	out, rep, _ := Apply(config.Cluster{}, src, Options{Groups: map[Group]Mode{GroupSettings: Replace}})
	if out.BackupEnabled {
		t.Error("backups must not be switched on without a password, the result would not validate")
	}
	if out.BackupIntervalHours != 6 || out.LogLevel != "debug" {
		t.Errorf("the other settings are still taken: %+v", out)
	}
	if len(rep.Groups[0].Skipped) != 1 || !strings.Contains(rep.Groups[0].Skipped[0], "backup password") {
		t.Errorf("skipped = %v", rep.Groups[0].Skipped)
	}
	withPW, _, _ := Apply(config.Cluster{BackupPassword: "set"}, src, Options{Groups: map[Group]Mode{GroupSettings: Replace}})
	if !withPW.BackupEnabled {
		t.Error("with a password of its own the cluster takes the setting")
	}
}

func TestApply_ScopeDefaultsKeepTheirOwnNodeSuffixes(t *testing.T) {
	file := mustParse(t, config.Cluster{ClusterID: "x", ScopeDefaults: &config.ScopeDefaults{VIPSuffix: "250", NodeIPSuffixes: map[string]string{"core-1": "51"}}})
	own := config.Cluster{ScopeDefaults: &config.ScopeDefaults{VIPSuffix: "254", NodeIPSuffixes: map[string]string{"core-1": "60"}}}
	out, _, _ := Apply(own, file, Options{Groups: map[Group]Mode{GroupDHCP: Replace}})
	if out.ScopeDefaults.VIPSuffix != "250" || out.ScopeDefaults.NodeIPSuffixes["core-1"] != "60" {
		t.Errorf("replace takes the file's defaults but keeps this cluster's node suffixes: %+v", out.ScopeDefaults)
	}
	out, _, _ = Apply(config.Cluster{}, file, Options{Groups: map[Group]Mode{GroupDHCP: Merge}})
	if out.ScopeDefaults == nil || out.ScopeDefaults.NodeIPSuffixes != nil {
		t.Errorf("without own defaults the file's node suffixes are dropped: %+v", out.ScopeDefaults)
	}
}

func TestApply_NotesTrunksThePlatformLacks(t *testing.T) {
	file := mustParse(t, config.Cluster{ClusterID: "x", Scopes: map[string]config.ScopeConfig{"a": {Parent: "ens19", VLANID: 1}, "b": {Parent: "ens20", VLANID: 2}}})
	_, rep, _ := Apply(config.Cluster{Platform: &config.Platform{Mgmt: "eth0", Workers: []string{"ens19"}}}, file, Options{Groups: map[Group]Mode{GroupScopes: Merge}})
	notes := rep.Groups[0].Notes
	if len(notes) != 1 || !strings.Contains(notes[0], "ens20") || strings.Contains(notes[0], "ens19") {
		t.Errorf("notes = %v, want only ens20 named", notes)
	}
	_, rep, _ = Apply(config.Cluster{Platform: &config.Platform{Mgmt: "eth0", Workers: []string{"ens19", "ens20"}}}, file, Options{Groups: map[Group]Mode{GroupScopes: Merge}})
	if len(rep.Groups[0].Notes) != 0 {
		t.Errorf("no note when the platform has every trunk: %v", rep.Groups[0].Notes)
	}
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write(b)
	gw.Close()
	return buf.Bytes()
}

func TestParseBackup(t *testing.T) {
	plain, _ := json.Marshal(fileCluster())
	blob, err := backupcrypt.Encrypt("pw-1", gzipBytes(t, plain))
	if err != nil {
		t.Fatal(err)
	}
	if !LooksEncrypted(blob) || LooksEncrypted(plain) {
		t.Error("an encrypted blob must be told apart from a JSON export")
	}
	src, err := ParseBackup(blob, "pw-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(src.Cluster.Scopes) != 2 || len(src.IgnoredSecrets) == 0 {
		t.Errorf("scopes %d, ignored %v", len(src.Cluster.Scopes), src.IgnoredSecrets)
	}
	if _, err := ParseBackup(blob, ""); !errors.Is(err, ErrNeedPassword) {
		t.Errorf("no password: %v", err)
	}
	if _, err := ParseBackup(blob, "wrong"); !errors.Is(err, backupcrypt.ErrWrongPasswordOrCorrupt) {
		t.Errorf("wrong password: %v", err)
	}
	notGzip, _ := backupcrypt.Encrypt("pw-1", []byte("plain text, not gzip"))
	if _, err := ParseBackup(notGzip, "pw-1"); err == nil {
		t.Error("decrypted content that is not a backup must be refused")
	}
}
