// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"html/template"
)

// TestDNSStoreRender writes the page for a few states to DNSSTORE_RENDER_DIR so they can be looked at in a browser.
func TestDNSStoreRender(t *testing.T) {
	dir := os.Getenv("DNSSTORE_RENDER_DIR")
	if dir == "" {
		t.Skip("set DNSSTORE_RENDER_DIR to render")
	}
	st := &dsStatus{Rev: 1234, Commit: 1234, Head: 1234, Hosts: 4210, Records: 380, Published: &dsPublished{Names: 8800, Records: 9100}}
	st.Replication = &struct {
		Role   string   `json:"role"`
		Leader string   `json:"leader"`
		Self   string   `json:"self"`
		Term   uint64   `json:"term"`
		Voters []string `json:"voters"`
	}{Role: "follower", Leader: "core-1", Self: "core-2", Term: 12, Voters: []string{"core1", "core2", "core3"}}
	top, bottom := newPagerBars("/dns/store", map[string][]string{"kind": {"hosts"}}, "10", 4210, 1, 421, 0, 10)
	top.Show = true
	var hosts []dsHostRow
	for i := 0; i < 10; i++ {
		hosts = append(hosts, dsHostRow{ID: strings.Repeat("a", 32), Label: "camera-" + strings.Repeat("x", i*4), Domains: "example.lan, lab.example.lan, av.example.lan, a-very-long-domain-name.example.lan", Addrs: "10.20.30.4" + string(rune('0'+i)) + ", fd00:20:30::4" + string(rune('0'+i)), TTL: uint32(i * 100)})
	}
	base := dsPage{Tabs: template.HTML(dnsTabs("/dns/store")), Enabled: true, Status: st, Mode: "overlay: records in the store are answered, everything else is forwarded", Leader: "core-1", Kind: "hosts",
		Nodes: []dsNodeRow{{Name: "core-1", Role: "leader", Head: "1234", Commit: "1234"}, {Name: "core-2", Role: "follower", Head: "1234", Commit: "1234"}, {Name: "core-3", Err: "not enabled"}},
		Hosts: hosts, Total: 4210, PagerTop: top, PagerBottom: bottom, Chips: []listChip{{Label: "Hosts 4210", URL: "/dns/store?kind=hosts", Active: true}, {Label: "Records 380", URL: "/dns/store?kind=records"}}}
	warn := base
	warn.Msg = "added host nas"
	warn.Err = "cam.example.lan is already used by another host; a very long reason that goes on and on so that the line is long enough to show how the banner copes with it"
	p := *st.Published
	for i := 0; i < 145; i++ {
		p.RowErrors = append(p.RowErrors, "record "+strings.Repeat("x", i%7)+" is skipped")
	}
	p.RowErrN = 145
	p.Error = "write /var/lib/dnshived/dnstable.bin: no space left on device"
	wst := *st
	wst.Published = &p
	warn.Status = &wst
	empty := dsPage{Tabs: template.HTML(dnsTabs("/dns/store"))}
	for name, d := range map[string]dsPage{"normal": base, "warnings": warn, "disabled": empty} {
		f, err := os.Create(filepath.Join(dir, name+".html"))
		if err != nil {
			t.Fatal(err)
		}
		if err := dsTmpl.Execute(f, d); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
}
