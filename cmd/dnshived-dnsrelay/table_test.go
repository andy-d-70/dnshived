// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dnsrelay/dnsanswer"
)

func tableQuery(name string, typ uint16) []byte {
	q := []byte{0xAB, 0xCD, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, byte(typ>>8), byte(typ), 0, 1)
}

func testTable(t *testing.T) *dnsanswer.Table {
	t.Helper()
	b := dnsanswer.NewBuilder()
	if err := b.AddZone("example.lan", false); err != nil {
		t.Fatal(err)
	}
	rd, _ := dnsanswer.RDataA("10.0.0.5")
	if err := b.Add(dnsanswer.RR{Owner: "cam.example.lan", Type: dnsanswer.TypeA, TTL: 300, RData: rd}); err != nil {
		t.Fatal(err)
	}
	tb, err := b.Build(7, 60)
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

func TestLocalTable_UDPAnswersWithoutForwarding(t *testing.T) {
	localTable.Store(testTable(t))
	t.Cleanup(func() { localTable.Store(nil) })
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	before := localAnsweredTotal.Load()
	if _, err := cli.Write(tableQuery("cam.example.lan", dnsanswer.TypeA)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	_ = srv.SetReadDeadline(time.Now().Add(time.Second))
	n, from, err := srv.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	processUDPQuery(srv, buf[:n], from, nil)
	_ = cli.SetReadDeadline(time.Now().Add(time.Second))
	n, err = cli.Read(buf)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	if n < 12 || binary.BigEndian.Uint16(buf[6:]) != 1 || buf[3]&0xF != 0 || buf[2]&0x04 == 0 {
		t.Fatalf("answer %x", buf[:n])
	}
	if localAnsweredTotal.Load() != before+1 {
		t.Fatal("the local answer must be counted")
	}
}

func TestTableLoop_LoadsKeepsOnDamageAndReloads(t *testing.T) {
	localTable.Store(nil)
	t.Cleanup(func() { localTable.Store(nil) })
	path := filepath.Join(t.TempDir(), "dnstable.bin")
	spec := &dnsanswer.Spec{Zones: []dnsanswer.Zone{{Name: "example.lan"}}, Serial: 1, NegTTL: 60}
	tb, _ := spec.Build()
	if err := os.WriteFile(path, dnsanswer.EncodeTable(spec, tb.Digest()), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setTablePath(path)
	t.Cleanup(func() { setTablePath("") })
	go tableLoop(ctx)
	wait := func(cond func() bool, what string) {
		t.Helper()
		for i := 0; i < 50; i++ {
			if cond() {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", what)
	}
	wait(func() bool { return localTable.Load() != nil }, "the first load")
	first := localTable.Load()
	if err := os.WriteFile(path, []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if localTable.Load() != first {
		t.Fatal("a damaged file must leave the table in use alone")
	}
	spec2 := &dnsanswer.Spec{Zones: []dnsanswer.Zone{{Name: "example.lan"}, {Name: "other.lan"}}, Serial: 2, NegTTL: 60}
	tb2, _ := spec2.Build()
	if err := os.WriteFile(path, dnsanswer.EncodeTable(spec2, tb2.Digest()), 0o600); err != nil {
		t.Fatal(err)
	}
	wait(func() bool { return localTable.Load() != first }, "the reload")
	setTablePath("")
	wait(func() bool { return localTable.Load() == nil }, "the table to be dropped when the path is cleared")
}
