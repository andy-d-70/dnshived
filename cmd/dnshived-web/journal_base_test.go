// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/url"
	"testing"

	"dnshived/internal/cfgjournal"
	"dnshived/internal/config"
)

func TestBaseWithPageLoadRecords_OnlyTheLinesTheOperatorChangedCount(t *testing.T) {
	a := config.DNSRecord{Name: "a.lan", Type: "A", Value: "10.0.0.1"}
	b := config.DNSRecord{Name: "b.lan", Type: "A", Value: "10.0.0.2"}
	c := config.DNSRecord{Name: "c.lan", Type: "A", Value: "10.0.0.3"}
	current := config.Cluster{LogLevel: "info", GlobalDNSRecords: []config.DNSRecord{a, b}}
	form := url.Values{"orig_global_dns_records": {formatDNSRecordLines([]config.DNSRecord{a})}}
	cand := current
	cand.GlobalDNSRecords = []config.DNSRecord{a, c}

	ct, _ := cfgjournal.Replicated(&cand)
	bt, err := cfgjournal.DecodeTree(replicatedBase(baseWithPageLoadRecords(current, form, "")))
	if err != nil {
		t.Fatal(err)
	}
	changes, err := cfgjournal.FromChange("cluster", bt, ct, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Path != "global_dns_records/[c.lan|A]" || changes[0].Old != nil {
		t.Fatalf("only the added line counts, the colleague's record b stays untouched: %+v", changes)
	}
}

func TestClusterPushPayloadFrom_CarriesABaseThatCommitsDrop(t *testing.T) {
	p := clusterPushPayloadFrom(config.Cluster{LogLevel: "info"})
	if len(p.Base) == 0 {
		t.Fatal("a staged change carries the document it was made on")
	}
	if q := clusterPushPayloadNoBase(config.Cluster{LogLevel: "info"}); len(q.Base) != 0 {
		t.Fatal("the catch-up payload carries no base")
	}
}
