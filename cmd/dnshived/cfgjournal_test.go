// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"dnshived/internal/auth"
	"dnshived/internal/cfgjournal"
	"dnshived/internal/config"
	"dnshived/internal/dnsrepl"
	"dnshived/internal/dnsstore"
	"dnshived/internal/dnsstore/vfs"
)

// singleCoreJournal runs the journal of a one-core cluster against the config at path, as the daemon does.
func singleCoreJournal(t *testing.T, path string) *cfgJournalRuntime {
	t.Helper()
	keys, storeID, token := cfgJournalIdentity(testPSK)
	dir := filepath.Join(t.TempDir(), "cfgjournal")
	st, err := dnsstore.Open(dir, dnsstore.Options{Keys: keys, Create: true, StoreID: storeID})
	if err != nil {
		t.Fatal(err)
	}
	node, err := dnsrepl.New(dnsrepl.Config{ID: config.RoleCore1, Membership: dnsMembership([]string{config.RoleCore1})}, st, vfs.OS{}, dir)
	if err != nil {
		t.Fatal(err)
	}
	j := &cfgJournalRuntime{path: path, store: st, node: node, token: token, scheme: "http", client: &http.Client{}, addrOf: func(string) (string, bool) { return "", false }, kick: make(chan struct{}, 1)}
	drv := j.build()
	drv.Start()
	deadline := time.Now().Add(10 * time.Second)
	for node.Role() != dnsrepl.Leader {
		if time.Now().After(deadline) {
			t.Fatal("the only core never took the lead")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cfgJournal.Store(j)
	t.Cleanup(func() {
		cfgJournal.Store(nil)
		drv.Stop()
		_ = st.Close()
	})
	return j
}

func officeUpdate(logLevel string) configUpdate {
	return configUpdate{
		PSK: testPSK, Platform: testPlatform(), LogLevel: logLevel, Author: "ann",
		Scopes: map[string]config.ScopeConfig{
			"office": {
				Parent: "ens19", VLANID: 100, VIP: "192.168.100.1/24",
				DHCPRange: [2]string{"192.168.100.100", "192.168.100.200"},
				Gateway:   "192.168.100.1", VRRPID: 51, PreferredWorker: config.RoleCore1,
			},
		},
	}
}

func TestConfigJournal_APushGoesThroughTheJournalOnce(t *testing.T) {
	path := writeBaseConfig(t)
	j := singleCoreJournal(t, path)
	if status, body := applyConfigUpdate(path, officeUpdate("info"), nil, nil, nil); status != http.StatusOK {
		t.Fatalf("status %d %v", status, body)
	}
	c, err := config.Load(path)
	if err != nil || !c.HasScopes() || c.LogLevel != "info" {
		t.Fatalf("not applied: %v", err)
	}
	_, rev, _, err := j.doc.Load()
	if err != nil || rev == 0 {
		t.Fatalf("the file holds journal revision %d: %v", rev, err)
	}
	if c.PSK != testPSK || c.Role != config.RoleCore1 {
		t.Fatal("own fields must stay")
	}
	if status, _ := applyConfigUpdate(path, officeUpdate("info"), nil, nil, nil); status != http.StatusOK {
		t.Fatalf("the same push again (the web sends it to every core) must succeed: %d", status)
	}
	if _, again, _, _ := j.doc.Load(); again != rev {
		t.Fatalf("the same push again must not add a change: %d -> %d", rev, again)
	}
	if status, _ := applyConfigUpdate(path, officeUpdate("debug"), nil, nil, nil); status != http.StatusOK {
		t.Fatalf("a real change: %d", status)
	}
	if c, _ := config.Load(path); c.LogLevel != "debug" || c.ConfigRevision != 2 {
		t.Fatalf("second change: level %q revision %d", c.LogLevel, c.ConfigRevision)
	}
	catchUp := officeUpdate("warn")
	catchUp.ConfigCatchUp, catchUp.ConfigRevision = true, 99
	if status, _ := applyConfigUpdate(path, catchUp, nil, nil, nil); status != http.StatusConflict {
		t.Fatalf("a catch-up push is refused while the journal runs: %d", status)
	}
}

func TestConfigJournal_InvalidResultIsRefusedAndNothingChanges(t *testing.T) {
	path := writeBaseConfig(t)
	singleCoreJournal(t, path)
	upd := officeUpdate("info")
	sc := upd.Scopes["office"]
	sc.VLANID = 9999
	upd.Scopes["office"] = sc
	if status, _ := applyConfigUpdate(path, upd, nil, nil, nil); status == http.StatusOK {
		t.Fatal("an invalid configuration must be refused")
	}
	if c, _ := config.Load(path); c.HasScopes() {
		t.Fatal("a refused change must not reach the file")
	}
}

type testCore struct {
	j   *cfgJournalRuntime
	drv *dnsrepl.Driver
	srv *httptest.Server
}

// threeCores runs the journal of a three-core cluster in one process: every core has its own configuration file,
// store and HTTP endpoint, and they replicate to each other as the daemons do.
func threeCores(t *testing.T) []*testCore {
	t.Helper()
	roles := []string{config.RoleCore1, config.RoleCore2, config.RoleCore3}
	keys, storeID, token := cfgJournalIdentity(testPSK)
	addrs := map[string]string{}
	var mu sync.Mutex
	cores := make([]*testCore, 3)
	for i, role := range roles {
		path := writeBaseConfig(t)
		c, _ := config.Load(path)
		c.Role = role
		if err := config.Save(path, c); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "cfgjournal")
		st, err := dnsstore.Open(dir, dnsstore.Options{Keys: keys, Create: true, StoreID: storeID})
		if err != nil {
			t.Fatal(err)
		}
		var peers []string
		for _, r := range roles {
			if r != role {
				peers = append(peers, r)
			}
		}
		node, err := dnsrepl.New(dnsrepl.Config{ID: role, Peers: peers, Membership: dnsMembership(roles)}, st, vfs.OS{}, dir)
		if err != nil {
			t.Fatal(err)
		}
		addrOf := func(r string) (string, bool) {
			mu.Lock()
			defer mu.Unlock()
			a, ok := addrs[r]
			return a, ok
		}
		j := &cfgJournalRuntime{path: path, store: st, node: node, token: token, scheme: "http", client: &http.Client{Timeout: 5 * time.Second}, addrOf: addrOf, kick: make(chan struct{}, 1)}
		drv := j.build()
		mux := http.NewServeMux()
		allow := func(*http.Request) bool { return true }
		drv.RoutesAt(mux, cfgJournalReplPrefix, token, allow)
		mux.HandleFunc("POST "+cfgJournalProposePath, j.handlePropose(allow))
		authMw := auth.New([]config.APIToken{{Name: "admin", Token: "admin-token-for-the-test-only-0123456789", Role: "admin"}})
		srv := httptest.NewServer(authMw.Wrap(mux))
		mu.Lock()
		addrs[role] = srv.Listener.Addr().String()
		mu.Unlock()
		cores[i] = &testCore{j: j, drv: drv, srv: srv}
	}
	for _, c := range cores {
		c.drv.Start()
	}
	t.Cleanup(func() {
		for _, c := range cores {
			c.drv.Stop()
			c.srv.Close()
			_ = c.j.store.Close()
		}
	})
	deadline := time.Now().Add(15 * time.Second)
	for {
		leaders := 0
		for _, c := range cores {
			if c.j.node.Role() == dnsrepl.Leader {
				leaders++
			}
		}
		if leaders == 1 {
			return cores
		}
		if time.Now().After(deadline) {
			t.Fatal("no single leader")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func follower(cores []*testCore) *testCore {
	for _, c := range cores {
		if c.j.node.Role() != dnsrepl.Leader {
			return c
		}
	}
	return nil
}

func TestConfigJournal_AChangeAtAFollowerReachesEveryCore(t *testing.T) {
	cores := threeCores(t)
	f := follower(cores)
	before, _ := config.Load(f.j.path)
	after, _ := config.Load(f.j.path)
	after.LogLevel = "debug"
	after.GlobalDNSRecords = []config.DNSRecord{{Name: "ntp.lan", Type: "A", Value: "10.0.0.9"}}
	lt, _ := cfgjournal.Replicated(before)
	at, _ := cfgjournal.Replicated(after)
	entries, _ := cfgjournal.FromChange(cfgJournalDoc, lt, at, 0)
	res, err := f.j.propose(cfgjournal.Meta{Author: "ann"}, entries)
	if err != nil || res.Rev == 0 {
		t.Fatalf("propose at a follower: %+v %v", res, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for _, c := range cores {
		for {
			_, _, _ = c.j.writer.Sync()
			got, _ := config.Load(c.j.path)
			if got.LogLevel == "debug" && len(got.GlobalDNSRecords) == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s never got the change", got.Role)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	stale, _ := cfgjournal.FromChange(cfgJournalDoc, lt, func() any {
		x := *before
		x.LogLevel = "warn"
		r, _ := cfgjournal.Replicated(&x)
		return r
	}(), 0)
	other := follower(cores)
	if _, err := other.j.propose(cfgjournal.Meta{Author: "bob"}, stale); !errors.Is(err, cfgjournal.ErrConflict) {
		t.Fatalf("a change computed before the first one landed must be refused: %v", err)
	}
	for _, c := range cores {
		if got, _ := config.Load(c.j.path); got.LogLevel != "debug" {
			t.Fatalf("%s lost the first change: %q", got.Role, got.LogLevel)
		}
	}
}

func TestConfigJournal_StatusShowsRoleAndAppliedRevision(t *testing.T) {
	if cfgJournalStatus() != nil {
		t.Fatal("the status has no journal part while the journal is off")
	}
	path := writeBaseConfig(t)
	j := singleCoreJournal(t, path)
	if status, body := applyConfigUpdate(path, officeUpdate("info"), nil, nil, nil); status != http.StatusOK {
		t.Fatalf("push: %d %v", status, body)
	}
	st := cfgJournalStatus()
	_, rev, _, _ := j.doc.Load()
	if st == nil || st["role"] != "leader" || st["leader"] != config.RoleCore1 || st["applied_rev"] != rev || st["last_error"] != "" {
		t.Fatalf("status %v, file at %d", st, rev)
	}
}
