// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsservice

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"dnshived/internal/dnsanswer"
	"dnshived/internal/dnsdata"
	"dnshived/internal/dnsrepl"
	"dnshived/internal/dnsstore"
	"dnshived/internal/dnsstore/vfs"
)

type clusterNode struct {
	id   string
	dir  string
	st   *dnsstore.Store
	drv  *dnsrepl.Driver
	svc  *Service
	srv  *httptest.Server
	mux  *http.ServeMux
	addr string
}

type cluster struct {
	t     *testing.T
	ids   []string
	root  string
	mu    sync.Mutex
	addrs map[string]string
	nodes map[string]*clusterNode
}

func keysFor() dnsstore.Keys {
	return dnsstore.StaticKeys{Cur: 1, Epochs: map[uint32][]byte{1: []byte("0123456789abcdef0123456789abcdef")}}
}

func newCluster(t *testing.T) *cluster {
	c := &cluster{t: t, ids: []string{"core1", "core2", "core3"}, root: t.TempDir(), addrs: map[string]string{}, nodes: map[string]*clusterNode{}}
	t.Cleanup(func() {
		for id := range c.nodes {
			c.stop(id)
		}
	})
	return c
}

func (c *cluster) start(id string) *clusterNode {
	c.t.Helper()
	dir := filepath.Join(c.root, id)
	_ = os.MkdirAll(dir, 0o700)
	st, err := dnsstore.Open(filepath.Join(dir, "dnsstore"), dnsstore.Options{Keys: keysFor(), Create: true, StoreID: dnsstore.ID{9, 9}})
	if err != nil {
		c.t.Fatal(err)
	}
	var peers []string
	for _, o := range c.ids {
		if o != id {
			peers = append(peers, o)
		}
	}
	node, err := dnsrepl.New(dnsrepl.Config{ID: id, Peers: peers, Membership: 1}, st, vfs.OS{}, filepath.Join(dir, "dnsstore"))
	if err != nil {
		c.t.Fatal(err)
	}
	n := &clusterNode{id: id, dir: dir, st: st, mux: http.NewServeMux()}
	tr := &dnsrepl.HTTPTransport{Client: &http.Client{Timeout: 3 * time.Second}, Scheme: "http", Token: "t", Addr: func(p string) (string, bool) {
		c.mu.Lock()
		defer c.mu.Unlock()
		a, ok := c.addrs[p]
		return a, ok
	}}
	n.drv = dnsrepl.NewDriver(node, tr, dnsrepl.DriverConfig{Tick: 10 * time.Millisecond, Heartbeat: 30 * time.Millisecond, ElectionMin: 200 * time.Millisecond, ElectionMax: 500 * time.Millisecond, OnCommit: func() {
		c.mu.Lock()
		cn := c.nodes[id]
		c.mu.Unlock()
		if cn != nil && cn.svc != nil {
			cn.svc.Kick()
		}
	}})
	n.drv.Routes(n.mux, "t", nil)
	svc, err := New(Options{
		Dir: filepath.Join(dir, "dnsstore"), TablePath: filepath.Join(dir, "dnstable.bin"), Store: st,
		Input: func() CompileInput {
			return CompileInput{Zones: []dnsanswer.Zone{{Name: "example.lan"}}, DefaultTTL: 300, NegTTL: 60}
		},
		Leases:  func() []dnsdata.LeaseName { return nil },
		Propose: n.drv.Propose,
		LeaderAddr: func(l string) string {
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.addrs[l]
		},
	})
	if err != nil {
		c.t.Fatal(err)
	}
	n.svc = svc
	svc.Routes(n.mux, func(h http.HandlerFunc) http.HandlerFunc { return h })
	n.srv = httptest.NewServer(n.mux)
	n.addr = n.srv.Listener.Addr().String()
	c.mu.Lock()
	c.addrs[id] = n.addr
	c.nodes[id] = n
	c.mu.Unlock()
	n.drv.Start()
	return n
}

func (c *cluster) stop(id string) {
	c.mu.Lock()
	n := c.nodes[id]
	delete(c.nodes, id)
	c.mu.Unlock()
	if n == nil {
		return
	}
	n.drv.Stop()
	n.srv.Close()
	_ = n.svc.Close()
	_ = n.st.Close()
}

func (c *cluster) leader() *clusterNode {
	c.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		for _, n := range c.nodes {
			if n.drv.Node().Role() == dnsrepl.Leader {
				c.mu.Unlock()
				return n
			}
		}
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	c.t.Fatal("no leader")
	return nil
}

func post(t *testing.T, addr, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post("http://"+addr+"/api/v1/dnsstore/commit", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func replHostJSON(label, ip string) string {
	return fmt.Sprintf(`{"author":"t","ops":[{"op":"put","kind":"host","host":{"label":%q,"domains":["example.lan"],"addrs":[{"ip":%q,"ptr":true}]}}]}`, label, ip)
}

func (c *cluster) waitTables(want int, ids ...string) {
	c.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var digest [32]byte
		ok := true
		for i, id := range ids {
			c.mu.Lock()
			n := c.nodes[id]
			c.mu.Unlock()
			b, err := os.ReadFile(filepath.Join(n.dir, "dnstable.bin"))
			if err != nil {
				ok = false
				break
			}
			tb, _, err := dnsanswer.DecodeTable(b)
			if err != nil || tb.Records() < want {
				ok = false
				break
			}
			if i == 0 {
				digest = tb.Digest()
			} else if tb.Digest() != digest {
				ok = false
				break
			}
		}
		if ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	c.t.Fatalf("the published tables on %v did not become identical with at least %d records", ids, want)
}

func TestReplicatedService_WritesThroughTheLeaderPublishEverywhere(t *testing.T) {
	c := newCluster(t)
	for _, id := range c.ids {
		c.start(id)
	}
	lead := c.leader()
	for i := 1; i <= 5; i++ {
		if code, out := post(t, lead.addr, replHostJSON(fmt.Sprintf("host-%d", i), fmt.Sprintf("10.0.0.%d", i))); code != 200 {
			t.Fatalf("commit %d: %d %v", i, code, out)
		}
	}
	c.waitTables(10, "core1", "core2", "core3")

	for _, id := range c.ids {
		if id == lead.id {
			continue
		}
		code, out := post(t, c.nodes[id].addr, replHostJSON("nope", "10.9.9.9"))
		if code != 409 || out["error"] != "not_leader" || out["leader"] != lead.id || out["leader_addr"] != lead.addr {
			t.Fatalf("%s: %d %v", id, code, out)
		}
	}
	code, out := post(t, lead.addr, replHostJSON("host-1", "10.0.0.50"))
	if code != 422 {
		t.Fatalf("the gate runs on the leader: %d %v", code, out)
	}

	dead := lead.id
	c.stop(dead)
	var rest []string
	for _, id := range c.ids {
		if id != dead {
			rest = append(rest, id)
		}
	}
	var nl *clusterNode
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		c.mu.Lock()
		for _, n := range c.nodes {
			if n.drv.Node().Role() == dnsrepl.Leader {
				nl = n
			}
		}
		c.mu.Unlock()
		if nl != nil {
			break
		}
	}
	if nl == nil {
		t.Fatal("no new leader after the old one stopped")
	}
	if code, out := post(t, nl.addr, replHostJSON("after-failover", "10.0.1.1")); code != 200 {
		t.Fatalf("write after failover: %d %v", code, out)
	}
	c.waitTables(12, rest...)
	c.start(dead)
	c.waitTables(12, "core1", "core2", "core3")
	b, _ := os.ReadFile(filepath.Join(c.root, dead, "dnstable.bin"))
	tb, _, _ := dnsanswer.DecodeTable(b)
	q := query("after-failover.example.lan", dnsanswer.TypeA)
	out2, st := tb.Respond(q, nil, false)
	if st != dnsanswer.Answered || out2[3]&0xF != 0 || out2[7] != 1 {
		t.Fatal("the restarted node must serve the record written while it was down")
	}
}
