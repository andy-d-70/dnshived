// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"dnshived/internal/auditlog"
)

type auditCore struct {
	repl *auditRepl
	srv  *httptest.Server
}

// auditCluster starts n cores; reach[a][b] says whether a can reach b.
func auditCluster(t *testing.T, n int) ([]*auditCore, func(a, b int, ok bool)) {
	t.Helper()
	key, token := auditIdentity("cluster-psk")
	var mu sync.Mutex
	reach := map[[2]int]bool{}
	cores := make([]*auditCore, n)
	roles := make([]string, n)
	for i := range cores {
		roles[i] = fmt.Sprintf("core%d", i+1)
	}
	for i := range cores {
		st, err := auditlog.Open(filepath.Join(t.TempDir(), "auditstore"), auditlog.Options{Key: key})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		cores[i] = &auditCore{}
		self := i
		a := &auditRepl{st: st, token: token, scheme: "http", client: http.DefaultClient, self: roles[i],
			allow: func(*http.Request) bool { return true }, queue: make(chan auditlog.StoredEntry, auditPushQueue)}
		a.peers = func() []string {
			var out []string
			for j, r := range roles {
				if j != self {
					out = append(out, r)
				}
			}
			return out
		}
		a.addrOf = func(role string) (string, bool) {
			j := int(role[len(role)-1] - '1')
			mu.Lock()
			ok := reach[[2]int{self, j}]
			mu.Unlock()
			return strings.TrimPrefix(cores[j].srv.URL, "http://"), ok
		}
		mux := http.NewServeMux()
		a.routes(mux)
		cores[i].repl = a
		cores[i].srv = httptest.NewServer(mux)
		t.Cleanup(cores[i].srv.Close)
	}
	set := func(a, b int, ok bool) {
		mu.Lock()
		reach[[2]int{a, b}], reach[[2]int{b, a}] = ok, ok
		mu.Unlock()
	}
	for i := range cores {
		for j := range cores {
			set(i, j, true)
		}
	}
	return cores, set
}

func auditAppend(t *testing.T, c *auditCore, from, to int) {
	t.Helper()
	l := auditlog.New(filepath.Join(t.TempDir(), "audit.log"))
	l.Attach(c.repl.st, nil)
	for i := from; i < to; i++ {
		if err := l.Append("ann", c.repl.self, "config.save", fmt.Sprintf("change %d", i)); err != nil {
			t.Fatal(err)
		}
	}
}

func pullAll(t *testing.T, cores []*auditCore) {
	t.Helper()
	for _, c := range cores {
		for _, role := range c.repl.peers() {
			if _, err := c.repl.pullFrom(context.Background(), role); err != nil && !strings.Contains(err.Error(), "not reachable") {
				t.Fatalf("%s pulls from %s: %v", c.repl.self, role, err)
			}
		}
	}
}

func TestAuditRepl_PartitionedCoresHoldTheUnionAfterRejoin(t *testing.T) {
	cores, set := auditCluster(t, 3)
	set(0, 1, false)
	set(0, 2, false)
	auditAppend(t, cores[0], 0, 40)
	auditAppend(t, cores[1], 100, 130)
	auditAppend(t, cores[2], 200, 205)
	pullAll(t, cores)
	if cores[0].repl.st.Len() != 40 || cores[1].repl.st.Len() != 35 || cores[2].repl.st.Len() != 35 {
		t.Fatalf("while split, the reachable side merges and the lone core keeps its own: %d %d %d",
			cores[0].repl.st.Len(), cores[1].repl.st.Len(), cores[2].repl.st.Len())
	}
	set(0, 1, true)
	set(0, 2, true)
	pullAll(t, cores)
	want := cores[0].repl.st.Hashes()
	for _, c := range cores {
		if c.repl.st.Len() != 75 || c.repl.st.Hashes() != want {
			t.Fatalf("%s after rejoin: %d entries, same content %v", c.repl.self, c.repl.st.Len(), c.repl.st.Hashes() == want)
		}
	}
	pullAll(t, cores)
	if cores[1].repl.st.Len() != 75 {
		t.Fatal("a pull with nothing new adds nothing")
	}
}

func TestAuditRepl_PushDeliversANewEntryAtOnce(t *testing.T) {
	cores, _ := auditCluster(t, 2)
	l := auditlog.New(filepath.Join(t.TempDir(), "audit.log"))
	l.Attach(cores[0].repl.st, cores[0].repl.enqueue)
	if err := l.Append("ann", "core1", "config.save", "pushed"); err != nil {
		t.Fatal(err)
	}
	close(cores[0].repl.queue)
	cores[0].repl.pushLoop()
	if cores[1].repl.st.Len() != 1 || cores[1].repl.st.Hashes() != cores[0].repl.st.Hashes() {
		t.Fatal("the peer holds the pushed entry, byte for byte")
	}
}

func TestAuditRepl_RefusesAWrongTokenOrUntrustedHost(t *testing.T) {
	cores, _ := auditCluster(t, 1)
	for _, tc := range []struct {
		name, token string
		trusted     bool
	}{{"wrong token", "nope", true}, {"untrusted host", cores[0].repl.token, false}} {
		t.Run(tc.name, func(t *testing.T) {
			cores[0].repl.allow = func(*http.Request) bool { return tc.trusted }
			req := httptest.NewRequest(http.MethodPost, "/internal/audit/push", strings.NewReader(`{"entries":[{"id":"00000000000000000000000000000001","body":"e30="}]}`))
			req.Header.Set(auditTokenHeader, tc.token)
			rec := httptest.NewRecorder()
			cores[0].repl.guard(cores[0].repl.handlePush)(rec, req)
			if rec.Code != http.StatusForbidden || cores[0].repl.st.Len() != 0 {
				t.Fatalf("refused, nothing stored: %d %d", rec.Code, cores[0].repl.st.Len())
			}
		})
	}
}
