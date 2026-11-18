// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"dnshived/internal/access"
)

type accessStateResult struct {
	Active   bool           `json:"active"`
	Required string         `json:"required"`
	Blocking []accessBlock  `json:"blocking,omitempty"`
	Mode     string         `json:"mode"`
	List     *access.Config `json:"list,omitempty"`
	Always   []string       `json:"always,omitempty"`
	DNS      access.Report  `json:"dns"`
	DHCP     access.Report  `json:"dhcp"`
}

type accessBlock struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Reason  string `json:"reason"`
}

func fetchAccessState(node NodeConfig) (accessStateResult, error) {
	var s accessStateResult
	status, err := doGet(httpClient, node, "/api/v1/access", &s)
	if err != nil {
		return s, err
	}
	if status != 200 {
		return s, fmt.Errorf("status %d", status)
	}
	return s, nil
}

type webAccess struct {
	m      atomic.Pointer[access.Matcher]
	rep    *access.Reporter
	failed atomic.Int64
}

var webAccessState = &webAccess{rep: access.NewReporter(0)}

func (w *webAccess) permit(r *http.Request) bool {
	m := w.m.Load()
	if m == nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return true
	}
	if m.Check(access.Web, addr).Allowed {
		return true
	}
	w.rep.Add(access.Web, addr, time.Now())
	if !m.Enforcing() {
		return true
	}
	w.failed.Add(1)
	return false
}

// accessGuard drops the connection of a source the access list does not allow: no response at all.
func accessGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if !webAccessState.permit(r) {
			panic(http.ErrAbortHandler)
		}
		next.ServeHTTP(rw, r)
	})
}

// refresh reads the list from the first node that answers. The list only applies once every core can enforce it
// (the daemon says so); a node that cannot be reached leaves the last list in place.
func (w *webAccess) refresh(cfg *WebConfig) {
	for _, n := range nodesIncludingSelf(cfg) {
		st, err := fetchAccessState(n)
		if err != nil {
			continue
		}
		if !st.Active || st.List == nil {
			w.m.Store(nil)
			return
		}
		always := append([]string(nil), st.Always...)
		for _, nn := range nodesIncludingSelf(cfg) {
			if host, _, err := net.SplitHostPort(nn.Addr); err == nil {
				always = append(always, host)
			}
		}
		var addrs []netip.Addr
		for _, a := range always {
			if ip, err := netip.ParseAddr(a); err == nil {
				addrs = append(addrs, ip)
			}
		}
		m, err := access.New(st.List, addrs)
		if err != nil {
			log.Printf("[ACCESS] list ignored: %v", err)
			w.m.Store(nil)
			return
		}
		w.m.Store(m)
		return
	}
}

// primeAccess loads the list once before the listeners open, so a restart does not leave a window in which
// everyone is served. It waits at most three seconds; a daemon that does not answer leaves the list empty until
// the next refresh.
func primeAccess(ref *configRef) {
	done := make(chan struct{})
	go func() {
		webAccessState.refresh(ref.Load())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

func runAccessRefresh(ctx context.Context, ref *configRef) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			webAccessState.refresh(ref.Load())
		}
	}
}
