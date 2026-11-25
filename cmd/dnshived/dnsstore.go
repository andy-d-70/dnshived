// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash/fnv"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"dnshived/internal/agent"
	"dnshived/internal/auth"
	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/dnsanswer"
	"dnshived/internal/dnsdata"
	"dnshived/internal/dnsfeed"
	"dnshived/internal/dnsrepl"
	"dnshived/internal/dnsservice"
	"dnshived/internal/dnsstore"
	"dnshived/internal/dnsstore/vfs"
	"dnshived/internal/fsm"
	"dnshived/internal/loglevel"
	"dnshived/internal/ownership"
	"dnshived/internal/tlspin"
	"dnshived/internal/trustedhosts"
)

const dnsStoreEnableFile = "/etc/dnshived/dns-store.enable"

const dnsStoreNegTTL = 60

var dnsStoreSvc atomic.Pointer[dnsservice.Service]

// dnsConfigFrozen is true once the DNS store is authoritative: from then on the configuration's own DNS records are
// not the source any more, and a change to them would silently do nothing.
func dnsConfigFrozen() bool {
	svc := dnsStoreSvc.Load()
	return svc != nil && svc.Authoritative()
}

func dnsRecordsDigest(c *config.Cluster) string {
	b, _ := json.Marshal(dnsdata.ConfigRecords(c))
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func dnsStoreEnabled() bool {
	_, err := os.Stat(dnsStoreEnableFile)
	return err == nil
}

func dnsStoreInput() dnsservice.CompileInput {
	cfg := currentConfig.Load()
	in := dnsservice.CompileInput{NegTTL: dnsStoreNegTTL, Reserved: map[string]string{}}
	in.ReservedNames = dnsdata.ReservedNames(cfg)
	var domains []string
	for _, d := range cfg.LocalDomains {
		if c, err := dnsanswer.CanonicalName(d.Name); err == nil {
			domains = append(domains, c)
			in.Zones = append(in.Zones, dnsanswer.Zone{Name: c})
		}
	}
	for scope, sc := range cfg.Scopes {
		for _, r := range sc.Reservations {
			for _, n := range r.DNSNames() {
				c, err := dnsanswer.CanonicalName(n)
				if err != nil {
					continue
				}
				in.Reserved[c] = scope
				if !containsDot(c) {
					for _, d := range domains {
						in.Reserved[c+"."+d] = scope
					}
				}
			}
		}
	}
	return in
}

func containsDot(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return true
		}
	}
	return false
}

// dnsStoreLeases turns the merged DHCP lease table into names under the first local domain. A per-scope DNS domain is
// not part of the configuration yet; without a local domain the bare host name is published as before.
func dnsStoreLeases(ag *agent.Agent) []dnsdata.LeaseName {
	cfg := currentConfig.Load()
	suffix := ""
	if len(cfg.LocalDomains) > 0 {
		if c, err := dnsanswer.CanonicalName(cfg.LocalDomains[0].Name); err == nil {
			suffix = "." + c
		}
	}
	type scopePrefix struct {
		name   string
		prefix netip.Prefix
	}
	var prefixes []scopePrefix
	for name, sc := range cfg.Scopes {
		if p, err := netip.ParsePrefix(sc.VIP); err == nil {
			prefixes = append(prefixes, scopePrefix{name, p.Masked()})
		}
	}
	now := time.Now().Unix()
	var out []dnsdata.LeaseName
	for _, l := range ag.MergedDHCPLeaseSnapshot() {
		if l.Hostname == "" || containsDot(l.Hostname) || (l.ExpiresAt != 0 && l.ExpiresAt < now) {
			continue
		}
		ip, err := netip.ParseAddr(l.IP)
		if err != nil {
			continue
		}
		name, err := dnsanswer.CanonicalName(l.Hostname + suffix)
		if err != nil {
			continue
		}
		scope := ""
		for _, sp := range prefixes {
			if sp.prefix.Contains(ip) {
				scope = sp.name
				break
			}
		}
		out = append(out, dnsdata.LeaseName{Name: name, IP: ip, MAC: l.MAC, Scope: scope, LeasedAt: l.LeasedAt})
	}
	return out
}

// dnsStoreIdentity derives, from the cluster PSK, the store key, the store id and the replication token, so every
// core builds the same chain without a key exchange. A dedicated replicated store key replaces this later.
func dnsStoreIdentity(psk string) (keys dnsstore.Keys, id dnsstore.ID, token string) {
	derive := func(label string) []byte {
		m := hmac.New(sha256.New, []byte(psk))
		m.Write([]byte(label))
		return m.Sum(nil)
	}
	keys = dnsstore.StaticKeys{Cur: 1, Epochs: map[uint32][]byte{1: derive("dnshived-dnsstore-key-v1")}}
	copy(id[:], derive("dnshived-dnsstore-id-v1"))
	return keys, id, hex.EncodeToString(derive("dnshived-dnsrepl-token-v1"))
}

var allCoreRoles = []string{config.RoleCore1, config.RoleCore2, config.RoleCore3}

func dnsVoters(cfg *config.Cluster) []string {
	n := len(cfg.Peers) + 1
	if n > len(allCoreRoles) {
		n = len(allCoreRoles)
	}
	return allCoreRoles[:n]
}

func dnsMembership(ids []string) uint64 {
	h := fnv.New64a()
	for _, id := range ids {
		h.Write([]byte(id))
		h.Write([]byte{0})
	}
	return h.Sum64()
}

// startDNSStore opens the DNS store and registers its admin API when the switch file exists. On a cluster with a PSK
// the store is replicated between the cores; otherwise it runs alone with a local key file.
func startDNSStore(mux *http.ServeMux, authMw *auth.Middleware, ag *agent.Agent, machine *fsm.Machine, observer *cluster.Observer, trusted []string) {
	if !dnsStoreEnabled() {
		return
	}
	cfg := currentConfig.Load()
	dir := dataDir(cfg)
	storeDir := filepath.Join(dir, "dnsstore")
	replicated := cfg.PSK != "" && isCoreRole(cfg.Role)
	var keys dnsstore.Keys
	var storeID dnsstore.ID
	var token string
	var err error
	if replicated {
		keys, storeID, token = dnsStoreIdentity(cfg.PSK)
	} else if keys, err = dnsservice.LoadOrCreateKey(filepath.Join(dir, "dnsstore.key")); err != nil {
		loglevel.Warnf("[DNSSTORE:ERROR] key: %v", err)
		return
	}
	st, err := dnsstore.Open(storeDir, dnsstore.Options{Keys: keys, Create: true, StoreID: storeID})
	if err != nil {
		loglevel.Warnf("[DNSSTORE:ERROR] open %s: %v (a store created before replication was switched on has another identity and must be removed)", storeDir, err)
		return
	}
	opts := dnsservice.Options{
		Dir:       storeDir,
		TablePath: filepath.Join(dir, "dnstable.bin"),
		Keys:      keys,
		Store:     st,
		Input:     dnsStoreInput,
		Leases:    func() []dnsdata.LeaseName { return dnsStoreLeases(ag) },
		Log:       func(f string, a ...any) { loglevel.Infof(f, a...) },
		Chown:     ownership.Dnshived,

		ImportSource: func() []config.DNSRecord { return dnsdata.ConfigRecords(currentConfig.Load()) },
		OnServing: func(ok bool) {
			loglevel.Infof("[DNSSTORE:SERVING] this core %s DNS from the store", map[bool]string{true: "can serve", false: "cannot serve"}[ok])
		},
	}
	var svc *dnsservice.Service
	var drv *dnsrepl.Driver
	if replicated {
		ids := dnsVoters(cfg)
		var peers []string
		self := false
		for _, id := range ids {
			if id == cfg.Role {
				self = true
			} else {
				peers = append(peers, id)
			}
		}
		if !self {
			loglevel.Warnf("[DNSSTORE:ERROR] this node's role %q is not one of the cluster's voters %v; replication is off", cfg.Role, ids)
			_ = st.Close()
			return
		}
		node, err := dnsrepl.New(dnsrepl.Config{ID: cfg.Role, Peers: peers, Membership: dnsMembership(ids)}, st, vfs.OS{}, storeDir)
		if err != nil {
			loglevel.Warnf("[DNSSTORE:ERROR] replication: %v", err)
			_ = st.Close()
			return
		}
		scheme := "http"
		client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}}
		if cfg.TLSEnabled() {
			scheme = "https"
			client.Transport.(*http.Transport).TLSClientConfig = tlspin.Config()
		}
		addrOf := func(role string) (string, bool) {
			if role == cfg.Role {
				return cfg.ListenAddr(), true
			}
			ok, addr := observer.RoleReachable(role)
			return addr, ok && addr != ""
		}
		tr := &dnsrepl.HTTPTransport{Client: client, Scheme: scheme, Token: token, Addr: addrOf}
		drv = dnsrepl.NewDriver(node, tr, dnsrepl.DriverConfig{
			Permit: func() bool { return machine.Snapshot().State == fsm.StateStable },
			OnCommit: func() {
				if svc != nil {
					svc.Kick()
				}
			},
			Log: func(f string, a ...any) { loglevel.Infof(f, a...) },
		})
		allowed := trustedhosts.New(trusted)
		drv.Routes(mux, token, func(r *http.Request) bool { return allowed.Allowed(r.RemoteAddr) })
		opts.Propose = drv.Propose
		opts.LeaderAddr = func(role string) string { a, _ := addrOf(role); return a }
		opts.ReplStatus = func() any {
			return map[string]any{"role": node.Role().String(), "term": node.Term(), "leader": node.Leader(), "self": cfg.Role, "voters": ids}
		}
	}
	var feed *dnsfeed.Publisher
	if dnsFeedEnabled() {
		feed = dnsfeed.NewPublisher(dnsfeed.Options{Log: func(f string, a ...any) { loglevel.Infof(f, a...) }})
		opts.Feed = feed
	}
	svc, err = dnsservice.New(opts)
	if err != nil {
		loglevel.Warnf("[DNSSTORE:ERROR] %v", err)
		if drv != nil {
			_ = st.Close()
		}
		return
	}
	dnsStoreSvc.Store(svc)
	if feed != nil {
		if err := startDNSFeed(context.Background(), filepath.Join(dir, "dnsfeed.sock"), feed); err != nil {
			loglevel.Warnf("[DNSFEED:ERROR] %v", err)
		}
	}
	svc.Routes(mux, authMw.RequireAdmin)
	if drv != nil {
		drv.Start()
	}
	loglevel.Infof("[DNSSTORE:START] DNS store open at revision %d (replicated: %v), table published at %s", st.View().Rev(), drv != nil, filepath.Join(dir, "dnstable.bin"))
}
