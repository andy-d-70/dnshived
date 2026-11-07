// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"dnshived/internal/activation"
	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/identity"
	"dnshived/internal/quorum"
)

func up(addr string, rev int64, hash string) peerView {
	return peerView{Addr: addr, Reachable: true, Known: true, Version: "0.9.8.9-3+abc", Revision: rev, Hash: hash}
}

func TestPeerViews(t *testing.T) {
	snap := []cluster.PeerState{
		{Addr: "b:1", Reachable: true, Identity: &identity.Identity{Version: "v", ConfigRevision: 4, ConfigHash: "h", MembershipEpoch: 2}},
		{Addr: "a:1"},
	}
	got := peerViews(snap)
	if len(got) != 2 || got[0].Addr != "a:1" || got[0].Known || got[1].Revision != 4 || got[1].MembershipEpoch != 2 || !got[1].Known {
		t.Errorf("views = %+v", got)
	}
}

func TestPeersRunAtLeast(t *testing.T) {
	const need = activation.OutageRulesVersion
	newV, oldV := "0.9.8.9-3+abc", "0.9.8.8+abc"
	tests := []struct {
		name       string
		self       string
		configured int
		peers      []peerView
		ok         bool
	}{
		{"all new", newV, 2, []peerView{{Addr: "a", Known: true, Version: newV}, {Addr: "b", Known: true, Version: newV}}, true},
		{"release builds count", "0.9.8.9+abc", 1, []peerView{{Addr: "a", Known: true, Version: "0.9.9.0+x"}}, true},
		{"one old", newV, 2, []peerView{{Addr: "a", Known: true, Version: newV}, {Addr: "b", Known: true, Version: oldV}}, false},
		{"one never seen", newV, 2, []peerView{{Addr: "a", Known: true, Version: newV}, {Addr: "b"}}, false},
		{"self old", oldV, 1, []peerView{{Addr: "a", Known: true, Version: newV}}, false},
		{"peer missing from the observer", newV, 2, []peerView{{Addr: "a", Known: true, Version: newV}}, false},
		{"unreadable version", newV, 1, []peerView{{Addr: "a", Known: true, Version: "garbage"}}, false},
		{"standalone", newV, 0, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, blocking := peersRunAtLeast(tt.self, need, tt.configured, tt.peers)
			if ok != tt.ok {
				t.Errorf("ok = %v (%v), want %v", ok, blocking, tt.ok)
			}
			if !ok && len(blocking) == 0 {
				t.Error("a refusal must name what blocks it")
			}
		})
	}
}

func TestConfigVerdict(t *testing.T) {
	tests := []struct {
		name       string
		selfRev    int64
		selfHash   string
		configured int
		peers      []peerView
		since      time.Duration
		want       string
		hold       bool
	}{
		{"standalone", 3, "h", 0, nil, 0, cfgVerified, false},
		{"peer agrees", 5, "h5", 2, []peerView{up("a", 5, "h5")}, time.Second, cfgVerified, false},
		{"peer behind us", 5, "h5", 2, []peerView{up("a", 3, "h3")}, time.Second, cfgVerified, false},
		{"peer ahead with other content", 3, "h3", 2, []peerView{up("a", 5, "h5")}, time.Second, cfgBehind, true},
		{"peer ahead with the same content", 3, "h", 2, []peerView{up("a", 5, "h")}, time.Second, cfgVerified, false},
		{"one peer ahead, one agrees", 3, "h3", 2, []peerView{up("a", 3, "h3"), up("b", 5, "h5")}, time.Second, cfgBehind, true},
		{"nobody answered yet", 3, "h", 2, []peerView{{Addr: "a"}}, 5 * time.Second, cfgVerifying, true},
		{"nobody answered, waited long enough", 3, "h", 2, []peerView{{Addr: "a"}}, configVerifyWait, cfgUnverified, false},
		{"peers too old to say", 3, "h", 2, []peerView{{Addr: "a", Reachable: true, Known: true, Version: "0.9.8.8"}}, 5 * time.Second, cfgVerifying, true},
		{"peers too old, waited", 3, "h", 2, []peerView{{Addr: "a", Reachable: true, Known: true, Version: "0.9.8.8"}}, time.Minute, cfgUnverified, false},
		{"unreachable peer ahead is ignored", 3, "h3", 2, []peerView{{Addr: "a", Known: true, Revision: 9, Hash: "h9"}}, time.Minute, cfgUnverified, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, reason := configVerdict(tt.selfRev, tt.selfHash, "", tt.configured, tt.peers, tt.since)
			if state != tt.want {
				t.Fatalf("state = %q (%s), want %q", state, reason, tt.want)
			}
			if got := startHoldFor(state, reason) != ""; got != tt.hold {
				t.Errorf("hold = %v, want %v", got, tt.hold)
			}
			if state != cfgVerified && reason == "" {
				t.Error("a state other than verified must say why")
			}
		})
	}
}

func TestMembershipVerdict(t *testing.T) {
	tests := []struct {
		name  string
		self  int64
		peers []peerView
		held  bool
	}{
		{"same epoch", 2, []peerView{{Addr: "a", Reachable: true, Known: true, MembershipEpoch: 2}}, false},
		{"peer lower", 3, []peerView{{Addr: "a", Reachable: true, Known: true, MembershipEpoch: 1}}, false},
		{"peer higher", 2, []peerView{{Addr: "a", Reachable: true, Known: true, MembershipEpoch: 3}}, true},
		{"higher but unreachable", 2, []peerView{{Addr: "a", Known: true, MembershipEpoch: 3}}, false},
		{"higher but never seen", 2, []peerView{{Addr: "a", Reachable: true, MembershipEpoch: 3}}, false},
		{"old peers announce none", 2, []peerView{{Addr: "a", Reachable: true, Known: true}}, false},
		{"no peers", 0, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := membershipVerdict(tt.self, tt.peers)
			if (got != "") != tt.held {
				t.Errorf("verdict = %q, want held=%v", got, tt.held)
			}
			if tt.held && !strings.Contains(got, "removed while away") {
				t.Errorf("reason = %q", got)
			}
		})
	}
}

func TestOutageRulesLatch(t *testing.T) {
	var o outageRules
	newV := "0.9.8.9-3+abc"
	oldPeers := []peerView{{Addr: "a", Known: true, Version: "0.9.8.8+x"}}
	if o.refresh(newV, 1, oldPeers, nil) || o.Active() {
		t.Fatal("latched with an old peer")
	}
	saved := 0
	newPeers := []peerView{{Addr: "a", Known: true, Version: newV}}
	if !o.refresh(newV, 1, newPeers, func() error { saved++; return nil }) || !o.Active() || saved != 1 {
		t.Fatalf("did not latch: active=%v saved=%d", o.Active(), saved)
	}
	if o.refresh(newV, 1, newPeers, func() error { saved++; return nil }) || saved != 1 {
		t.Error("persisted twice")
	}
	if !o.Active() {
		t.Error("the latch must stay on")
	}
	var failing outageRules
	if failing.refresh(newV, 1, newPeers, func() error { return errors.New("disk full") }) || failing.Active() {
		t.Error("a latch that could not be saved must not switch the rules on")
	}
}

type fakeQuorum struct{ v quorum.Verdict }

func (f fakeQuorum) Quorum() quorum.Verdict { return f.v }

func base(r int64) *int64 { return &r }

func TestCheckWriteRules(t *testing.T) {
	has := fakeQuorum{quorum.Verdict{TotalVoters: 3, VotesSeen: 2, Needed: 2, HasQuorum: true}}
	lacks := fakeQuorum{quorum.Verdict{TotalVoters: 3, VotesSeen: 1, Needed: 2, HasQuorum: false}}
	cur := &config.Cluster{ConfigRevision: 5}
	tests := []struct {
		name   string
		active bool
		q      fakeQuorum
		upd    configUpdate
		status int
		code   string
	}{
		{"rules off allows everything", false, lacks, configUpdate{ConfigBaseRevision: base(1)}, 0, ""},
		{"quorum and no base", true, has, configUpdate{}, 0, ""},
		{"quorum and current base", true, has, configUpdate{ConfigBaseRevision: base(5)}, 0, ""},
		{"quorum and a base ahead of this node", true, has, configUpdate{ConfigBaseRevision: base(7)}, 0, ""},
		{"no quorum", true, lacks, configUpdate{}, http.StatusServiceUnavailable, "no_quorum"},
		{"no quorum wins over a good base", true, lacks, configUpdate{ConfigBaseRevision: base(5)}, http.StatusServiceUnavailable, "no_quorum"},
		{"stale base", true, has, configUpdate{ConfigBaseRevision: base(3)}, http.StatusConflict, "stale_base"},
		{"base zero on a committed cluster", true, has, configUpdate{ConfigBaseRevision: base(0)}, http.StatusConflict, "stale_base"},
		{"catch-up needs quorum too", true, lacks, configUpdate{ConfigCatchUp: true, ConfigRevision: 9}, http.StatusServiceUnavailable, "no_quorum"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body, ok := checkWriteRules(tt.active, tt.q, cur, tt.upd)
			if status != tt.status || ok != (tt.status == 0) {
				t.Fatalf("status = %d ok=%v, want %d", status, ok, tt.status)
			}
			if body["code"] != tt.code {
				t.Errorf("code = %q, want %q", body["code"], tt.code)
			}
			if tt.status != 0 && body["error"] == "" {
				t.Error("a refusal needs a message")
			}
		})
	}
}

func TestConfigVerdict_UsesTheSecondHashWhenBothSidesHaveIt(t *testing.T) {
	peer := func(rev int64, hash, hashV2 string) peerView {
		p := up("a", rev, hash)
		p.HashV2 = hashV2
		return p
	}
	tests := []struct {
		name       string
		selfRev    int64
		selfV1     string
		selfV2     string
		peer       peerView
		wantBehind bool
	}{
		{"same v1, different v2: the backup settings differ", 3, "h", "v2-self", peer(5, "h", "v2-peer"), true},
		{"same v1 and v2", 3, "h", "v2", peer(5, "h", "v2"), false},
		{"different v1, same v2 is the same content", 3, "h-self", "v2", peer(5, "h-peer", "v2"), false},
		{"peer has no v2: fall back to v1 (same)", 3, "h", "v2-self", peer(5, "h", ""), false},
		{"peer has no v2: fall back to v1 (different)", 3, "h-self", "v2-self", peer(5, "h-peer", ""), true},
		{"this node has no v2: fall back to v1", 3, "h", "", peer(5, "h", "v2-peer"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, _ := configVerdict(tt.selfRev, tt.selfV1, tt.selfV2, 2, []peerView{tt.peer}, time.Second)
			if (state == cfgBehind) != tt.wantBehind {
				t.Errorf("state = %q, wantBehind %v", state, tt.wantBehind)
			}
		})
	}
}

// Every field a commit pushes must be hashed, or listed here as metadata.
// A new setting that is pushed but not hashed would drift unnoticed.
func TestEveryPushedSettingIsHashedOrMarkedAsMetadata(t *testing.T) {
	metadata := map[string]bool{
		"config_revision": true, "config_revision_at": true, "config_revision_origin": true,
		"config_catchup": true, "config_base_revision": true,
	}
	_, hashed := config.HashedKeys()
	covered := map[string]bool{}
	for _, k := range hashed {
		covered[k] = true
	}
	typ := reflect.TypeOf(configUpdate{})
	for i := 0; i < typ.NumField(); i++ {
		key, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		if !covered[key] && !metadata[key] {
			t.Errorf("configUpdate field %q is pushed by a commit but not covered by ConfigDocumentHashV2; add it to documentV2Extra or to the metadata list", key)
		}
	}
	for k := range metadata {
		if covered[k] {
			t.Errorf("%q is listed as metadata but is hashed", k)
		}
	}
}
