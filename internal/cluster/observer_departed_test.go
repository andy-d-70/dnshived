package cluster

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"dnshived/internal/identity"
)

func newDepartedFixture(t *testing.T, handler http.Handler) (*Observer, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetPeerForTest("core-2-addr", &PeerState{
		Addr:     "core-2-addr",
		Identity: &identity.Identity{ClusterID: "c", NodeID: "n-core-2", Role: "core-2"},
	})
	o.SetFallbackAddrs(map[string]map[string]string{"core-2": {"ens19": srv.Listener.Addr().String()}})
	return o, srv
}

func TestObserver_RemovePeer_ClearsStaleFallbackReachability(t *testing.T) {
	o, _ := newDepartedFixture(t, identityResponder("core-2"))
	o.probeFallbackSweep()
	o.ObserveMgmtBeacon("core-2", true)

	if ok, _ := o.RoleReachable("core-2"); !ok {
		t.Fatal("precondition: core-2 should be fallback-reachable before removal")
	}

	o.RemovePeer("core-2-addr")

	if ok, _ := o.RoleReachable("core-2"); ok {
		t.Error("RoleReachable(core-2) = true after RemovePeer, want false")
	}
	for _, fs := range o.FallbackStatuses() {
		if fs.Role == "core-2" {
			t.Errorf("FallbackStatuses() still has %+v after RemovePeer", fs)
		}
	}
	for _, parent := range []string{"ens19", mgmtParentKey} {
		if _, known := o.PathScore("core-2", parent); known {
			t.Errorf("PathScore(core-2, %s) still known after RemovePeer", parent)
		}
	}

	o.probeFallbackSweep()
	if ok, _ := o.RoleReachable("core-2"); ok {
		t.Error("a later sweep re-probed the removed role")
	}
}

func TestObserver_RemovePeer_DoesNotMutateCallerFallbackMap(t *testing.T) {
	srv := httptest.NewServer(identityResponder("core-2"))
	defer srv.Close()

	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")
	o.SetPeerForTest("core-2-addr", &PeerState{
		Addr:     "core-2-addr",
		Identity: &identity.Identity{Role: "core-2"},
	})
	targets := map[string]map[string]string{
		"core-2": {"ens19": srv.Listener.Addr().String()},
		"core-3": {"ens19": "unused:1"},
	}
	o.SetFallbackAddrs(targets)

	o.RemovePeer("core-2-addr")

	if _, ok := targets["core-2"]; !ok {
		t.Error("RemovePeer deleted core-2 from the caller's own targets map")
	}
}

func TestObserver_RemovePeer_InFlightSweepCannotResurrect(t *testing.T) {
	arrived := make(chan struct{})
	release := make(chan struct{})
	o, _ := newDepartedFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(arrived)
		<-release
		identityResponder("core-2")(w, r)
	}))

	done := make(chan struct{})
	go func() {
		o.probeFallbackSweep()
		close(done)
	}()
	<-arrived
	o.RemovePeer("core-2-addr")
	close(release)
	<-done

	if ok, _ := o.RoleReachable("core-2"); ok {
		t.Error("an in-flight sweep wrote core-2 back as reachable after RemovePeer")
	}
}

func TestObserver_RemovePeer_MgmtBeaconStopsUntilHeardAgain(t *testing.T) {
	o, _ := newDepartedFixture(t, identityResponder("core-2"))
	o.ObserveMgmtBeacon("core-2", true)
	o.RemovePeer("core-2-addr")

	o.ObserveMgmtBeacon("core-2", false)
	if _, ok := findFallbackStatus(o.FallbackStatuses(), "core-2", mgmtParentKey); ok {
		t.Error("an unheard beacon tick recreated the removed role's mgmt entry")
	}

	o.ObserveMgmtBeacon("core-2", true)
	if fs, ok := findFallbackStatus(o.FallbackStatuses(), "core-2", mgmtParentKey); !ok || !fs.Reachable {
		t.Errorf("a new occupant's heard beacon was ignored: %+v (ok=%v)", fs, ok)
	}
}

func TestObserver_SetFallbackAddrs_PrunesDroppedPathsKeepsMgmt(t *testing.T) {
	o, _ := newDepartedFixture(t, identityResponder("core-2"))
	o.probeFallbackSweep()
	o.ObserveMgmtBeacon("core-2", false)

	o.SetFallbackAddrs(nil)

	if _, ok := findFallbackStatus(o.FallbackStatuses(), "core-2", "ens19"); ok {
		t.Error("ens19 result survived after it was dropped from the target set")
	}
	if _, ok := findFallbackStatus(o.FallbackStatuses(), "core-2", mgmtParentKey); !ok {
		t.Error("mgmt entry was pruned, but it never lives in fallbackAddrs")
	}
	if ok, _ := o.RoleReachable("core-2"); ok {
		t.Error("RoleReachable(core-2) = true from a dropped path")
	}
}
