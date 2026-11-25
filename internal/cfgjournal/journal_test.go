// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package cfgjournal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"dnshived/internal/changeset"
	"dnshived/internal/config"
	"dnshived/internal/dnsstore"
	"dnshived/internal/dnsstore/vfs/faultfs"
)

func newStore(t testing.TB) *dnsstore.Store {
	t.Helper()
	keys := dnsstore.StaticKeys{Cur: 1, Epochs: map[uint32][]byte{1: []byte("0123456789abcdef0123456789abcdef")}}
	s, err := dnsstore.Open("/j", dnsstore.Options{FS: faultfs.New(1), Keys: keys, Create: true, SnapshotBytes: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func tree(t testing.TB, v any) any {
	t.Helper()
	tr, err := changeset.Tree(v)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func cluster(mod func(c *config.Cluster)) config.Cluster {
	c := config.Cluster{
		LogLevel: "info",
		LocalDomains: []config.LocalDomain{{Name: "a.lan", Records: []config.LocalDomainHost{
			{Host: "h1", Type: "A", Value: "10.0.0.1"},
			{Host: "h2", Type: "A", Value: "10.0.0.2"},
		}}},
		Scopes: map[string]config.ScopeConfig{"office": {VLANID: 10, Reservations: []config.Reservation{{MAC: "aa:aa:aa:aa:aa:01", IP: "10.1.0.5", Hostname: "cam"}}}},
	}
	if mod != nil {
		mod(&c)
	}
	return c
}

func TestEntry_RoundTripKeepsAbsentAndEmptyApart(t *testing.T) {
	tests := []struct {
		name string
		e    Entry
	}{
		{"added", Entry{Doc: "cluster", Path: "log_level", New: []byte(`"debug"`), Base: 7, Author: "ann", TimeMs: 5, Origin: 2, Seq: 3}},
		{"removed", Entry{Doc: "cluster", Path: "x", Old: []byte(`1`)}},
		{"empty but present", Entry{Doc: "cluster", Path: "x", Old: []byte{}, New: []byte(`null`)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeEntry(tt.e.encode())
			if err != nil || !reflect.DeepEqual(got, tt.e) {
				t.Fatalf("got %+v %v, want %+v", got, err, tt.e)
			}
		})
	}
	for _, bad := range []Entry{{Path: "x", New: []byte("1")}, {Doc: "c", New: []byte("1")}, {Doc: "c", Path: "x"}} {
		if _, err := decodeEntry(bad.encode()); !errors.Is(err, ErrEntry) {
			t.Errorf("%+v must be refused: %v", bad, err)
		}
	}
}

func FuzzDecodeEntry(f *testing.F) {
	f.Add((&Entry{Doc: "c", Path: "p", New: []byte("1")}).encode())
	f.Add([]byte{1, 200})
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := decodeEntry(b)
		if err == nil {
			if again, err := decodeEntry(e.encode()); err != nil || !reflect.DeepEqual(again, e) {
				t.Fatalf("a decoded entry must encode to the same entry: %v", err)
			}
		}
	})
}

func TestAppend_KeepsOrderAndSplitsLargeEntries(t *testing.T) {
	s := newStore(t)
	j := New(s.Commit)
	big := []byte(`"` + strings.Repeat("x", 300<<10) + `"`)
	r1, err := j.Append(Meta{Author: "ann", TimeMs: 1}, []Entry{{Doc: "c", Path: "b", New: []byte("1")}, {Doc: "c", Path: "a", New: big}})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := j.Append(Meta{Author: "bob", TimeMs: 2}, []Entry{{Doc: "c", Path: "a", Old: big, New: []byte("2")}})
	if err != nil || r2 <= r1 {
		t.Fatal(r2, err)
	}
	recs, err := Since(s.View(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 || recs[0].Path != "b" || recs[1].Path != "a" || !bytes.Equal(recs[1].New, big) || recs[2].Rev != r2 || recs[2].Author != "bob" {
		t.Fatalf("records: %d %+v", len(recs), recs[0])
	}
	if later, _ := Since(s.View(), r1); len(later) != 1 || later[0].Rev != r2 {
		t.Fatalf("since r1: %+v", later)
	}
	if s.View().CountOf(TypePart) < 7 {
		t.Fatal("a 300 KiB value is stored in several parts")
	}
}

func TestAppend_RefusesBadChangeSets(t *testing.T) {
	j := New(newStore(t).Commit)
	tests := []struct {
		name    string
		entries []Entry
	}{
		{"empty", nil},
		{"same item twice", []Entry{{Doc: "c", Path: "a", New: []byte("1")}, {Doc: "c", Path: "a", New: []byte("2")}}},
		{"changes nothing", []Entry{{Doc: "c", Path: "a"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := j.Append(Meta{}, tt.entries); !errors.Is(err, ErrEntry) {
				t.Fatalf("err %v", err)
			}
		})
	}
}

func TestSince_RefusesAMissingPart(t *testing.T) {
	s := newStore(t)
	j := New(s.Commit)
	if _, err := j.Append(Meta{}, []Entry{{Doc: "c", Path: "a", New: []byte(`"` + strings.Repeat("y", 200<<10) + `"`)}}); err != nil {
		t.Fatal(err)
	}
	var victim dnsstore.ID
	s.View().Range(TypePart, func(id dnsstore.ID, _ uint64, _ []byte) bool { victim = id; return false })
	if _, err := s.Commit(dnsstore.Batch{Ops: []dnsstore.Op{{Kind: dnsstore.OpDel, Type: TypePart, ID: victim}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Since(s.View(), 0); !errors.Is(err, ErrJournal) {
		t.Fatalf("a missing part must be an error, got %v", err)
	}
}

func docOn(fs *faultfs.FS) *Document {
	return &Document{FS: fs, Name: "cluster", Path: "/etc/cluster.json", Mode: 0o640}
}

func seed(t *testing.T, fs *faultfs.FS, v any) {
	t.Helper()
	raw, _ := json.Marshal(v)
	if err := writeAtomic(fs, "/etc/cluster.json", raw, 0o640); err != nil {
		t.Fatal(err)
	}
}

func change(t *testing.T, s *dnsstore.Store, live, cand config.Cluster, base uint64) uint64 {
	t.Helper()
	es, err := FromChange("cluster", tree(t, live), tree(t, cand), base)
	if err != nil {
		t.Fatal(err)
	}
	rev, err := New(s.Commit).Append(Meta{Author: "ann"}, es)
	if err != nil {
		t.Fatal(err)
	}
	return rev
}

func loadCluster(t *testing.T, d *Document) (config.Cluster, uint64) {
	t.Helper()
	tr, rev, _, err := d.Load()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(tr)
	var c config.Cluster
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c, rev
}

func sameCluster(t *testing.T, got, want config.Cluster) {
	t.Helper()
	if rest := changeset.Changes(tree(t, got), tree(t, want)); len(rest) != 0 {
		t.Fatalf("documents differ at %v", rest)
	}
}

func TestReplay_AdoptsTheFileAndAppliesEveryChange(t *testing.T) {
	fs, s := faultfs.New(2), newStore(t)
	c0 := cluster(nil)
	seed(t, fs, c0)
	c1 := cluster(func(c *config.Cluster) {
		c.LogLevel = "debug"
		c.LocalDomains[0].Records = append(c.LocalDomains[0].Records, config.LocalDomainHost{Host: "h3", Type: "A", Value: "10.0.0.3"})
	})
	c2 := cluster(func(c *config.Cluster) {
		c.LogLevel = "debug"
		c.Scopes["lab"] = config.ScopeConfig{VLANID: 20}
		delete(c.Scopes, "office")
	})
	r1 := change(t, s, c0, c1, 0)
	r2 := change(t, s, c1, c2, r1)
	d := docOn(fs)
	n, rev, err := Replay(s.View(), d)
	if err != nil || n == 0 || rev != r2 {
		t.Fatalf("replay: %d %d %v", n, rev, err)
	}
	got, at := loadCluster(t, d)
	sameCluster(t, got, c2)
	if at != r2 {
		t.Fatalf("the file holds revision %d, want %d", at, r2)
	}
	if n, _, err := Replay(s.View(), d); err != nil || n != 0 {
		t.Fatalf("a second replay changes nothing: %d %v", n, err)
	}
}

func TestReplay_RefusesAChangeBasedOnAnotherValue(t *testing.T) {
	fs, s := faultfs.New(3), newStore(t)
	c0 := cluster(nil)
	seed(t, fs, c0)
	before, _ := fs.Raw("/etc/cluster.json")
	stale := cluster(func(c *config.Cluster) { c.LogLevel = "warn" })
	change(t, s, stale, cluster(func(c *config.Cluster) { c.LogLevel = "debug" }), 0)
	_, _, err := Replay(s.View(), docOn(fs))
	var ce *ConflictError
	if !errors.As(err, &ce) || ce.Path != "log_level" || !strings.Contains(string(ce.Have), "info") {
		t.Fatalf("err %v", err)
	}
	if after, _ := fs.Raw("/etc/cluster.json"); !bytes.Equal(before, after) {
		t.Fatal("a refused change must leave the file as it was")
	}
}

func TestReplay_CrashAtEveryStepEndsAtOneOfTheTwoStates(t *testing.T) {
	s := newStore(t)
	c0 := cluster(nil)
	c1 := cluster(func(c *config.Cluster) { c.LogLevel = "debug" })
	c2 := cluster(func(c *config.Cluster) { c.LogLevel = "error"; c.Scopes["lab"] = config.ScopeConfig{VLANID: 20} })
	r1 := change(t, s, c0, c1, 0)
	r2 := change(t, s, c1, c2, r1)
	probe := faultfs.New(9)
	seed(t, probe, c0)
	start := probe.Ops()
	if _, _, err := Replay(s.View(), docOn(probe)); err != nil {
		t.Fatal(err)
	}
	steps := probe.Ops() - start
	for crashAt := 1; crashAt <= steps; crashAt++ {
		for _, torn := range []bool{false, true} {
			t.Run(fmt.Sprintf("op%d/torn=%v", crashAt, torn), func(t *testing.T) {
				fs := faultfs.New(int64(crashAt))
				seed(t, fs, c0)
				fs.SetCrashAt(fs.Ops()+crashAt, torn)
				_, _, _ = Replay(s.View(), docOn(fs))
				fs.Crash()
				d := docOn(fs)
				if _, at, _, err := d.Load(); err != nil || (at != 0 && at != r2) {
					t.Fatalf("after the crash: revision %d, %v", at, err)
				}
				if _, rev, err := Replay(s.View(), d); err != nil || rev != r2 {
					t.Fatalf("replay after the crash: %d %v", rev, err)
				}
				got, at := loadCluster(t, d)
				sameCluster(t, got, c2)
				if at != r2 {
					t.Fatalf("revision %d", at)
				}
			})
		}
	}
}

func TestLoad_DetectsAChangeOutsideTheJournal(t *testing.T) {
	fs, s := faultfs.New(4), newStore(t)
	seed(t, fs, cluster(nil))
	change(t, s, cluster(nil), cluster(func(c *config.Cluster) { c.LogLevel = "debug" }), 0)
	d := docOn(fs)
	if _, _, err := Replay(s.View(), d); err != nil {
		t.Fatal(err)
	}
	raw, _ := fs.Raw("/etc/cluster.json")
	if err := writeAtomic(fs, "/etc/cluster.json", bytes.Replace(raw, []byte("debug"), []byte("trace"), 1), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := d.Load(); !errors.Is(err, ErrOutside) {
		t.Fatalf("err %v", err)
	}
	if _, _, err := Replay(s.View(), d); !errors.Is(err, ErrOutside) {
		t.Fatal("replay must not touch a file changed outside the journal")
	}
}

func TestIndex_VersionCoversContainingAndContainedItems(t *testing.T) {
	x := NewIndex()
	x.Add(Record{Rev: 3, Entry: Entry{Doc: "c", Path: "scopes/office"}},
		Record{Rev: 5, Entry: Entry{Doc: "c", Path: "scopes/lab/vlan_id"}},
		Record{Rev: 7, Entry: Entry{Doc: "c", Path: "log_level"}})
	tests := []struct {
		path string
		want uint64
	}{
		{"scopes/office/vlan_id", 3},
		{"scopes/lab", 5},
		{"scopes", 5},
		{"log_level", 7},
		{"scopes/other", 0},
		{"log", 0},
	}
	for _, tt := range tests {
		if got := x.Version("c", tt.path); got != tt.want {
			t.Errorf("%s: %d, want %d", tt.path, got, tt.want)
		}
	}
	if got := x.Version("other", "log_level"); got != 0 {
		t.Errorf("another document: %d", got)
	}
	if stale := x.Stale("c", map[string]uint64{"scopes/lab": 4, "log_level": 7, "scopes/office/gateway": 2}); !reflect.DeepEqual(stale, []string{"scopes/lab", "scopes/office/gateway"}) {
		t.Fatalf("stale %v", stale)
	}
}
