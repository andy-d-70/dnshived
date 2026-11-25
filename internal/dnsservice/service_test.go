// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsservice

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/dnsanswer"
	"dnshived/internal/dnsdata"
)

type rig struct {
	t      testing.TB
	svc    *Service
	mux    *http.ServeMux
	dir    string
	leases atomic.Pointer[[]dnsdata.LeaseName]
	resv   atomic.Pointer[[]dnsdata.ReservedName]
	logs   []string
	recs   []config.DNSRecord
}

func newRig(t *testing.T) *rig {
	t.Helper()
	return openRig(t, t.TempDir())
}

func openRig(t *testing.T, dir string) *rig { return openRigMode(t, dir, 0) }

func openRigMode(t *testing.T, dir string, tableMode os.FileMode) *rig {
	return openRigWith(t, dir, tableMode, nil)
}

func openRigWith(t testing.TB, dir string, tableMode os.FileMode, mod func(*Options)) *rig {
	t.Helper()
	r := &rig{t: t, dir: dir}
	keys, err := LoadOrCreateKey(filepath.Join(dir, "dnsstore.key"))
	if err != nil {
		t.Fatal(err)
	}
	o := Options{
		Dir: filepath.Join(dir, "dnsstore"), TablePath: filepath.Join(dir, "dnstable.bin"), TableMode: tableMode, Keys: keys,
		Input: func() CompileInput {
			in := CompileInput{Zones: []dnsanswer.Zone{{Name: "example.lan"}}, Reserved: map[string]string{"printer.example.lan": "office"}, NegTTL: 60}
			if p := r.resv.Load(); p != nil {
				in.ReservedNames = *p
			}
			return in
		},
		Leases: func() []dnsdata.LeaseName {
			if p := r.leases.Load(); p != nil {
				return append([]dnsdata.LeaseName(nil), *p...)
			}
			return nil
		},
		Log:          func(f string, a ...any) { r.logs = append(r.logs, strings.TrimSpace(strings.ReplaceAll(f, "\n", " "))) },
		ImportSource: func() []config.DNSRecord { return r.recs },
	}
	if mod != nil {
		mod(&o)
	}
	svc, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	r.svc = svc
	r.mux = http.NewServeMux()
	svc.Routes(r.mux, func(h http.HandlerFunc) http.HandlerFunc { return h })
	t.Cleanup(func() { _ = svc.Close() })
	return r
}

func (r *rig) do(method, path, body string) (int, map[string]any) {
	r.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	r.mux.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (r *rig) table() *dnsanswer.Table {
	r.t.Helper()
	b, err := os.ReadFile(filepath.Join(r.dir, "dnstable.bin"))
	if err != nil {
		r.t.Fatal(err)
	}
	tb, _, err := dnsanswer.DecodeTable(b)
	if err != nil {
		r.t.Fatal(err)
	}
	return tb
}

func query(name string, typ uint16) []byte {
	q := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	return append(q, 0, byte(typ>>8), byte(typ), 0, 1)
}

func (r *rig) answerCount(name string, typ uint16) (rcode, an int) {
	out, st := r.table().Respond(query(name, typ), nil, false)
	if st != dnsanswer.Answered {
		return -1, 0
	}
	return int(out[3] & 0xF), int(out[6])<<8 | int(out[7])
}

const addHost = `{"author":"t","ops":[{"op":"put","kind":"host","id":"%s","host":{"label":"cam-1","domains":["example.lan"],"addrs":[{"ip":"10.0.0.5","ptr":true}]}}]}`

func hostBody(id string) string { return strings.Replace(addHost, "%s", id, 1) }

func TestService_CommitPublishesAndSurvivesRestart(t *testing.T) {
	r := newRig(t)
	code, out := r.do("POST", "/api/v1/dnsstore/commit", hostBody("00000000000000000000000000000001"))
	if code != 200 || out["rev"].(float64) != 1 {
		t.Fatalf("commit: %d %v", code, out)
	}
	if rc, an := r.answerCount("cam-1.example.lan", dnsanswer.TypeA); rc != 0 || an != 1 {
		t.Fatalf("published table: rcode %d answers %d", rc, an)
	}
	if rc, an := r.answerCount("5.0.0.10.in-addr.arpa", dnsanswer.TypePTR); rc != 0 || an != 1 {
		t.Fatalf("reverse record: rcode %d answers %d", rc, an)
	}
	code, st := r.do("GET", "/api/v1/dnsstore/status", "")
	pub := st["published"].(map[string]any)
	if code != 200 || st["rows"].(float64) != 1 || pub["names"].(float64) < 2 || pub["error"] != nil {
		t.Fatalf("status %d %v", code, st)
	}
	_ = r.svc.Close()
	r2 := openRig(t, r.dir)
	if rc, an := r2.answerCount("cam-1.example.lan", dnsanswer.TypeA); rc != 0 || an != 1 {
		t.Fatal("the data must survive a restart")
	}
}

func TestService_GateRefusesAndWarns(t *testing.T) {
	r := newRig(t)
	r.do("POST", "/api/v1/dnsstore/commit", hostBody("00000000000000000000000000000001"))
	code, out := r.do("POST", "/api/v1/dnsstore/commit", hostBody("00000000000000000000000000000002"))
	if code != 422 || !strings.Contains(out["errors"].([]any)[0].(string), "already used") {
		t.Fatalf("duplicate name: %d %v", code, out)
	}
	code, out = r.do("POST", "/api/v1/dnsstore/commit", `{"author":"t","ops":[{"op":"put","kind":"host","host":{"label":"printer","domains":["example.lan"]}}]}`)
	if code != 422 || !strings.Contains(out["errors"].([]any)[0].(string), "reservation office") {
		t.Fatalf("reservation name: %d %v", code, out)
	}
	leases := []dnsdata.LeaseName{{Name: "pc.example.lan", IP: netip.MustParseAddr("10.0.5.9"), MAC: "aa:bb", LeasedAt: 5}}
	r.leases.Store(&leases)
	code, out = r.do("POST", "/api/v1/dnsstore/commit", `{"author":"t","ops":[{"op":"put","kind":"host","host":{"label":"pc","domains":["example.lan"],"addrs":[{"ip":"10.0.0.9"}]}}]}`)
	if code != 200 || len(out["warnings"].([]any)) != 1 {
		t.Fatalf("lease warning: %d %v", code, out)
	}
	if code, _ = r.do("POST", "/api/v1/dnsstore/commit", `{"author":"t","dry_run":true,"ops":[{"op":"put","kind":"host","host":{"label":"dry","domains":["example.lan"]}}]}`); code != 200 {
		t.Fatal("dry run")
	}
	if _, st := r.do("GET", "/api/v1/dnsstore/status", ""); st["rev"].(float64) != 2 {
		t.Fatalf("a refused or dry-run change must not commit: %v", st["rev"])
	}
}

func TestService_BadRequests(t *testing.T) {
	r := newRig(t)
	for name, body := range map[string]string{
		"unknown field": `{"author":"t","bogus":1,"ops":[]}`,
		"bad json":      `{`,
		"bad kind":      `{"ops":[{"op":"put","kind":"zone"}]}`,
		"bad id":        `{"ops":[{"op":"del","kind":"host","id":"xyz"}]}`,
		"delete no id":  `{"ops":[{"op":"del","kind":"host"}]}`,
		"put no body":   `{"ops":[{"op":"put","kind":"host"}]}`,
		"bad op":        `{"ops":[{"op":"zap","kind":"host","id":"00000000000000000000000000000001"}]}`,
		"bad name":      `{"ops":[{"op":"put","kind":"host","host":{"label":"a b","domains":["example.lan"]}}]}`,
		"bad address":   `{"ops":[{"op":"put","kind":"host","host":{"label":"a","domains":["example.lan"],"addrs":[{"ip":"nope"}]}}]}`,
		"bad type":      `{"ops":[{"op":"put","kind":"record","record":{"type":"ZZZ","owner":"a.example.lan"}}]}`,
	} {
		if code, _ := r.do("POST", "/api/v1/dnsstore/commit", body); code != 400 {
			t.Errorf("%s: status %d, want 400", name, code)
		}
	}
	big := bytes.Repeat([]byte("x"), maxRequestBody+10)
	if code, _ := r.do("POST", "/api/v1/dnsstore/commit", string(big)); code != 400 {
		t.Errorf("oversized body: %d", code)
	}
}

func TestService_RecordsListAndSearch(t *testing.T) {
	r := newRig(t)
	r.do("POST", "/api/v1/dnsstore/commit", hostBody("00000000000000000000000000000001"))
	code, out := r.do("POST", "/api/v1/dnsstore/commit", `{"author":"t","ops":[
		{"op":"put","kind":"record","record":{"owner":"info.example.lan","type":"TXT","value":"hello"}},
		{"op":"put","kind":"record","record":{"host":"00000000000000000000000000000001","sub":"_rtsp._tcp","type":"SRV","target":"cam-1.example.lan","port":554}},
		{"op":"put","kind":"record","record":{"owner":"mail.example.lan","type":"MX","target":"mx.example.lan","pref":10}}]}`)
	if code != 200 {
		t.Fatalf("records: %d %v", code, out)
	}
	if rc, an := r.answerCount("_rtsp._tcp.cam-1.example.lan", dnsanswer.TypeSRV); rc != 0 || an != 1 {
		t.Fatalf("host-relative SRV: %d %d", rc, an)
	}
	_, list := r.do("GET", "/api/v1/dnsstore/records?q=hello", "")
	if list["total"].(float64) != 1 {
		t.Fatalf("search: %v", list)
	}
	_, list = r.do("GET", "/api/v1/dnsstore/hosts?q=10.0.0", "")
	if list["total"].(float64) != 1 || list["items"].([]any)[0].(map[string]any)["label"] != "cam-1" {
		t.Fatalf("host search by address: %v", list)
	}
	_, list = r.do("GET", "/api/v1/dnsstore/records?limit=2&offset=1", "")
	if len(list["items"].([]any)) != 2 || list["total"].(float64) != 3 {
		t.Fatalf("paging: %v", list)
	}
}

func TestService_LeaseNamesAndCollisions(t *testing.T) {
	r := newRig(t)
	r.do("POST", "/api/v1/dnsstore/commit", hostBody("00000000000000000000000000000001"))
	leases := []dnsdata.LeaseName{
		{Name: "pc.example.lan", IP: netip.MustParseAddr("10.0.5.9"), MAC: "aa:02", LeasedAt: 5, Scope: "office"},
		{Name: "cam-1.example.lan", IP: netip.MustParseAddr("10.0.5.10"), MAC: "aa:03", LeasedAt: 6, Scope: "office"},
	}
	r.leases.Store(&leases)
	if err := r.svc.Rebuild(false); err != nil {
		t.Fatal(err)
	}
	if rc, an := r.answerCount("pc.example.lan", dnsanswer.TypeA); rc != 0 || an != 1 {
		t.Fatal("a lease name is published")
	}
	if _, an := r.answerCount("cam-1.example.lan", dnsanswer.TypeA); an != 1 {
		t.Fatal("an authored name is never replaced by a lease")
	}
	_, st := r.do("GET", "/api/v1/dnsstore/status", "")
	cols := st["published"].(map[string]any)["collisions"].([]any)
	if len(cols) != 1 || cols[0].(map[string]any)["holder"] != "authored" {
		t.Fatalf("collisions: %v", cols)
	}
	found := false
	for _, l := range r.logs {
		found = found || strings.Contains(l, "DNSSTORE:COLLISION")
	}
	if !found {
		t.Fatalf("the collision must be logged: %v", r.logs)
	}
	before := len(r.logs)
	if err := r.svc.Rebuild(true); err != nil {
		t.Fatal(err)
	}
	for _, l := range r.logs[before:] {
		if strings.Contains(l, "COLLISION") {
			t.Fatal("a known collision is logged once, not on every rebuild")
		}
	}
}

func TestKey_PermissionsAndSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	if _, err := LoadOrCreateKey(path); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(path); err == nil {
		t.Fatal("a key file readable by others must be refused")
	}
	short := filepath.Join(dir, "short")
	_ = os.WriteFile(short, []byte("abc"), 0o600)
	if _, err := LoadOrCreateKey(short); err == nil {
		t.Fatal("a short key must be refused")
	}
}

func TestTableFile_RejectsDamage(t *testing.T) {
	spec := &dnsanswer.Spec{Zones: []dnsanswer.Zone{{Name: "example.lan"}}, Serial: 3, NegTTL: 60}
	tb, _ := spec.Build()
	good := dnsanswer.EncodeTable(spec, tb.Digest())
	if _, _, err := dnsanswer.DecodeTable(good); err != nil {
		t.Fatal(err)
	}
	for i := range good {
		bad := append([]byte(nil), good...)
		bad[i] ^= 0x40
		if _, _, err := dnsanswer.DecodeTable(bad); err == nil {
			t.Fatalf("a flipped bit at %d went unnoticed", i)
		}
	}
	for i := 0; i < len(good); i++ {
		if _, _, err := dnsanswer.DecodeTable(good[:i]); err == nil {
			t.Fatalf("a table cut at %d went unnoticed", i)
		}
	}
}

func FuzzDecodeTable(f *testing.F) {
	spec := &dnsanswer.Spec{Zones: []dnsanswer.Zone{{Name: "example.lan"}}, Serial: 3, NegTTL: 60}
	tb, _ := spec.Build()
	f.Add(dnsanswer.EncodeTable(spec, tb.Digest()))
	f.Add([]byte("DHTB"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _, _ = dnsanswer.DecodeTable(b) })
}

func (r *rig) answerTTL(name string, typ uint16) (uint32, bool) { return ttlOf(r.table(), name, typ) }

func ttlOf(tb *dnsanswer.Table, name string, typ uint16) (uint32, bool) {
	q := query(name, typ)
	out, st := tb.Respond(q, nil, false)
	if st != dnsanswer.Answered || len(out) < len(q) || int(out[6])<<8|int(out[7]) == 0 {
		return 0, false
	}
	p := len(q)
	for p < len(out) {
		if out[p]&0xC0 == 0xC0 {
			p += 2
			break
		}
		if out[p] == 0 {
			p++
			break
		}
		p += 1 + int(out[p])
	}
	if p+8 > len(out) {
		return 0, false
	}
	return uint32(out[p+4])<<24 | uint32(out[p+5])<<16 | uint32(out[p+6])<<8 | uint32(out[p+7]), true
}

func TestService_DefaultTTLSetting(t *testing.T) {
	r := newRig(t)
	resv := []dnsdata.ReservedName{{Name: "printer.example.lan", IP: netip.MustParseAddr("10.0.0.7"), Scope: "office"}}
	r.resv.Store(&resv)
	leases := []dnsdata.LeaseName{{Name: "pc.example.lan", IP: netip.MustParseAddr("10.0.5.9"), MAC: "aa:02", LeasedAt: 5, Scope: "office"}}
	r.leases.Store(&leases)
	own := `{"author":"t","ops":[{"op":"put","kind":"host","id":"00000000000000000000000000000002","host":{"label":"never","domains":["example.lan"],"addrs":[{"ip":"10.0.0.8"}],"own_ttl":true}}]}`
	for _, body := range []string{hostBody("00000000000000000000000000000001"), own} {
		if code, out := r.do("POST", "/api/v1/dnsstore/commit", body); code != 200 {
			t.Fatalf("commit: %d %v", code, out)
		}
	}
	names := []string{"cam-1.example.lan", "printer.example.lan", "pc.example.lan"}
	check := func(want uint32) {
		t.Helper()
		for _, n := range names {
			if got, ok := r.answerTTL(n, dnsanswer.TypeA); !ok || got != want {
				t.Errorf("%s: ttl %d (answered %v), want %d", n, got, ok, want)
			}
		}
		if got, ok := r.answerTTL("never.example.lan", dnsanswer.TypeA); !ok || got != 0 {
			t.Errorf("an own TTL of 0 stays 0, got %d (answered %v)", got, ok)
		}
	}
	check(0)
	code, out := r.do("POST", "/api/v1/dnsstore/settings", `{"default_ttl":600,"author":"t"}`)
	if code != 200 || out["default_ttl"].(float64) != 600 {
		t.Fatalf("settings: %d %v", code, out)
	}
	check(600)
	if _, st := r.do("GET", "/api/v1/dnsstore/status", ""); st["default_ttl"].(float64) != 600 || st["authoritative"] != false {
		t.Fatalf("status: %v", st)
	}
	_, items := r.do("GET", "/api/v1/dnsstore/hosts?q=never", "")
	if list, _ := items["items"].([]any); len(list) != 1 || list[0].(map[string]any)["own_ttl"] != true {
		t.Fatalf("the host list shows the own TTL: %v", items)
	}
	for _, bad := range []string{`{}`, `{"default_ttl":-1}`, `{"default_ttl":"300"}`, `{"default_ttl":300,"extra":1}`} {
		if code, _ := r.do("POST", "/api/v1/dnsstore/settings", bad); code != 400 {
			t.Errorf("%s: %d, want 400", bad, code)
		}
	}
	if code, _ := r.do("POST", "/api/v1/dnsstore/settings", `{"default_ttl":2147483648}`); code == 200 {
		t.Error("a default TTL above the DNS limit must be refused")
	}
}
