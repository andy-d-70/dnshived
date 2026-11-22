// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsservice

import (
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/dnsanswer"
)

func TestService_OverlayUntilTheCutover(t *testing.T) {
	r := newRig(t)
	r.do("POST", "/api/v1/dnsstore/commit", hostBody("00000000000000000000000000000001"))
	if rc, an := r.answerCount("cam-1.example.lan", dnsanswer.TypeA); rc != 0 || an != 1 {
		t.Fatal("a stored record is answered from the start")
	}
	if rc, _ := r.answerCount("missing.example.lan", dnsanswer.TypeA); rc != -1 {
		t.Fatalf("before the cutover a name the store lacks is forwarded (rcode %d)", rc)
	}
	if _, st := r.do("GET", "/api/v1/dnsstore/status", ""); st["authoritative"] != false {
		t.Fatal("status must say overlay")
	}
	if code, out := r.do("POST", "/api/v1/dnsstore/settings", `{"authoritative":true}`); code != 200 || out["authoritative"] != true {
		t.Fatalf("cutover: %d %v", code, out)
	}
	if rc, _ := r.answerCount("missing.example.lan", dnsanswer.TypeA); rc != 3 {
		t.Fatalf("after the cutover the whole domain is answered (rcode %d)", rc)
	}
	if !r.svc.Authoritative() {
		t.Fatal("Authoritative()")
	}
	if code, _ := r.do("POST", "/api/v1/dnsstore/settings", `{"authoritative":false}`); code != 200 {
		t.Fatal("back to overlay")
	}
	if rc, _ := r.answerCount("missing.example.lan", dnsanswer.TypeA); rc != -1 {
		t.Fatal("overlay again")
	}
	for name, body := range map[string]string{"empty": `{}`, "unknown": `{"authoritative":true,"x":1}`, "bad": `{`} {
		if code, _ := r.do("POST", "/api/v1/dnsstore/settings", body); code != 400 {
			t.Errorf("%s: status %d", name, code)
		}
	}
}

func TestService_ImportFromTheConfiguration(t *testing.T) {
	r := newRig(t)
	r.recs = []config.DNSRecord{
		{Name: "web.example.lan.", Type: "A", Value: "10.0.0.7"},
		{Name: "www.example.lan.", Type: "CNAME", Value: "web.example.lan."},
		{Name: "bad name.example.lan.", Type: "A", Value: "10.0.0.8"},
	}
	code, out := r.do("POST", "/api/v1/dnsstore/import", `{"dry_run":true}`)
	if code != 200 || out["records"].(float64) != 2 || len(out["skipped"].([]any)) != 1 {
		t.Fatalf("dry run: %d %v", code, out)
	}
	if _, st := r.do("GET", "/api/v1/dnsstore/status", ""); st["rows"].(float64) != 0 {
		t.Fatal("a dry run must not write")
	}
	if code, out = r.do("POST", "/api/v1/dnsstore/import", `{}`); code != 200 || out["batches"].(float64) != 1 {
		t.Fatalf("import: %d %v", code, out)
	}
	if rc, an := r.answerCount("www.example.lan", dnsanswer.TypeA); rc != 0 || an != 2 {
		t.Fatalf("imported records answer: %d %d", rc, an)
	}
	if code, _ = r.do("POST", "/api/v1/dnsstore/import", `{}`); code != 200 {
		t.Fatal("again")
	}
	if _, st := r.do("GET", "/api/v1/dnsstore/status", ""); st["rows"].(float64) != 2 {
		t.Fatalf("importing twice must not duplicate: %v", st["rows"])
	}
}

func TestService_ServingStateAndSettingsRequest(t *testing.T) {
	r := newRig(t)
	if !r.svc.Serving() {
		t.Fatal("a service that built its first table is serving")
	}
	if _, st := r.do("GET", "/api/v1/dnsstore/status", ""); st["serving"] != true {
		t.Fatalf("status: %v", st)
	}
	for name, body := range map[string]string{"empty": `{}`, "the removed DNS VIP": `{"dns_vip":"192.0.2.53/24","vrrp_id":61}`} {
		if code, _ := r.do("POST", "/api/v1/dnsstore/settings", body); code != 400 {
			t.Errorf("%s: status %d, want 400", name, code)
		}
	}
}
