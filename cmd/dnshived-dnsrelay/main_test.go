// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMain gives every test a consistent, minimal package-level baseline
// (logger/cacheShards/rateShards/cfg defaults).
func TestMain(m *testing.M) {
	logger = log.New(io.Discard, "", 0)
	initCacheShards()
	for i := range rateShards {
		rateShards[i] = newRateShard()
	}
	cfg = Config{
		ListenAddr:        "0.0.0.0:0",
		CacheSize:         500,
		MaxPacketSize:     4096,
		RateLimit:         100,
		RateBurst:         200,
		RateLimitScope:    "subnet",
		MaxTCPConnections: 100,
		MaxTCPPerSource:   10,
	}
	os.Exit(m.Run())
}

// ------------------------- synthetic packet builders
// -------------------------

func mustEncodeName(t testing.TB, name string) []byte {
	t.Helper()
	enc, err := encodeName(name)
	if err != nil {
		t.Fatalf("encodeName(%q): %v", name, err)
	}
	return enc
}

func appendRRFields(owner []byte, rtype, rclass uint16, ttl uint32, rdata []byte) []byte {
	var tmp [10]byte
	binary.BigEndian.PutUint16(tmp[0:2], rtype)
	binary.BigEndian.PutUint16(tmp[2:4], rclass)
	binary.BigEndian.PutUint32(tmp[4:8], ttl)
	binary.BigEndian.PutUint16(tmp[8:10], uint16(len(rdata)))
	out := append([]byte{}, owner...)
	out = append(out, tmp[:]...)
	out = append(out, rdata...)
	return out
}

func buildLiteralRR(t testing.TB, name string, rtype, rclass uint16, ttl uint32, rdata []byte) []byte {
	t.Helper()
	return appendRRFields(mustEncodeName(t, name), rtype, rclass, ttl, rdata)
}

// buildPointerRR builds one RR whose OWNER name is a 2-byte compression
// pointer to byte offset ptr.
func buildPointerRR(ptr uint16, rtype, rclass uint16, ttl uint32, rdata []byte) []byte {
	owner := []byte{0xC0 | byte(ptr>>8), byte(ptr)}
	return appendRRFields(owner, rtype, rclass, ttl, rdata)
}

func buildMessage(t testing.TB, id, flags uint16, qname string, qtype, qclass uint16, answers ...[]byte) []byte {
	t.Helper()
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	binary.BigEndian.PutUint16(hdr[6:8], uint16(len(answers)))
	out := append([]byte{}, hdr[:]...)
	out = append(out, mustEncodeName(t, qname)...)
	var qt [4]byte
	binary.BigEndian.PutUint16(qt[0:2], qtype)
	binary.BigEndian.PutUint16(qt[2:4], qclass)
	out = append(out, qt[:]...)
	for _, a := range answers {
		out = append(out, a...)
	}
	return out
}

// buildOPT builds a minimal EDNS0 OPT pseudo-RR (root owner name, TYPE
// 41).
func buildOPT(udpPayloadSize uint16) []byte {
	return appendRRFields([]byte{0}, 41, udpPayloadSize, 0, nil)
}

// ------------------------- encodeName -------------------------

func TestEncodeName_RoundTripsThroughExtractName(t *testing.T) {
	enc := mustEncodeName(t, "app.dantetest.local")
	pkt := append(make([]byte, 12), enc...)
	name, ok := extractName(pkt, 12)
	if !ok || name != "app.dantetest.local" {
		t.Fatalf("extractName after encodeName = %q, %v; want %q, true", name, ok, "app.dantetest.local")
	}
}

func TestEncodeName_EmptyNameEncodesRoot(t *testing.T) {
	enc, err := encodeName("")
	if err != nil || len(enc) != 1 || enc[0] != 0 {
		t.Fatalf("encodeName(\"\") = %v, %v; want [0], nil", enc, err)
	}
}

func TestEncodeName_RejectsOverlongLabel(t *testing.T) {
	long := make([]byte, 64)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := encodeName(string(long) + ".test"); err == nil {
		t.Fatal("expected an error for a 64-byte label, got nil")
	}
}

// ------------------------- nameWireLength / skipRRName
// -------------------------

func TestNameWireLength_LiteralName(t *testing.T) {
	enc := mustEncodeName(t, "backend.internal.test")
	pkt := append(make([]byte, 12), enc...)
	n, ok := nameWireLength(pkt, 12)
	if !ok || n != len(enc) {
		t.Fatalf("nameWireLength = %d, %v; want %d, true", n, ok, len(enc))
	}
}

func TestNameWireLength_CompressionPointerIsAlwaysTwoBytes(t *testing.T) {
	pkt := buildMessage(t, 1, 0, "backend.internal.test", 1, 1,
		buildPointerRR(12, 1, 1, 300, net.ParseIP("10.9.9.9").To4()))
	answerOwnerOffset, ok := questionEndOffset(pkt)
	if !ok {
		t.Fatal("questionEndOffset failed")
	}
	n, ok := nameWireLength(pkt, answerOwnerOffset)
	if !ok || n != 2 {
		t.Fatalf("nameWireLength(pointer) = %d, %v; want 2, true", n, ok)
	}

	skipped, ok := skipName(pkt, answerOwnerOffset)
	if !ok {
		t.Fatal("skipName failed")
	}
	if skipped == answerOwnerOffset+2 {
		t.Fatal("skipName unexpectedly matched nameWireLength's in-place answer — the two are not supposed to agree for a compressed name")
	}
}

func TestSkipRRName_EqualsOffsetPlusNameWireLength(t *testing.T) {
	pkt := buildMessage(t, 1, 0, "backend.internal.test", 1, 1,
		buildPointerRR(12, 1, 1, 300, net.ParseIP("10.9.9.9").To4()))
	off, _ := questionEndOffset(pkt)
	got, ok := skipRRName(pkt, off)
	if !ok || got != off+2 {
		t.Fatalf("skipRRName = %d, %v; want %d, true", got, ok, off+2)
	}
}

// ------------------------- parseRR -------------------------

func TestParseRR_CompressedOwnerName(t *testing.T) {
	ip := net.ParseIP("10.9.9.9").To4()
	pkt := buildMessage(t, 1, 0, "backend.internal.test", 1, 1,
		buildPointerRR(12, 1, 1, 300, ip))
	off, _ := questionEndOffset(pkt)

	owner, rtype, rclass, ttl, rdata, next, ok := parseRR(pkt, off)
	if !ok {
		t.Fatal("parseRR failed")
	}
	if owner != "backend.internal.test" {
		t.Errorf("owner = %q, want %q", owner, "backend.internal.test")
	}
	if rtype != 1 || rclass != 1 {
		t.Errorf("rtype/rclass = %d/%d, want 1/1", rtype, rclass)
	}
	if ttl != 300 {
		t.Errorf("ttl = %d, want 300 (this is the exact field the live bug corrupted)", ttl)
	}
	if string(rdata) != string(ip) {
		t.Errorf("rdata = %v, want %v", rdata, ip)
	}
	if next != len(pkt) {
		t.Errorf("next = %d, want %d (end of message)", next, len(pkt))
	}
}

// ------------------------- getMinTTL / hasOPT / decrementTTLs
// -------------------------

func TestGetMinTTL_CompressedAnswerOwner(t *testing.T) {
	pkt := buildMessage(t, 1, 0x8180, "backend.internal.test", 1, 1,
		buildPointerRR(12, 1, 1, 300, net.ParseIP("10.9.9.9").To4()))
	if got := getMinTTL(pkt); got != 300 {
		t.Fatalf("getMinTTL = %d, want 300", got)
	}
}

func TestGetMinTTL_MultipleCompressedAnswersPicksMinimum(t *testing.T) {
	ip := net.ParseIP("10.9.9.9").To4()
	pkt := buildMessage(t, 1, 0x8180, "multi.test", 1, 1,
		buildPointerRR(12, 1, 1, 500, ip),
		buildPointerRR(12, 1, 1, 50, ip),
		buildPointerRR(12, 1, 1, 900, ip),
	)
	if got := getMinTTL(pkt); got != 50 {
		t.Fatalf("getMinTTL = %d, want 50 (the minimum across all three answers)", got)
	}
}

func TestHasOPT_DetectsOPTPastACompressedAnswer(t *testing.T) {
	ip := net.ParseIP("10.9.9.9").To4()
	pkt := buildMessage(t, 1, 0x8180, "backend.internal.test", 1, 1,
		buildPointerRR(12, 1, 1, 300, ip))
	pkt = append(pkt, buildOPT(4096)...)
	binary.BigEndian.PutUint16(pkt[10:12], 1) // arcount = 1
	if !hasOPT(pkt) {
		t.Fatal("hasOPT = false, want true (OPT record is present past a compressed answer)")
	}
}

func TestHasOPT_FalseWithNoOPTRecord(t *testing.T) {
	ip := net.ParseIP("10.9.9.9").To4()
	pkt := buildMessage(t, 1, 0x8180, "backend.internal.test", 1, 1,
		buildPointerRR(12, 1, 1, 300, ip))
	if hasOPT(pkt) {
		t.Fatal("hasOPT = true, want false (no OPT record in this message)")
	}
}

func TestDecrementTTLs_CompressedAnswerOwner_WritesCorrectOffsetOnly(t *testing.T) {
	ip := net.ParseIP("10.9.9.9").To4()
	pkt := buildMessage(t, 1, 0x8180, "backend.internal.test", 1, 1,
		buildPointerRR(12, 1, 1, 300, ip))
	before := append([]byte{}, pkt...)

	decrementTTLs(pkt, 100)

	off, _ := questionEndOffset(pkt)
	_, _, _, ttl, rdata, _, ok := parseRR(pkt, off)
	if !ok {
		t.Fatal("parseRR failed after decrementTTLs")
	}
	if ttl != 200 {
		t.Fatalf("ttl after decrementTTLs(100) = %d, want 200", ttl)
	}
	if string(rdata) != string(ip) {
		t.Fatalf("rdata corrupted by decrementTTLs: got %v, want %v — the pre-fix bug wrote the new TTL at the WRONG offset, clobbering unrelated bytes", rdata, ip)
	}
	rrFieldsOffset, _ := skipRRName(pkt, off)
	ttlOffset := rrFieldsOffset + 4
	for i := range before {
		if i >= ttlOffset && i < ttlOffset+4 {
			continue // the TTL field itself, expected to differ
		}
		if before[i] != pkt[i] {
			t.Fatalf("byte %d changed unexpectedly: before=%#x after=%#x — decrementTTLs wrote outside the TTL field", i, before[i], pkt[i])
		}
	}
}

// ------------------------- rewriteResponseNames -------------------------

func TestRewriteResponseNames_TranslatesQuestionAndCompressedAnswerOwner(t *testing.T) {
	ip := net.ParseIP("10.9.9.9").To4()
	resp := buildMessage(t, 0x1234, 0x8180, "backend.internal.test", 1, 1,
		buildPointerRR(12, 1, 1, 300, ip))

	out, err := rewriteResponseNames(resp, "backend.internal.test", "app.dantetest.local")
	if err != nil {
		t.Fatalf("rewriteResponseNames: %v", err)
	}

	qname, qtype, qclass, ok := parseQuestion(out)
	if !ok || qname != "app.dantetest.local" || qtype != 1 || qclass != 1 {
		t.Fatalf("question = %q/%d/%d, %v; want app.dantetest.local/1/1, true", qname, qtype, qclass, ok)
	}
	off, _ := questionEndOffset(out)
	owner, rtype, rclass, ttl, rdata, _, ok := parseRR(out, off)
	if !ok {
		t.Fatal("parseRR on rewritten response failed")
	}
	if owner != "app.dantetest.local" {
		t.Errorf("answer owner = %q, want %q (translated back to the client's own name)", owner, "app.dantetest.local")
	}
	if rtype != 1 || rclass != 1 || ttl != 300 {
		t.Errorf("rtype/rclass/ttl = %d/%d/%d, want 1/1/300", rtype, rclass, ttl)
	}
	if string(rdata) != string(ip) {
		t.Errorf("rdata = %v, want %v", rdata, ip)
	}
}

func TestRewriteResponseNames_LeavesNonMatchingRDATAUntouched(t *testing.T) {
	cnameTarget := mustEncodeName(t, "backend.internal.test")
	resp := buildMessage(t, 1, 0x8180, "backend.internal.test", 5, 1,
		buildPointerRR(12, 5, 1, 300, cnameTarget))

	out, err := rewriteResponseNames(resp, "backend.internal.test", "app.dantetest.local")
	if err != nil {
		t.Fatalf("rewriteResponseNames: %v", err)
	}
	off, _ := questionEndOffset(out)
	_, _, _, _, rdata, _, ok := parseRR(out, off)
	if !ok {
		t.Fatal("parseRR failed")
	}
	if string(rdata) != string(cnameTarget) {
		t.Fatalf("CNAME RDATA changed: got %v, want %v unchanged", rdata, cnameTarget)
	}
}

func TestRewriteResponseNames_NoMatchLeavesNamesAsIs(t *testing.T) {
	ip := net.ParseIP("10.9.9.1").To4()
	resp := buildMessage(t, 1, 0x8180, "normal.forward.test", 1, 1,
		buildPointerRR(12, 1, 1, 300, ip))
	out, err := rewriteResponseNames(resp, "something-else.test", "irrelevant")
	if err != nil {
		t.Fatalf("rewriteResponseNames: %v", err)
	}
	qname, _, _, _ := parseQuestion(out)
	if qname != "normal.forward.test" {
		t.Fatalf("qname = %q, want unchanged %q", qname, "normal.forward.test")
	}
}

// ------------------------- buildRewrittenQuery -------------------------

func TestBuildRewrittenQuery_PreservesEDNSAdditionalSectionVerbatim(t *testing.T) {
	opt := buildOPT(4096)
	query := buildMessage(t, 0xabcd, 0x0100, "app.dantetest.local", 1, 1)
	query = append(query, opt...)
	binary.BigEndian.PutUint16(query[10:12], 1) // arcount = 1

	qnameEnd, ok := questionEndOffset(query)
	if !ok {
		t.Fatal("questionEndOffset failed")
	}
	out, err := buildRewrittenQuery(query, qnameEnd, "backend.internal.test", 1, 1)
	if err != nil {
		t.Fatalf("buildRewrittenQuery: %v", err)
	}

	if binary.BigEndian.Uint16(out[0:2]) != 0xabcd {
		t.Errorf("ID changed: got %#x, want %#x", binary.BigEndian.Uint16(out[0:2]), 0xabcd)
	}
	qname, qtype, qclass, ok := parseQuestion(out)
	if !ok || qname != "backend.internal.test" || qtype != 1 || qclass != 1 {
		t.Fatalf("question = %q/%d/%d, %v; want backend.internal.test/1/1, true", qname, qtype, qclass, ok)
	}
	// The OPT record must be copied through byte-for-byte, unmodified.
	newQNameEnd, _ := questionEndOffset(out)
	if got := out[newQNameEnd:]; string(got) != string(opt) {
		t.Fatalf("EDNS OPT record changed: got %v, want %v", got, opt)
	}
}

// ------------------------- makeSynthesizedAnswer -------------------------

func TestMakeSynthesizedAnswer_AQueryGetsARecord(t *testing.T) {
	query := buildMessage(t, 0x1111, 0x0100, "blocked.answertest.local", 1, 1)
	qnameEnd, _ := questionEndOffset(query)
	ip := net.ParseIP("203.0.113.55")

	resp := makeSynthesizedAnswer(query, qnameEnd, ip, 30, true)

	if binary.BigEndian.Uint16(resp[0:2]) != 0x1111 {
		t.Errorf("ID not echoed")
	}
	ancount := binary.BigEndian.Uint16(resp[6:8])
	if ancount != 1 {
		t.Fatalf("ancount = %d, want 1", ancount)
	}
	off, _ := questionEndOffset(resp)
	owner, rtype, rclass, ttl, rdata, _, ok := parseRR(resp, off)
	if !ok {
		t.Fatal("parseRR on synthesized answer failed")
	}
	if owner != "blocked.answertest.local" || rtype != 1 || rclass != 1 || ttl != 30 {
		t.Errorf("owner/rtype/rclass/ttl = %q/%d/%d/%d, want blocked.answertest.local/1/1/30", owner, rtype, rclass, ttl)
	}
	if string(rdata) != string(ip.To4()) {
		t.Errorf("rdata = %v, want %v", rdata, ip.To4())
	}
}

func TestMakeSynthesizedAnswer_NonAQueryGetsEmptyNoError(t *testing.T) {
	query := buildMessage(t, 0x2222, 0x0100, "blocked.answertest.local", 28, 1) // AAAA
	qnameEnd, _ := questionEndOffset(query)
	resp := makeSynthesizedAnswer(query, qnameEnd, net.ParseIP("203.0.113.55"), 30, false)

	ancount := binary.BigEndian.Uint16(resp[6:8])
	if ancount != 0 {
		t.Fatalf("ancount = %d, want 0 (never a record for a non-A qtype)", ancount)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	rcode := flags & 0xF
	if rcode != 0 {
		t.Fatalf("rcode = %d, want 0 (NOERROR)", rcode)
	}
}

// ------------------------- resolveRewriteRules -------------------------

func TestResolveRewriteRules_RequiresExactlyOneAction(t *testing.T) {
	cases := []struct {
		name    string
		rule    RewriteRule
		wantErr bool
	}{
		{"neither set", RewriteRule{Match: "x.test"}, true},
		{"both set", RewriteRule{Match: "x.test", Answer: "1.2.3.4", Rewrite: "y.test"}, true},
		{"answer only", RewriteRule{Match: "x.test", Answer: "1.2.3.4"}, false},
		{"rewrite only", RewriteRule{Match: "x.test", Rewrite: "y.test"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := resolveRewriteRules([]RewriteRule{c.rule})
			if (err != nil) != c.wantErr {
				t.Fatalf("resolveRewriteRules(%+v) err = %v, wantErr %v", c.rule, err, c.wantErr)
			}
		})
	}
}

func TestResolveRewriteRules_RejectsInvalidAnswerIP(t *testing.T) {
	_, err := resolveRewriteRules([]RewriteRule{{Match: "x.test", Answer: "not-an-ip"}})
	if err == nil {
		t.Fatal("expected an error for an invalid answer IP")
	}
}

func TestResolveRewriteRules_RejectsEmptyMatch(t *testing.T) {
	_, err := resolveRewriteRules([]RewriteRule{{Match: "  ", Answer: "1.2.3.4"}})
	if err == nil {
		t.Fatal("expected an error for an empty match")
	}
}

func TestResolveRewriteRules_WildcardRequiresBaseDomain(t *testing.T) {
	_, err := resolveRewriteRules([]RewriteRule{{Match: "*..", Answer: "1.2.3.4"}})
	if err == nil {
		t.Fatal("expected an error for a wildcard with no base domain")
	}
}

func TestResolveRewriteRules_DefaultsAnswerTTLTo60(t *testing.T) {
	resolved, err := resolveRewriteRules([]RewriteRule{{Match: "x.test", Answer: "1.2.3.4"}})
	if err != nil {
		t.Fatalf("resolveRewriteRules: %v", err)
	}
	if resolved[0].ttl != 60 {
		t.Fatalf("ttl = %d, want default 60", resolved[0].ttl)
	}
}

func TestResolveRewriteRules_NormalizesCaseAndTrailingDot(t *testing.T) {
	resolved, err := resolveRewriteRules([]RewriteRule{{Match: "App.DanteTest.Local.", Rewrite: "Backend.Internal.Test."}})
	if err != nil {
		t.Fatalf("resolveRewriteRules: %v", err)
	}
	if resolved[0].exact != "app.dantetest.local" {
		t.Errorf("exact = %q, want normalized lowercase, no trailing dot", resolved[0].exact)
	}
	if resolved[0].rewriteTo != "backend.internal.test" {
		t.Errorf("rewriteTo = %q, want normalized lowercase, no trailing dot", resolved[0].rewriteTo)
	}
}

// ------------------------- resolvedRewriteRule.matches / target -------------------------

func TestResolvedRewriteRule_ExactMatch(t *testing.T) {
	resolved, _ := resolveRewriteRules([]RewriteRule{{Match: "app.dantetest.local", Rewrite: "backend.internal.test"}})
	r := &resolved[0]
	if !r.matches("app.dantetest.local") {
		t.Error("expected an exact match")
	}
	if r.matches("sub.app.dantetest.local") {
		t.Error("an exact-match rule must not match a subdomain")
	}
}

func TestResolvedRewriteRule_WildcardMatchesBaseAndSubdomains(t *testing.T) {
	resolved, _ := resolveRewriteRules([]RewriteRule{{Match: "*.wild.test", Rewrite: "wild-backend.test"}})
	r := &resolved[0]
	if !r.matches("wild.test") {
		t.Error("wildcard rule should match its own base domain")
	}
	if !r.matches("host1.wild.test") {
		t.Error("wildcard rule should match a subdomain")
	}
	if r.matches("notwild.test") {
		t.Error("wildcard rule must not match an unrelated domain sharing a suffix substring")
	}
}

func TestResolvedRewriteRule_TargetPreservesPrefixForWildcard(t *testing.T) {
	resolved, _ := resolveRewriteRules([]RewriteRule{{Match: "*.wild.test", Rewrite: "wild-backend.test"}})
	r := &resolved[0]
	if got := r.target("host1.wild.test"); got != "host1.wild-backend.test" {
		t.Errorf("target = %q, want %q", got, "host1.wild-backend.test")
	}
	if got := r.target("wild.test"); got != "wild-backend.test" {
		t.Errorf("target(base) = %q, want %q (no stray leading dot)", got, "wild-backend.test")
	}
}

func TestResolvedRewriteRule_TargetForExactMatchIsAlwaysTheLiteralReplacement(t *testing.T) {
	resolved, _ := resolveRewriteRules([]RewriteRule{{Match: "app.dantetest.local", Rewrite: "backend.internal.test"}})
	if got := resolved[0].target("app.dantetest.local"); got != "backend.internal.test" {
		t.Errorf("target = %q, want %q", got, "backend.internal.test")
	}
}

// ------------------------- matchRewrite -------------------------

func TestMatchRewrite_FirstMatchWins(t *testing.T) {
	ifaceRule, _ := resolveRewriteRules([]RewriteRule{{Match: "app.dantetest.local", Answer: "192.0.2.99"}})
	globalRule, _ := resolveRewriteRules([]RewriteRule{{Match: "app.dantetest.local", Rewrite: "backend.internal.test"}})
	acl := &resolvedACL{rewrites: append(ifaceRule, globalRule...)} // interface rule prepended, matching resolveACL's own order

	d := matchRewrite(acl, "app.dantetest.local", 1)
	if d.answer == nil || d.answer.String() != "192.0.2.99" {
		t.Fatalf("expected the interface-specific answer rule to win, got %+v", d)
	}
}

func TestMatchRewrite_NoMatchIsZeroValue(t *testing.T) {
	acl := &resolvedACL{}
	d := matchRewrite(acl, "unrelated.test", 1)
	if d.answer != nil || d.rewritten {
		t.Fatalf("expected a zero-value decision, got %+v", d)
	}
}

func TestMatchRewrite_NilACLIsSafe(t *testing.T) {
	d := matchRewrite(nil, "x.test", 1)
	if d.answer != nil || d.rewritten {
		t.Fatalf("expected a zero-value decision for a nil ACL, got %+v", d)
	}
}

// ------------------------- resolveACL: rewrite merge semantics -------------------------

func TestResolveACL_InterfaceRewritesAreAdditiveNotReplacing(t *testing.T) {
	origRewrites := cfg.Rewrites
	origACLs := cfg.InterfaceACLs
	defer func() { cfg.Rewrites = origRewrites; cfg.InterfaceACLs = origACLs }()

	cfg.Rewrites = []RewriteRule{{Match: "global.test", Rewrite: "global-target.test"}}
	cfg.InterfaceACLs = map[string]ACLConfig{
		"dnstest1": {Rewrites: []RewriteRule{{Match: "iface-only.test", Rewrite: "iface-target.test"}}},
	}

	withOverride, err := resolveACL("dnstest1")
	if err != nil {
		t.Fatalf("resolveACL(dnstest1): %v", err)
	}
	if len(withOverride.rewrites) != 2 {
		t.Fatalf("dnstest1 rewrites = %d, want 2 (its own rule PLUS the global one)", len(withOverride.rewrites))
	}
	if !withOverride.rewrites[0].matches("iface-only.test") {
		t.Error("the interface's own rule must be checked first")
	}

	withoutOverride, err := resolveACL("dnstest0")
	if err != nil {
		t.Fatalf("resolveACL(dnstest0): %v", err)
	}
	if len(withoutOverride.rewrites) != 1 {
		t.Fatalf("dnstest0 rewrites = %d, want 1 (only the global rule)", len(withoutOverride.rewrites))
	}
}

func TestResolveACL_RejectsInvalidGlobalRewrite(t *testing.T) {
	origRewrites := cfg.Rewrites
	defer func() { cfg.Rewrites = origRewrites }()
	cfg.Rewrites = []RewriteRule{{Match: "bad.test", Answer: "not-an-ip"}}

	if _, err := resolveACL("anything"); err == nil {
		t.Fatal("expected resolveACL to reject a malformed cluster-wide rewrite rule")
	}
}

// ------------------------- aclDenies -------------------------

func TestACLDenies(t *testing.T) {
	cases := []struct {
		name  string
		acl   *resolvedACL
		qname string
		qtype uint16
		want  bool
	}{
		{"nil acl never denies", nil, "x.test", 1, false},
		{"empty acl never denies", &resolvedACL{}, "x.test", 1, false},
		{"denied qtype", &resolvedACL{deniedQTypes: map[uint16]bool{28: true}}, "x.test", 28, true},
		{"allowed qtype whitelist excludes others", &resolvedACL{allowedQTypes: map[uint16]bool{1: true}}, "x.test", 28, true},
		{"allowed qtype whitelist permits listed", &resolvedACL{allowedQTypes: map[uint16]bool{1: true}}, "x.test", 1, false},
		{"denied domain exact", &resolvedACL{deniedDomains: []string{"blocked.example"}}, "blocked.example", 1, true},
		{"denied domain subdomain", &resolvedACL{deniedDomains: []string{"blocked.example"}}, "sub.blocked.example", 1, true},
		{"allowed domain whitelist excludes others", &resolvedACL{allowedDomains: []string{"ok.example"}}, "other.example", 1, true},
		{"allowed domain whitelist permits listed", &resolvedACL{allowedDomains: []string{"ok.example"}}, "ok.example", 1, false},
		{"deny wins over allow on the same axis", &resolvedACL{allowedDomains: []string{"x.example"}, deniedDomains: []string{"x.example"}}, "x.example", 1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := aclDenies(c.acl, c.qname, c.qtype); got != c.want {
				t.Errorf("aclDenies(...) = %v, want %v", got, c.want)
			}
		})
	}
}

func TestDomainListMatches(t *testing.T) {
	domains := normalizeDomains([]string{"Blocked.Example."})
	if !domainListMatches(domains, "blocked.example") {
		t.Error("expected an exact match after normalization")
	}
	if !domainListMatches(domains, "sub.blocked.example") {
		t.Error("expected a subdomain match")
	}
	if domainListMatches(domains, "notblocked.example") {
		t.Error("must not match an unrelated domain sharing a suffix substring")
	}
}

// ------------------------- makeRefused / makeServFail -------------------------

func TestMakeRefused_SetsRCODE5(t *testing.T) {
	query := buildMessage(t, 0x9999, 0x0100, "blocked.example", 1, 1)
	resp := makeRefused(query)
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0xF != 5 {
		t.Fatalf("rcode = %d, want 5 (REFUSED)", flags&0xF)
	}
	if flags&0x8000 == 0 {
		t.Fatal("QR bit not set on the response")
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 0x9999 {
		t.Fatal("ID not echoed")
	}
}

func TestMakeServFail_SetsRCODE2(t *testing.T) {
	query := buildMessage(t, 0x8888, 0x0100, "x.test", 1, 1)
	resp := makeServFail(query)
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0xF != 2 {
		t.Fatalf("rcode = %d, want 2 (SERVFAIL)", flags&0xF)
	}
}

// ------------------------- validateDNSQuery / validateDNSResponse -------------------------

func TestValidateDNSQuery(t *testing.T) {
	good := buildMessage(t, 1, 0x0100, "x.test", 1, 1)
	if !validateDNSQuery(good) {
		t.Error("a well-formed query should validate")
	}
	notAQuery := buildMessage(t, 1, 0x8100, "x.test", 1, 1) // QR set — this is a response, not a query
	if validateDNSQuery(notAQuery) {
		t.Error("a message with QR set must not validate as a query")
	}
}

func TestValidateDNSResponse(t *testing.T) {
	ip := net.ParseIP("10.9.9.9").To4()
	good := buildMessage(t, 42, 0x8180, "x.test", 1, 1, buildPointerRR(12, 1, 1, 60, ip))
	if !validateDNSResponse(good, 42, "x.test", 1, 1) {
		t.Error("a well-formed, matching response should validate")
	}
	if validateDNSResponse(good, 43, "x.test", 1, 1) {
		t.Error("a response with the wrong ID must not validate")
	}
	if validateDNSResponse(good, 42, "other.test", 1, 1) {
		t.Error("a response for the wrong question must not validate")
	}
}

// ------------------------- cache -------------------------

func TestCacheSetGet_RoundTripsAndDecrementsTTL(t *testing.T) {
	ip := net.ParseIP("10.9.9.42").To4()
	resp := buildMessage(t, 1, 0x8180, "cachetest.internal.test", 1, 1,
		buildPointerRR(12, 1, 1, 300, ip))
	key := cacheKey{qnameRaw: string(mustEncodeName(t, "cachetest.internal.test")), qtype: 1, qclass: 1}

	cacheSet(key, resp, 300)
	got, found := cacheGet(key)
	if !found {
		t.Fatal("expected a cache hit immediately after cacheSet")
	}
	off, _ := questionEndOffset(got)
	_, _, _, ttl, rdata, _, ok := parseRR(got, off)
	if !ok {
		t.Fatal("parseRR on cached response failed")
	}
	if ttl > 300 {
		t.Fatalf("ttl = %d, must never exceed the stored value (300)", ttl)
	}
	if string(rdata) != string(ip) {
		t.Fatalf("rdata = %v, want %v — cacheGet's own TTL decrement must not corrupt the record", rdata, ip)
	}
}

func TestCacheSet_ZeroTTLIsNeverCached(t *testing.T) {
	resp := buildMessage(t, 1, 0x8180, "notcached.test", 1, 1,
		buildPointerRR(12, 1, 1, 0, net.ParseIP("10.0.0.1").To4()))
	key := cacheKey{qnameRaw: string(mustEncodeName(t, "notcached.test")), qtype: 1, qclass: 1}
	cacheSet(key, resp, 0)
	if _, found := cacheGet(key); found {
		t.Fatal("a ttl=0 cacheSet must never actually be retrievable")
	}
}

// buildSizedEntry builds a cacheable response whose total wire length is
// exactly n bytes, and the cache key it would be stored/looked up under.
func buildSizedEntry(t testing.TB, qname string, n int) ([]byte, cacheKey) {
	t.Helper()
	base := buildMessage(t, 1, 0x8180, qname, 1, 1, buildPointerRR(12, 1, 1, 300, nil))
	if n < len(base) {
		t.Fatalf("buildSizedEntry(%d): below the minimum possible size (%d)", n, len(base))
	}
	resp := buildMessage(t, 1, 0x8180, qname, 1, 1, buildPointerRR(12, 1, 1, 300, make([]byte, n-len(base))))
	key := cacheKey{qnameRaw: string(mustEncodeName(t, qname)), qtype: 1, qclass: 1}
	return resp, key
}

// cacheMaxBytesTestCleanup saves cfg.CacheMaxBytes, sets it to want, and
// returns a cleanup restoring it plus flushing the cache.
func cacheMaxBytesTestCleanup(t *testing.T, want int) {
	t.Helper()
	orig := cfg.CacheMaxBytes
	cfg.CacheMaxBytes = want
	cacheFlushAll()
	t.Cleanup(func() {
		cfg.CacheMaxBytes = orig
		cacheFlushAll()
	})
}

func TestCacheSet_CacheMaxBytesZeroDisablesByteCeiling(t *testing.T) {
	cacheMaxBytesTestCleanup(t, 0)

	var keys []cacheKey
	for i := 0; i < 5; i++ {
		resp, key := buildSizedEntry(t, fmt.Sprintf("bytecap-disabled-%d.test", i), 500)
		cacheSet(key, resp, 300)
		keys = append(keys, key)
	}
	for i, key := range keys {
		if _, found := cacheGet(key); !found {
			t.Errorf("entry %d evicted even though CacheMaxBytes=0 (disabled)", i)
		}
	}
}

// sameShardQNames returns n distinct qnames (candidate-%d.test, counting
// from 0) that all hash to the SAME cache shard as each other.
func sameShardQNames(t testing.TB, prefix string, n int) []string {
	t.Helper()
	var out []string
	want := -1
	for i := 0; len(out) < n; i++ {
		if i > 100000 {
			t.Fatalf("sameShardQNames(%q, %d): couldn't find %d same-shard names within 100000 tries", prefix, n, n)
		}
		name := fmt.Sprintf("%s-%d.test", prefix, i)
		idx := cacheShardIndex(cacheKey{qnameRaw: string(mustEncodeName(t, name)), qtype: 1, qclass: 1})
		if want == -1 {
			want = idx
		}
		if idx == want {
			out = append(out, name)
		}
	}
	return out
}

func TestCacheSet_ByteCeilingEvictsOldestToStayUnderBudget(t *testing.T) {
	// Budget fits exactly 2 of these ~500-byte entries — the 3rd must
	// evict the 1st (oldest, this shard's own FIFO order), not the 2nd.
	cacheMaxBytesTestCleanup(t, 1000)

	names := sameShardQNames(t, "bytecap-evict", 3)
	resp1, key1 := buildSizedEntry(t, names[0], 500)
	resp2, key2 := buildSizedEntry(t, names[1], 500)
	resp3, key3 := buildSizedEntry(t, names[2], 500)

	cacheSet(key1, resp1, 300)
	cacheSet(key2, resp2, 300)
	if _, found := cacheGet(key1); !found {
		t.Fatal("entry 1 should still be cached before the 3rd insert (budget not yet exceeded)")
	}

	cacheSet(key3, resp3, 300)

	if _, found := cacheGet(key1); found {
		t.Error("entry 1 (oldest) should have been evicted once the byte budget was exceeded")
	}
	if _, found := cacheGet(key2); !found {
		t.Error("entry 2 should NOT have been evicted — only the oldest entry needed to go")
	}
	if _, found := cacheGet(key3); !found {
		t.Error("entry 3 (just inserted) should be cached")
	}
	if got := cacheBytesUsed.Load(); got > 1000 {
		t.Errorf("cacheBytesUsed = %d, want <= the configured 1000-byte budget", got)
	}
}

func TestCacheSet_EntryLargerThanWholeBudgetIsSkipped(t *testing.T) {
	cacheMaxBytesTestCleanup(t, 200)

	resp, key := buildSizedEntry(t, "bytecap-toolarge.test", 500)
	before := cacheBytesUsed.Load()
	cacheSet(key, resp, 300)

	if _, found := cacheGet(key); found {
		t.Error("an entry larger than the whole configured budget must never be cached, not evict its way in")
	}
	if got := cacheBytesUsed.Load(); got != before {
		t.Errorf("cacheBytesUsed changed (%d -> %d) for an entry that was never actually cached", before, got)
	}
}

func TestCacheBytesUsed_TracksThroughExpiryEviction(t *testing.T) {
	cacheMaxBytesTestCleanup(t, 0)

	resp, key := buildSizedEntry(t, "bytecap-expiry.test", 500)
	before := cacheBytesUsed.Load()
	cacheSet(key, resp, 300)
	if got := cacheBytesUsed.Load(); got != before+int64(len(resp)) {
		t.Fatalf("cacheBytesUsed = %d, want %d right after cacheSet", got, before+int64(len(resp)))
	}

	shard := cacheShards[cacheShardIndex(key)]
	shard.mu.Lock()
	shard.items[key].expires = time.Now().Add(-time.Second)
	shard.mu.Unlock()

	if _, found := cacheGet(key); found {
		t.Fatal("cacheGet must not return an already-expired entry")
	}
	if got := cacheBytesUsed.Load(); got != before {
		t.Errorf("cacheBytesUsed = %d, want back to %d after the expired entry was evicted", got, before)
	}
}

func TestCacheFlushAll_ResetsCacheBytesUsed(t *testing.T) {
	cacheMaxBytesTestCleanup(t, 0)

	resp, key := buildSizedEntry(t, "bytecap-flush.test", 500)
	cacheSet(key, resp, 300)
	if cacheBytesUsed.Load() == 0 {
		t.Fatal("cacheBytesUsed should be nonzero right after cacheSet")
	}

	cacheFlushAll()

	if got := cacheBytesUsed.Load(); got != 0 {
		t.Errorf("cacheBytesUsed = %d, want 0 after cacheFlushAll", got)
	}
}

// ------------------------- cache stats file -------------------------

func TestBuildCacheStatsSnapshot_ComputesHitRateFromRealCounters(t *testing.T) {
	origHits, origMisses := cacheHits.Load(), cacheMisses.Load()
	cacheHits.Store(0)
	cacheMisses.Store(0)
	t.Cleanup(func() { cacheHits.Store(origHits); cacheMisses.Store(origMisses) })

	cacheHits.Add(3)
	cacheMisses.Add(1)

	snap := buildCacheStatsSnapshot()
	if snap.Hits != 3 || snap.Misses != 1 {
		t.Fatalf("Hits/Misses = %d/%d, want 3/1", snap.Hits, snap.Misses)
	}
	if snap.HitRatePct != 75.0 {
		t.Errorf("HitRatePct = %v, want 75.0 (3 hits / 4 total)", snap.HitRatePct)
	}
	if snap.UpdatedAt == "" {
		t.Error("UpdatedAt is empty, want a real RFC3339 timestamp")
	}
}

func TestBuildCacheStatsSnapshot_ZeroTotalIsZeroPercentNotNaN(t *testing.T) {
	origHits, origMisses := cacheHits.Load(), cacheMisses.Load()
	cacheHits.Store(0)
	cacheMisses.Store(0)
	t.Cleanup(func() { cacheHits.Store(origHits); cacheMisses.Store(origMisses) })

	snap := buildCacheStatsSnapshot()
	if snap.HitRatePct != 0 {
		t.Errorf("HitRatePct = %v, want 0 with zero hits and zero misses (not NaN/Inf from a 0/0 division)", snap.HitRatePct)
	}
}

func TestWriteCacheStatsSnapshot_RoundTripsRealJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.json")
	snap := cacheStatsSnapshot{
		Entries: 42, CacheSize: 5000, CacheMaxBytes: 8388608,
		BytesUsed: 12345, Hits: 100, Misses: 20, HitRatePct: 83.3,
		UpdatedAt: "2026-09-12T12:00:00Z",
	}
	if err := writeCacheStatsSnapshot(snap, path); err != nil {
		t.Fatalf("writeCacheStatsSnapshot: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got cacheStatsSnapshot
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal written file: %v", err)
	}
	if got != snap {
		t.Errorf("round-tripped snapshot = %+v, want %+v", got, snap)
	}
	// No leftover .tmp file after a successful write.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("stats.json.tmp still exists after a successful write (err=%v)", err)
	}
}

// ------------------------- reconfigureInterfaces / reloadInterfaces
// -------------------------

func TestReconfigureInterfaces_AppliesWhenAtLeastOneNameResolves(t *testing.T) {
	if ok := reconfigureInterfaces([]string{"lo"}); !ok {
		t.Fatal("reconfigureInterfaces([lo]) = false, want true")
	}
	ifaces := allowedIfaces.Load()
	if ifaces == nil || len(*ifaces) != 1 {
		t.Fatalf("allowedIfaces after reconfigure = %v, want exactly 1 entry", ifaces)
	}
}

func TestReconfigureInterfaces_RefusesAndKeepsOldSetWhenEveryNameFails(t *testing.T) {
	if ok := reconfigureInterfaces([]string{"lo"}); !ok {
		t.Fatal("setup: reconfigureInterfaces([lo]) failed")
	}
	before := allowedIfaces.Load()

	if ok := reconfigureInterfaces([]string{"definitely-not-a-real-interface-xyz"}); ok {
		t.Fatal("reconfigureInterfaces with an unresolvable-only list must return false")
	}
	after := allowedIfaces.Load()
	if after != before {
		t.Fatal("a refused reload must leave allowedIfaces completely untouched (same pointer, not just same content)")
	}
}

func TestReloadInterfaces_RestoresInterfaceACLsAndRewritesOnRefusal(t *testing.T) {
	if ok := reconfigureInterfaces([]string{"lo"}); !ok {
		t.Fatal("setup: reconfigureInterfaces([lo]) failed")
	}
	cfg.InterfaceACLs = map[string]ACLConfig{"lo": {RateLimit: intPtr(7)}}
	cfg.Rewrites = []RewriteRule{{Match: "old-rule.test", Answer: "1.1.1.1"}}

	dir := t.TempDir()
	path := filepath.Join(dir, "dnsrelay-reload-test.json")
	body := `{"allowed_interfaces": ["definitely-not-a-real-interface-xyz"], ` +
		`"interface_acls": {"lo": {"rate_limit": 999}}, ` +
		`"rewrites": [{"match": "new-rule.test", "answer": "2.2.2.2"}]}`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	reloadInterfaces(path)

	if got := cfg.InterfaceACLs["lo"].RateLimit; got == nil || *got != 7 {
		t.Errorf("cfg.InterfaceACLs was committed despite a refused reload: %+v", cfg.InterfaceACLs)
	}
	if len(cfg.Rewrites) != 1 || cfg.Rewrites[0].Match != "old-rule.test" {
		t.Errorf("cfg.Rewrites was committed despite a refused reload: %+v", cfg.Rewrites)
	}
}

func TestReloadInterfaces_CommitsInterfaceACLsAndRewritesOnSuccess(t *testing.T) {
	if ok := reconfigureInterfaces([]string{"lo"}); !ok {
		t.Fatal("setup: reconfigureInterfaces([lo]) failed")
	}
	cfg.InterfaceACLs = nil
	cfg.Rewrites = nil

	dir := t.TempDir()
	path := filepath.Join(dir, "dnsrelay-reload-ok-test.json")
	body := `{"allowed_interfaces": ["lo"], ` +
		`"interface_acls": {"lo": {"rate_limit": 55}}, ` +
		`"rewrites": [{"match": "applied-rule.test", "answer": "3.3.3.3"}]}`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	reloadInterfaces(path)

	if got := cfg.InterfaceACLs["lo"].RateLimit; got == nil || *got != 55 {
		t.Fatalf("cfg.InterfaceACLs not applied after a successful reload: %+v", cfg.InterfaceACLs)
	}
	if len(cfg.Rewrites) != 1 || cfg.Rewrites[0].Match != "applied-rule.test" {
		t.Fatalf("cfg.Rewrites not applied after a successful reload: %+v", cfg.Rewrites)
	}
}

func intPtr(v int) *int { return &v }

func TestOpenAddrSocket_CoexistsWithADifferentSpecificAddressOnSamePort(t *testing.T) {
	probe, err := net.Listen("tcp4", "127.0.10.1:0")
	if err != nil {
		t.Skipf("cannot even probe-bind a loopback alias on this host, skipping: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	// Stand-in for dnsmasq.central: a real TCP listener already
	// holding this exact port on ITS OWN specific address.
	other, err := net.Listen("tcp4", fmt.Sprintf("127.0.10.1:%d", port))
	if err != nil {
		t.Fatalf("setup: simulated dnsmasq.central listener failed: %v", err)
	}
	defer other.Close()

	sock, err := openAddrSocket(net.ParseIP("127.0.10.2"), 0, &ifaceInfo{acl: &resolvedACL{}}, port)
	if err != nil {
		t.Fatalf("openAddrSocket on a different specific address, same port, failed: %v — this exact coexistence is what dnshived-dnsrelay's whole per-address design depends on", err)
	}
	closeAddrSocket(sock)
}

func TestReconcileAddrSocketsLocked_OpensAndClosesWithInterfaceSet(t *testing.T) {
	reconcileMu.Lock()
	savedOpen := openSockets
	openSockets = make(map[uint32]*addrSocket)
	reconcileMu.Unlock()
	savedIfaces := allowedIfaces.Load()
	defer func() {
		reconcileMu.Lock()
		for _, s := range openSockets {
			closeAddrSocket(s)
		}
		openSockets = savedOpen
		reconcileMu.Unlock()
		allowedIfaces.Store(savedIfaces)
	}()

	if ok := reconfigureInterfaces([]string{"lo"}); !ok {
		t.Fatal("setup: reconfigureInterfaces([lo]) failed")
	}
	reconcileMu.Lock()
	n := len(openSockets)
	reconcileMu.Unlock()
	if n == 0 {
		t.Fatal("expected at least one socket bound for lo's own live address(es)")
	}

	if ok := reconfigureInterfaces([]string{"definitely-not-a-real-interface-xyz"}); ok {
		t.Fatal("setup: expected this reload to be refused")
	}
	reconcileMu.Lock()
	stillOpen := len(openSockets)
	reconcileMu.Unlock()
	if stillOpen != n {
		t.Fatalf("a refused interface reload changed the open socket count: %d -> %d", n, stillOpen)
	}
}

func TestReconcileAddrSocketsLocked_UpdatesACLWithoutReopening(t *testing.T) {
	reconcileMu.Lock()
	savedOpen := openSockets
	openSockets = make(map[uint32]*addrSocket)
	reconcileMu.Unlock()
	savedIfaces := allowedIfaces.Load()
	savedGlobalRewrites := cfg.Rewrites
	defer func() {
		reconcileMu.Lock()
		for _, s := range openSockets {
			closeAddrSocket(s)
		}
		openSockets = savedOpen
		reconcileMu.Unlock()
		allowedIfaces.Store(savedIfaces)
		cfg.Rewrites = savedGlobalRewrites
	}()

	if ok := reconfigureInterfaces([]string{"lo"}); !ok {
		t.Fatal("setup: reconfigureInterfaces([lo]) failed")
	}
	reconcileMu.Lock()
	var before *addrSocket
	for _, s := range openSockets {
		before = s
		break
	}
	reconcileMu.Unlock()
	if before == nil {
		t.Fatal("setup: no socket open for lo")
	}
	beforeUDP := before.udpConn

	cfg.Rewrites = []RewriteRule{{Match: "acl-update-marker.test", Answer: "9.9.9.9"}}
	if ok := reconfigureInterfaces([]string{"lo"}); !ok {
		t.Fatal("reconfigureInterfaces([lo]) (second call) failed")
	}

	reconcileMu.Lock()
	var after *addrSocket
	for _, s := range openSockets {
		after = s
		break
	}
	reconcileMu.Unlock()
	if after == nil || after.udpConn != beforeUDP {
		t.Fatal("the socket was reopened even though its own address never changed")
	}
	info := after.ifInfo.Load()
	if len(info.acl.rewrites) == 0 || !info.acl.rewrites[0].matches("acl-update-marker.test") {
		t.Fatal("the socket's own ifInfo was never updated with the fresh ACL/rewrite rule")
	}
}

// ------------------------- example config file -------------------------

// TestExampleConfig_ParsesAndRewriteRulesValidate guards against
// dnsrelay.json.example drifting out of sync with the real config schema.
func TestExampleConfig_ParsesAndRewriteRulesValidate(t *testing.T) {
	data, err := os.ReadFile("dnsrelay.json.example")
	if err != nil {
		t.Fatalf("read dnsrelay.json.example: %v", err)
	}
	var example Config
	if err := json.Unmarshal(data, &example); err != nil {
		t.Fatalf("parse dnsrelay.json.example: %v", err)
	}
	if len(example.AllowedInterfaces) == 0 {
		t.Error("example config has no allowed_interfaces")
	}
	if len(example.Upstreams) == 0 {
		t.Error("example config has no upstreams")
	}
	if _, err := resolveRewriteRules(example.Rewrites); err != nil {
		t.Errorf("example config's top-level rewrites don't validate: %v", err)
	}
	for name, acl := range example.InterfaceACLs {
		if _, err := resolveRewriteRules(acl.Rewrites); err != nil {
			t.Errorf("example config's interface_acls[%q].rewrites don't validate: %v", name, err)
		}
	}
	if example.InterfaceRateLimit <= 0 || example.InterfaceRateBurst <= 0 {
		t.Error("example config should set a real interface_rate_limit/interface_rate_burst, not leave the aggregate ceiling unconfigured")
	}
}

func TestUpstreamClientQuery_CollisionAvoidsClobberingExistingPending(t *testing.T) {
	// A real, silent listener — never replies, just absorbs bytes.
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer listener.Close()

	uc, err := newUpstreamClient(listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("newUpstreamClient: %v", err)
	}
	defer uc.conn.Close()

	const collidingID uint16 = 0x1234
	sentinel := make(chan *dnsResponse, 1)
	uc.pendMu.Lock()
	uc.pending[collidingID] = sentinel
	uc.pendMu.Unlock()

	// query() only ever reads/writes modified[0:2] (the transaction
	// ID) — the rest of the buffer's content is irrelevant here.
	modified := make([]byte, 12)
	binary.BigEndian.PutUint16(modified[0:2], collidingID)

	_, usedID, err := uc.query(modified, 20*time.Millisecond)
	if err == nil {
		t.Fatal("expected a timeout error (nothing is listening on the dial target), got nil")
	}
	if usedID == collidingID {
		t.Fatalf("usedID = %#04x, want a DIFFERENT id from the already-pending %#04x — the collision should have been avoided, not silently reused", usedID, collidingID)
	}

	uc.pendMu.Lock()
	_, stillPresent := uc.pending[collidingID]
	uc.pendMu.Unlock()
	if !stillPresent {
		t.Error("the original colliding entry was removed/overwritten — it should have been left completely untouched")
	}
	select {
	case <-sentinel:
		t.Error("the original sentinel channel was written to/closed — it should never have been touched by the second, colliding query")
	default:
	}
}

func TestIfaceAllowed_AggregateCeilingAppliesAcrossDistinctSources(t *testing.T) {
	const ifIndex = 987654 // arbitrary, unlikely to collide with any other test's own ifIndex
	const rate, burst = 5, 5

	allowed := 0
	for i := 0; i < burst+3; i++ {
		if ifaceAllowed(ifIndex, rate, burst) {
			allowed++
		}
	}
	if allowed != burst {
		t.Errorf("allowed %d of %d attempts, want exactly burst=%d — the aggregate bucket should exhaust after burst regardless of how many distinct 'sources' the caller pretends to be", allowed, burst+3, burst)
	}
}

func TestIfaceAllowed_ZeroRateMeansNoCeiling(t *testing.T) {
	const ifIndex = 987655
	for i := 0; i < 1000; i++ {
		if !ifaceAllowed(ifIndex, 0, 0) {
			t.Fatalf("call %d was refused with rate<=0, want always-allowed", i)
		}
	}
}

// TestIfaceAllowed_SeparateInterfacesHaveIndependentBuckets confirms the
// per-ifIndex keying actually isolates interfaces from each other.
func TestIfaceAllowed_SeparateInterfacesHaveIndependentBuckets(t *testing.T) {
	const ifA, ifB = 987656, 987657
	const rate, burst = 3, 3

	for i := 0; i < burst; i++ {
		if !ifaceAllowed(ifA, rate, burst) {
			t.Fatalf("ifA: call %d unexpectedly refused within its own burst", i)
		}
	}
	if ifaceAllowed(ifA, rate, burst) {
		t.Error("ifA: expected the bucket to be exhausted by now")
	}
	if !ifaceAllowed(ifB, rate, burst) {
		t.Error("ifB: a completely separate interface's own bucket should be unaffected by ifA's exhaustion")
	}
}

func TestDecrementTTLs_NeverRewritesOPTRecordExtendedFlags(t *testing.T) {
	ip := net.ParseIP("10.9.9.9").To4()
	pkt := buildMessage(t, 1, 0x8180, "backend.internal.test", 1, 1,
		buildPointerRR(12, 1, 1, 300, ip))

	opt := appendRRFields([]byte{0}, 41, 4096, 0x00008000, nil)
	pkt = append(pkt, opt...)
	binary.BigEndian.PutUint16(pkt[10:12], 1) // arcount = 1

	decrementTTLs(pkt, 100)

	off, _ := questionEndOffset(pkt)
	_, _, _, ttl, _, next, ok := parseRR(pkt, off)
	if !ok {
		t.Fatal("parseRR (answer) failed after decrementTTLs")
	}
	if ttl != 200 {
		t.Fatalf("answer ttl after decrementTTLs(100) = %d, want 200 — real records must still decrement normally", ttl)
	}

	optFlagsOffset := next + 5 // owner(1) + type(2) + class(2) + [flags(4) here]
	gotFlags := binary.BigEndian.Uint32(pkt[optFlagsOffset : optFlagsOffset+4])
	if gotFlags != 0x00008000 {
		t.Fatalf("OPT record's own extended-flags field = %#x after decrementTTLs, want unchanged %#x — the OPT guard failed to skip it", gotFlags, uint32(0x00008000))
	}
}
