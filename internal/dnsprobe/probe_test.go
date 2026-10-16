// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsprobe

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestEncodeQName_Basic(t *testing.T) {
	got, err := encodeQName("foo.bar.invalid.")
	if err != nil {
		t.Fatalf("encodeQName: %v", err)
	}
	want := []byte{3, 'f', 'o', 'o', 3, 'b', 'a', 'r', 7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0}
	if string(got) != string(want) {
		t.Errorf("encodeQName = %v, want %v", got, want)
	}
}

func TestEncodeQName_TrailingDotOptional(t *testing.T) {
	withDot, _ := encodeQName("localhost.")
	withoutDot, _ := encodeQName("localhost")
	if string(withDot) != string(withoutDot) {
		t.Error("encodeQName should treat a trailing dot as optional")
	}
}

func TestEncodeQName_RejectsEmpty(t *testing.T) {
	if _, err := encodeQName(""); err == nil {
		t.Error("encodeQName(\"\") should fail, not silently encode an empty query")
	}
}

func TestEncodeQName_RejectsOverlongLabel(t *testing.T) {
	long := make([]byte, 64)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := encodeQName(string(long) + ".invalid."); err == nil {
		t.Error("encodeQName should reject a label over 63 bytes (DNS wire format limit)")
	}
}

func TestBuildQuery_HeaderFields(t *testing.T) {
	p, err := buildQuery(0x1234, DefaultQName, qtypeNums["A"])
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}
	if len(p) < 12 {
		t.Fatalf("query too short: %d bytes", len(p))
	}
	if got := binary.BigEndian.Uint16(p[0:2]); got != 0x1234 {
		t.Errorf("query ID = %#x, want %#x", got, 0x1234)
	}
	if qdcount := binary.BigEndian.Uint16(p[4:6]); qdcount != 1 {
		t.Errorf("QDCOUNT = %d, want 1", qdcount)
	}
	if ancount := binary.BigEndian.Uint16(p[6:8]); ancount != 0 {
		t.Errorf("ANCOUNT = %d, want 0 (this is a query, not a response)", ancount)
	}
}

func TestBuildQuery_QTypeField(t *testing.T) {
	p, err := buildQuery(1, "example.invalid.", qtypeNums["SRV"])
	if err != nil {
		t.Fatalf("buildQuery: %v", err)
	}
	// QTYPE is the 2 bytes immediately before the trailing QCLASS(2).
	qtype := binary.BigEndian.Uint16(p[len(p)-4 : len(p)-2])
	if qtype != qtypeNums["SRV"] {
		t.Errorf("QTYPE = %d, want %d (SRV)", qtype, qtypeNums["SRV"])
	}
}

// --- answer-section construction helpers, shared by the tests below ---

// buildResponsePacket mirrors buildQuery but sets QR + a chosen RCODE, the
// test-side stand-in for a real dnsmasq reply, with no answer records.
func buildResponsePacket(id uint16, rcode int) []byte {
	p := make([]byte, 12)
	binary.BigEndian.PutUint16(p[0:2], id)
	flags := uint16(flagsQR) | uint16(rcode&0x000F)
	binary.BigEndian.PutUint16(p[2:4], flags)
	return p
}

// buildAnswerPacket builds a full, well-formed response: header + echoed
// question (qname/qtype) + one answer record of rrType containing rdata.
func buildAnswerPacket(t *testing.T, id uint16, qname string, qtype uint16, rrType uint16, rdata []byte) []byte {
	t.Helper()
	p := make([]byte, 12)
	binary.BigEndian.PutUint16(p[0:2], id)
	binary.BigEndian.PutUint16(p[2:4], flagsQR)
	binary.BigEndian.PutUint16(p[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(p[6:8], 1) // ANCOUNT

	qn, err := encodeQName(qname)
	if err != nil {
		t.Fatalf("encodeQName: %v", err)
	}
	p = append(p, qn...)
	p = binary.BigEndian.AppendUint16(p, qtype)
	p = binary.BigEndian.AppendUint16(p, qClass)

	// Answer: owner name (same as question, uncompressed for simplicity),
	// type, class, TTL, RDLENGTH, RDATA.
	p = append(p, qn...)
	p = binary.BigEndian.AppendUint16(p, rrType)
	p = binary.BigEndian.AppendUint16(p, qClass)
	p = binary.BigEndian.AppendUint32(p, 300) // TTL
	p = binary.BigEndian.AppendUint16(p, uint16(len(rdata)))
	p = append(p, rdata...)
	return p
}

func TestParseResponse_MatchingIDAccepted(t *testing.T) {
	pkt := buildResponsePacket(0xabcd, 0) // NOERROR
	rcode, _, ok := parseResponse(pkt, 0xabcd, qtypeNums["A"])
	if !ok {
		t.Fatal("parseResponse rejected a well-formed, matching-ID response")
	}
	if rcode != 0 {
		t.Errorf("rcode = %d, want 0 (NOERROR)", rcode)
	}
}

func TestParseResponse_NXDOMAINStillCountsAsAnswered(t *testing.T) {
	// The whole point of this package: NXDOMAIN means the server IS up
	// and processing queries — that's a pass, not a failure.
	pkt := buildResponsePacket(1, 3) // RCODE 3 = NXDOMAIN
	rcode, _, ok := parseResponse(pkt, 1, qtypeNums["A"])
	if !ok {
		t.Fatal("parseResponse should accept NXDOMAIN as a valid response")
	}
	if rcode != 3 {
		t.Errorf("rcode = %d, want 3 (NXDOMAIN)", rcode)
	}
}

func TestParseResponse_WrongIDRejected(t *testing.T) {
	pkt := buildResponsePacket(1, 0)
	if _, _, ok := parseResponse(pkt, 2, qtypeNums["A"]); ok {
		t.Error("parseResponse accepted a response with a mismatched transaction ID")
	}
}

func TestParseResponse_QueryNotResponseRejected(t *testing.T) {
	// A query (QR=0) — e.g. some unrelated stray packet — must never be
	// mistaken for our answer.
	p := make([]byte, 12)
	binary.BigEndian.PutUint16(p[0:2], 1)
	if _, _, ok := parseResponse(p, 1, qtypeNums["A"]); ok {
		t.Error("parseResponse accepted a packet with QR=0 (a query, not a response)")
	}
}

func TestParseResponse_TooShortRejected(t *testing.T) {
	if _, _, ok := parseResponse([]byte{1, 2}, 1, qtypeNums["A"]); ok {
		t.Error("parseResponse accepted a packet shorter than the DNS header")
	}
}

func TestParseResponse_DecodesARecord(t *testing.T) {
	pkt := buildAnswerPacket(t, 1, "nas.office.lan.", qtypeNums["A"], qtypeNums["A"], net.ParseIP("192.168.100.50").To4())
	_, data, ok := parseResponse(pkt, 1, qtypeNums["A"])
	if !ok {
		t.Fatal("expected a matching response")
	}
	if data != "192.168.100.50" {
		t.Errorf("data = %q, want %q", data, "192.168.100.50")
	}
}

func TestParseResponse_DecodesAAAARecord(t *testing.T) {
	ip := net.ParseIP("fe80::1")
	pkt := buildAnswerPacket(t, 1, "nas6.office.lan.", qtypeNums["AAAA"], qtypeNums["AAAA"], ip.To16())
	_, data, ok := parseResponse(pkt, 1, qtypeNums["AAAA"])
	if !ok {
		t.Fatal("expected a matching response")
	}
	if data != ip.String() {
		t.Errorf("data = %q, want %q", data, ip.String())
	}
}

func TestParseResponse_DecodesCNAMERecord(t *testing.T) {
	target, err := encodeQName("nas.office.lan.")
	if err != nil {
		t.Fatalf("encodeQName: %v", err)
	}
	pkt := buildAnswerPacket(t, 1, "printer.office.lan.", qtypeNums["CNAME"], qtypeNums["CNAME"], target)
	_, data, ok := parseResponse(pkt, 1, qtypeNums["CNAME"])
	if !ok {
		t.Fatal("expected a matching response")
	}
	if data != "nas.office.lan." {
		t.Errorf("data = %q, want %q", data, "nas.office.lan.")
	}
}

func TestParseResponse_DecodesPTRRecord(t *testing.T) {
	target, err := encodeQName("nas.office.lan.")
	if err != nil {
		t.Fatalf("encodeQName: %v", err)
	}
	pkt := buildAnswerPacket(t, 1, "50.100.168.192.in-addr.arpa.", qtypeNums["PTR"], qtypeNums["PTR"], target)
	_, data, ok := parseResponse(pkt, 1, qtypeNums["PTR"])
	if !ok {
		t.Fatal("expected a matching response")
	}
	if data != "nas.office.lan." {
		t.Errorf("data = %q, want %q", data, "nas.office.lan.")
	}
}

func TestParseResponse_DecodesTXTRecordMultiString(t *testing.T) {
	var rdata []byte
	for _, s := range []string{"note=hello", "world"} {
		rdata = append(rdata, byte(len(s)))
		rdata = append(rdata, s...)
	}
	pkt := buildAnswerPacket(t, 1, "_info.office.lan.", qtypeNums["TXT"], qtypeNums["TXT"], rdata)
	_, data, ok := parseResponse(pkt, 1, qtypeNums["TXT"])
	if !ok {
		t.Fatal("expected a matching response")
	}
	if data != "note=hello,world" {
		t.Errorf("data = %q, want %q (joined with a comma to reconstruct the configured value)", data, "note=hello,world")
	}
}

func TestParseResponse_DecodesSRVRecord(t *testing.T) {
	target, err := encodeQName("nas.office.lan.")
	if err != nil {
		t.Fatalf("encodeQName: %v", err)
	}
	rdata := make([]byte, 0, 6+len(target))
	rdata = binary.BigEndian.AppendUint16(rdata, 10)   // priority
	rdata = binary.BigEndian.AppendUint16(rdata, 20)   // weight
	rdata = binary.BigEndian.AppendUint16(rdata, 4440) // port
	rdata = append(rdata, target...)
	pkt := buildAnswerPacket(t, 1, "_dante._udp.office.lan.", qtypeNums["SRV"], qtypeNums["SRV"], rdata)
	_, data, ok := parseResponse(pkt, 1, qtypeNums["SRV"])
	if !ok {
		t.Fatal("expected a matching response")
	}
	want := "10 20 4440 nas.office.lan."
	if data != want {
		t.Errorf("data = %q, want %q", data, want)
	}
}

func TestParseResponse_DecodesMXRecord(t *testing.T) {
	target, err := encodeQName("mail.office.lan.")
	if err != nil {
		t.Fatalf("encodeQName: %v", err)
	}
	rdata := make([]byte, 0, 2+len(target))
	rdata = binary.BigEndian.AppendUint16(rdata, 10) // preference
	rdata = append(rdata, target...)
	pkt := buildAnswerPacket(t, 1, "office.lan.", qtypeNums["MX"], qtypeNums["MX"], rdata)
	_, data, ok := parseResponse(pkt, 1, qtypeNums["MX"])
	if !ok {
		t.Fatal("expected a matching response")
	}
	want := "10 mail.office.lan."
	if data != want {
		t.Errorf("data = %q, want %q", data, want)
	}
}

func TestParseResponse_DecodesNAPTRRecord(t *testing.T) {
	replacement, err := encodeQName("_sip._udp.office.lan.")
	if err != nil {
		t.Fatalf("encodeQName: %v", err)
	}
	charString := func(s string) []byte {
		return append([]byte{byte(len(s))}, []byte(s)...)
	}
	var rdata []byte
	rdata = binary.BigEndian.AppendUint16(rdata, 100) // order
	rdata = binary.BigEndian.AppendUint16(rdata, 10)  // preference
	rdata = append(rdata, charString("S")...)
	rdata = append(rdata, charString("SIP+D2U")...)
	rdata = append(rdata, charString("")...)
	rdata = append(rdata, replacement...)
	pkt := buildAnswerPacket(t, 1, "_sip._udp.office.lan.", qtypeNums["NAPTR"], qtypeNums["NAPTR"], rdata)
	_, data, ok := parseResponse(pkt, 1, qtypeNums["NAPTR"])
	if !ok {
		t.Fatal("expected a matching response")
	}
	want := "100 10 S|SIP+D2U| _sip._udp.office.lan."
	if data != want {
		t.Errorf("data = %q, want %q", data, want)
	}
}

func TestParseResponse_DecodesCAARecord(t *testing.T) {
	tag := "issue"
	value := "letsencrypt.org"
	rdata := append([]byte{0, byte(len(tag))}, append([]byte(tag), []byte(value)...)...)
	pkt := buildAnswerPacket(t, 1, "office.lan.", qtypeNums["CAA"], qtypeNums["CAA"], rdata)
	_, data, ok := parseResponse(pkt, 1, qtypeNums["CAA"])
	if !ok {
		t.Fatal("expected a matching response")
	}
	want := "0 issue letsencrypt.org"
	if data != want {
		t.Errorf("data = %q, want %q", data, want)
	}
}

func TestParseResponse_DecodesUnknownTypeAsHex(t *testing.T) {
	rawType := uint16(65280)
	rdata := []byte("hello")
	pkt := buildAnswerPacket(t, 1, "raw.office.lan.", rawType, rawType, rdata)
	_, data, ok := parseResponse(pkt, 1, rawType)
	if !ok {
		t.Fatal("expected a matching response")
	}
	want := "68656c6c6f"
	if data != want {
		t.Errorf("data = %q, want %q", data, want)
	}
}

func TestParseResponse_NoMatchingTypeReturnsEmptyData(t *testing.T) {
	pkt := buildAnswerPacket(t, 1, "nas.office.lan.", qtypeNums["A"], qtypeNums["A"], net.ParseIP("192.168.100.50").To4())
	_, data, ok := parseResponse(pkt, 1, qtypeNums["AAAA"])
	if !ok {
		t.Fatal("expected a matching response (header-level match is independent of RR type)")
	}
	if data != "" {
		t.Errorf("data = %q, want empty — no record of the requested type was present", data)
	}
}

func TestDecodeName_FollowsCompressionPointer(t *testing.T) {
	msg, err := encodeQName("nas.office.lan.")
	if err != nil {
		t.Fatalf("encodeQName: %v", err)
	}
	for len(msg) < 20 {
		msg = append(msg, 0) // padding
	}
	ptr := make([]byte, 2)
	binary.BigEndian.PutUint16(ptr, 0xC000) // pointer to offset 0
	msg = append(msg, ptr...)

	name, consumed, err := decodeName(msg, 20)
	if err != nil {
		t.Fatalf("decodeName: %v", err)
	}
	if name != "nas.office.lan." {
		t.Errorf("name = %q, want %q", name, "nas.office.lan.")
	}
	if consumed != 2 {
		t.Errorf("consumed = %d, want 2 (a pointer is always exactly 2 bytes at its own position)", consumed)
	}
}

func TestDecodeName_RejectsPointerLoop(t *testing.T) {
	// A pointer at offset 0 pointing to itself must not hang forever.
	msg := make([]byte, 2)
	binary.BigEndian.PutUint16(msg, 0xC000)
	if _, _, err := decodeName(msg, 0); err == nil {
		t.Error("expected an error for a self-referencing pointer loop, got none")
	}
}

// --- ProbeAddr integration tests (real UDP socket I/O) ---

func TestProbe_RealUDPRoundTrip(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 512)
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		id := binary.BigEndian.Uint16(buf[:n])
		resp := buildResponsePacket(id, 0)
		pc.WriteTo(resp, src)
	}()

	result, err := ProbeAddr(pc.LocalAddr().String(), "", "", 2*time.Second)
	if err != nil {
		t.Fatalf("ProbeAddr: %v", err)
	}
	if !result.Answered {
		t.Error("Probe.Answered = false, want true against a real responding server")
	}
	if result.RCode != 0 {
		t.Errorf("Probe.RCode = %d, want 0", result.RCode)
	}
}

func TestProbe_TimeoutWhenNothingListening(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := pc.LocalAddr().String()
	pc.Close() // nothing will answer here now

	result, err := ProbeAddr(addr, "", "", 300*time.Millisecond)
	if err != nil {
		t.Fatalf("ProbeAddr returned an error instead of a clean timeout: %v", err)
	}
	if result.Answered {
		t.Error("Probe.Answered = true with nothing listening")
	}
}

func TestProbeAddr_RejectsUnsupportedQType(t *testing.T) {
	// "BOGUS" is neither a known type name nor a bare number — resolveQType's
	// only two ways to resolve a qtype at all.
	if _, err := ProbeAddr("127.0.0.1:1", "example.invalid.", "BOGUS", time.Second); err == nil {
		t.Error("expected an error for an unsupported query type, got none")
	}
}

func TestResolveQType_NumericFallbackForRAW(t *testing.T) {
	n, err := resolveQType("65280")
	if err != nil {
		t.Fatalf("resolveQType(\"65280\"): %v", err)
	}
	if n != 65280 {
		t.Errorf("resolveQType(\"65280\") = %d, want 65280", n)
	}
}

func TestResolveQType_KnownNameCaseInsensitive(t *testing.T) {
	n, err := resolveQType("mx")
	if err != nil {
		t.Fatalf("resolveQType(\"mx\"): %v", err)
	}
	if n != 15 {
		t.Errorf("resolveQType(\"mx\") = %d, want 15", n)
	}
}

func TestProbe_RealUDPRoundTrip_DecodesSRVAnswer(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 512)
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		id := binary.BigEndian.Uint16(buf[:n])
		target, terr := encodeQName("nas.office.lan.")
		if terr != nil {
			return
		}
		rdata := make([]byte, 0, 6+len(target))
		rdata = binary.BigEndian.AppendUint16(rdata, 10)
		rdata = binary.BigEndian.AppendUint16(rdata, 20)
		rdata = binary.BigEndian.AppendUint16(rdata, 4440)
		rdata = append(rdata, target...)
		resp := buildAnswerPacket(t, id, "_dante._udp.office.lan.", qtypeNums["SRV"], qtypeNums["SRV"], rdata)
		pc.WriteTo(resp, src)
	}()

	result, err := ProbeAddr(pc.LocalAddr().String(), "_dante._udp.office.lan.", "SRV", 2*time.Second)
	if err != nil {
		t.Fatalf("ProbeAddr: %v", err)
	}
	if !result.Answered {
		t.Fatal("Probe.Answered = false, want true")
	}
	want := "10 20 4440 nas.office.lan."
	if result.Data != want {
		t.Errorf("Data = %q, want %q", result.Data, want)
	}
}
