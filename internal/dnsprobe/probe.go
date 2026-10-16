// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package dnsprobe sends a single, minimal DNS query over UDP.
package dnsprobe

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

// DefaultQName is queried by Probe.
const DefaultQName = "localhost."

// DefaultQType is used when qtype is empty.
const DefaultQType = "A"

const (
	qClass  = 1 // IN
	flagsQR = 1 << 15
)

// qtypeNums maps config.DNSRecord's own type name strings to DNS wire
// QTYPE values.
var qtypeNums = map[string]uint16{
	"A":     1,
	"AAAA":  28,
	"CNAME": 5,
	"PTR":   12,
	"TXT":   16,
	"MX":    15,
	"SRV":   33,
	"NAPTR": 35,
	"CAA":   257,
}

// resolveQType maps qtype to a wire-format QTYPE number: first by name
// (qtypeNums), then as a bare decimal number (for RAW records).
func resolveQType(qtype string) (uint16, error) {
	if n, ok := qtypeNums[strings.ToUpper(qtype)]; ok {
		return n, nil
	}
	if n, err := strconv.ParseUint(qtype, 10, 16); err == nil {
		return uint16(n), nil
	}
	return 0, fmt.Errorf("unsupported query type %q", qtype)
}

// Result is the outcome of one Probe call.
type Result struct {
	Answered bool
	RCode    int // valid only when Answered
	Latency  time.Duration
	Data     string
}

// Probe sends one qtype-record query for qname (DefaultQName/DefaultQType
// if empty) to addr:53 over UDP and waits up to timeout for a response.
func Probe(addr string, qname string, qtype string, timeout time.Duration) (Result, error) {
	return ProbeAddr(net.JoinHostPort(addr, "53"), qname, qtype, timeout)
}

// ProbeAddr is Probe with an explicit host:port instead of an assumed :53.
func ProbeAddr(hostport string, qname string, qtype string, timeout time.Duration) (Result, error) {
	if qname == "" {
		qname = DefaultQName
	}
	if qtype == "" {
		qtype = DefaultQType
	}
	qtypeNum, err := resolveQType(qtype)
	if err != nil {
		return Result{}, err
	}

	conn, err := net.DialTimeout("udp4", hostport, timeout)
	if err != nil {
		return Result{}, fmt.Errorf("dial %s: %w", hostport, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	id := uint16(rand.Intn(1 << 16))
	query, err := buildQuery(id, qname, qtypeNum)
	if err != nil {
		return Result{}, err
	}

	start := time.Now()
	if _, err := conn.Write(query); err != nil {
		return Result{}, fmt.Errorf("send query: %w", err)
	}

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return Result{Answered: false}, nil // timeout — not an error, just "no answer"
		}
		rcode, data, ok := parseResponse(buf[:n], id, qtypeNum)
		if !ok {
			continue // not our transaction — keep waiting until the deadline
		}
		return Result{Answered: true, RCode: rcode, Latency: time.Since(start), Data: data}, nil
	}
}

func buildQuery(id uint16, qname string, qtype uint16) ([]byte, error) {
	p := make([]byte, 12, 32)
	binary.BigEndian.PutUint16(p[0:2], id)
	binary.BigEndian.PutUint16(p[2:4], 0x0100) // flags: RD=1, everything else 0 (standard query)
	binary.BigEndian.PutUint16(p[4:6], 1)      // QDCOUNT=1
	// ANCOUNT/NSCOUNT/ARCOUNT stay 0 (bytes 6..12 already zero)

	qn, err := encodeQName(qname)
	if err != nil {
		return nil, err
	}
	p = append(p, qn...)
	p = binary.BigEndian.AppendUint16(p, qtype)
	p = binary.BigEndian.AppendUint16(p, qClass)
	return p, nil
}

// encodeQName converts "foo.bar.invalid." into DNS wire format: one
// length-prefixed label per dot-separated segment, terminated by a zero
// length byte.
func encodeQName(qname string) ([]byte, error) {
	qname = strings.TrimSuffix(qname, ".")
	if qname == "" {
		return nil, fmt.Errorf("empty qname")
	}
	var out []byte
	for _, label := range strings.Split(qname, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid label length in %q", qname)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	return out, nil
}

// decodeName reads a DNS name starting at offset in msg, following
// compression pointers (RFC 1035 §4.1.4) as needed.
func decodeName(msg []byte, offset int) (name string, consumed int, err error) {
	var labels []string
	pos := offset
	jumped := false
	realConsumed := 0
	for loops := 0; ; loops++ {
		if loops > 128 { // guards against a malicious/corrupt pointer cycle
			return "", 0, fmt.Errorf("name decompression: too many pointer jumps")
		}
		if pos >= len(msg) {
			return "", 0, fmt.Errorf("name decompression: offset out of range")
		}
		b := msg[pos]
		if b&0xC0 == 0xC0 {
			if pos+1 >= len(msg) {
				return "", 0, fmt.Errorf("name decompression: truncated pointer")
			}
			if !jumped {
				realConsumed = pos + 2 - offset
				jumped = true
			}
			pos = int(binary.BigEndian.Uint16(msg[pos:pos+2]) & 0x3FFF)
			continue
		}
		if b == 0 {
			pos++
			break
		}
		length := int(b)
		pos++
		if pos+length > len(msg) {
			return "", 0, fmt.Errorf("name decompression: truncated label")
		}
		labels = append(labels, string(msg[pos:pos+length]))
		pos += length
	}
	if !jumped {
		realConsumed = pos - offset
	}
	return strings.Join(labels, ".") + ".", realConsumed, nil
}

// parseResponse checks the fixed 12-byte header and, for a matching-ID
// response, decodes the first answer record matching qtype; ok=false means
// not our transaction.
func parseResponse(msg []byte, id uint16, qtype uint16) (rcode int, data string, ok bool) {
	if len(msg) < 12 {
		return 0, "", false
	}
	if binary.BigEndian.Uint16(msg[0:2]) != id {
		return 0, "", false
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&flagsQR == 0 {
		return 0, "", false // a query, not a response — not what we're waiting for
	}
	rcode = int(flags & 0x000F)

	qdcount := int(binary.BigEndian.Uint16(msg[4:6]))
	ancount := int(binary.BigEndian.Uint16(msg[6:8]))

	pos := 12
	for i := 0; i < qdcount; i++ {
		_, n, err := decodeName(msg, pos)
		if err != nil {
			return rcode, "", true // header matched; malformed body doesn't change Answered
		}
		pos += n + 4 // QTYPE(2) + QCLASS(2)
	}

	for i := 0; i < ancount; i++ {
		if pos >= len(msg) {
			break
		}
		_, n, err := decodeName(msg, pos) // owner name — not needed, just skipped correctly
		if err != nil {
			break
		}
		pos += n
		if pos+10 > len(msg) {
			break
		}
		rrType := binary.BigEndian.Uint16(msg[pos : pos+2])
		rdlength := int(binary.BigEndian.Uint16(msg[pos+8 : pos+10]))
		rdataStart := pos + 10
		if rdataStart+rdlength > len(msg) {
			break
		}
		if rrType == qtype {
			data = decodeRData(msg, rdataStart, msg[rdataStart:rdataStart+rdlength], rrType)
			return rcode, data, true
		}
		pos = rdataStart + rdlength
	}
	return rcode, "", true
}

// decodeRData decodes one answer record's RDATA into Result.Data's
// documented string form.
func decodeRData(msg []byte, rdataStart int, rdata []byte, rrType uint16) string {
	switch rrType {
	case qtypeNums["A"]:
		if len(rdata) != 4 {
			return ""
		}
		return net.IP(rdata).String()
	case qtypeNums["AAAA"]:
		if len(rdata) != 16 {
			return ""
		}
		return net.IP(rdata).String()
	case qtypeNums["CNAME"], qtypeNums["PTR"]:
		name, _, err := decodeName(msg, rdataStart)
		if err != nil {
			return ""
		}
		return name
	case qtypeNums["TXT"]:
		var parts []string
		i := 0
		for i < len(rdata) {
			l := int(rdata[i])
			i++
			if i+l > len(rdata) {
				break
			}
			parts = append(parts, string(rdata[i:i+l]))
			i += l
		}
		return strings.Join(parts, ",")
	case qtypeNums["SRV"]:
		if len(rdata) < 6 {
			return ""
		}
		priority := binary.BigEndian.Uint16(rdata[0:2])
		weight := binary.BigEndian.Uint16(rdata[2:4])
		port := binary.BigEndian.Uint16(rdata[4:6])
		target, _, err := decodeName(msg, rdataStart+6)
		if err != nil {
			target = ""
		}
		return fmt.Sprintf("%d %d %d %s", priority, weight, port, target)
	case qtypeNums["MX"]:
		if len(rdata) < 3 {
			return ""
		}
		preference := binary.BigEndian.Uint16(rdata[0:2])
		exchange, _, err := decodeName(msg, rdataStart+2)
		if err != nil {
			exchange = ""
		}
		return fmt.Sprintf("%d %s", preference, exchange)
	case qtypeNums["NAPTR"]:
		if len(rdata) < 4 {
			return ""
		}
		order := binary.BigEndian.Uint16(rdata[0:2])
		preference := binary.BigEndian.Uint16(rdata[2:4])
		pos := 4
		readCharString := func() (string, bool) {
			if pos >= len(rdata) {
				return "", false
			}
			l := int(rdata[pos])
			pos++
			if pos+l > len(rdata) {
				return "", false
			}
			s := string(rdata[pos : pos+l])
			pos += l
			return s, true
		}
		flags, ok1 := readCharString()
		service, ok2 := readCharString()
		regex, ok3 := readCharString()
		if !ok1 || !ok2 || !ok3 {
			return ""
		}
		replacement, _, err := decodeName(msg, rdataStart+pos)
		if err != nil {
			replacement = ""
		}
		return fmt.Sprintf("%d %d %s|%s|%s %s", order, preference, flags, service, regex, replacement)
	case qtypeNums["CAA"]:
		if len(rdata) < 2 {
			return ""
		}
		flags := rdata[0]
		tagLen := int(rdata[1])
		if 2+tagLen > len(rdata) {
			return ""
		}
		tag := string(rdata[2 : 2+tagLen])
		value := string(rdata[2+tagLen:])
		return fmt.Sprintf("%d %s %s", flags, tag, value)
	default:
		return hex.EncodeToString(rdata)
	}
}
