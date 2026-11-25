// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package dnsverify checks that the DNS store says exactly what the cluster configuration says and that every core and
// the published table are in step with it. It has no I/O: the caller collects the input, Run judges it.
package dnsverify

import (
	"cmp"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/dnsanswer"
	"dnshived/internal/dnsdata"
	"dnshived/internal/dnsstore"
)

const defaultMaxExamples = 20

const (
	CheckRows        = "rows"
	CheckAnswers     = "answers"
	CheckGate        = "gate"
	CheckReplication = "replication"
	CheckPublished   = "published"
	CheckLive        = "live comparison"
	CheckForwarder   = "forwarder"
	CheckQueryLog    = "query log"
)

// Core is what one configured core reports about its copy of the store.
type Core struct {
	Name     string
	Err      string
	Commit   uint64
	Manifest [32]byte
}

// Input is everything one verification looks at. View must be the committed view the service builds its table from,
// and Leases the lease names of the build whose digest is in Published.
type Input struct {
	Config      *config.Cluster
	View        *dnsstore.View
	Zones       []dnsanswer.Zone
	NegTTL      uint32
	Gate        dnsdata.GateContext
	Leases      []dnsdata.LeaseName
	Cores       []Core
	Published   *[32]byte
	MaxExamples int
	Now         time.Time
}

type Check struct {
	Name      string         `json:"name"`
	OK        bool           `json:"ok"`
	Available bool           `json:"available"`
	Reason    string         `json:"reason,omitempty"`
	Counts    map[string]int `json:"counts,omitempty"`
	Examples  []string       `json:"examples,omitempty"`
	Info      []string       `json:"info,omitempty"`
}

type Result struct {
	ConfigRevision int64   `json:"config_revision"`
	StoreRevision  uint64  `json:"store_revision"`
	At             string  `json:"at"`
	Green          bool    `json:"green"`
	TableDigest    string  `json:"table_digest,omitempty"`
	Checks         []Check `json:"checks"`
}

// Run performs every check. The result is green only when every check is available and passes; the checks of phases
// that are not built yet stay red.
func Run(in Input) Result {
	if in.MaxExamples <= 0 {
		in.MaxExamples = defaultMaxExamples
	}
	res := Result{ConfigRevision: in.Config.ConfigRevision, StoreRevision: in.View.Rev(), At: in.Now.UTC().Format(time.RFC3339)}
	rows, gate := checkRowsAndGate(in)
	answers, published, digest := checkAnswersAndPublished(in)
	res.TableDigest = digest
	res.Checks = []Check{
		rows,
		answers,
		gate,
		checkReplication(in),
		published,
		unavailable(CheckLive, "needs the live shadow comparison of the DNS service (WP2.5)"),
		unavailable(CheckForwarder, "needs the forwarder to the real resolvers and its health (WP2.3)"),
		unavailable(CheckQueryLog, "needs the relay's query log (R2)"),
	}
	res.Green = true
	for _, c := range res.Checks {
		res.Green = res.Green && c.OK && c.Available
	}
	return res
}

func unavailable(name, why string) Check {
	return Check{Name: name, Reason: "not available yet: " + why}
}

type rowKey struct {
	typ uint8
	id  dnsstore.ID
}

// examples collects failure descriptions and keeps a sorted, bounded selection, so the output is deterministic.
type examples struct{ all []string }

func (e *examples) add(format string, a ...any) { e.all = append(e.all, fmt.Sprintf(format, a...)) }

func (e *examples) first(n int) []string {
	sort.Strings(e.all)
	return e.all[:min(n, len(e.all))]
}

// checkRowsAndGate keeps the converted configuration only while these two checks need it, so it is gone before the
// table is built.
func checkRowsAndGate(in Input) (rows, gate Check) {
	ops, mrep := dnsdata.MigrateOps(in.Config)
	expected := make(map[rowKey][]byte, len(ops))
	for _, op := range ops {
		expected[rowKey{op.Type, op.ID}] = op.Body
	}
	return checkRows(in, expected), checkGate(in, ops, expected, mrep)
}

func checkRows(in Input, expected map[rowKey][]byte) Check {
	c := Check{Name: CheckRows, Available: true, Counts: map[string]int{}}
	var ex examples
	seen := make(map[rowKey]bool, len(expected))
	for _, typ := range []uint8{dnsdata.TypeHost, dnsdata.TypeRecord} {
		in.View.Range(typ, func(id dnsstore.ID, _ uint64, body []byte) bool {
			k := rowKey{typ, id}
			c.Counts[typeLabel(typ)+"s in the store"]++
			want, ok := expected[k]
			switch {
			case !ok:
				c.Counts["extra"]++
				ex.add("extra in the store: %s", describeRow(typ, body))
			case string(want) != string(body):
				c.Counts["different"]++
				ex.add("different: %s, the configuration says %s", describeRow(typ, body), describeRow(typ, want))
			}
			seen[k] = true
			return true
		})
	}
	for k, body := range expected {
		c.Counts[typeLabel(k.typ)+"s expected"]++
		if !seen[k] {
			c.Counts["missing"]++
			ex.add("missing from the store: %s", describeRow(k.typ, body))
		}
	}
	bad := c.Counts["missing"] + c.Counts["extra"] + c.Counts["different"]
	c.OK = bad == 0
	if !c.OK {
		c.Reason = fmt.Sprintf("the store differs from the configuration in %d row(s): %d missing, %d extra, %d different",
			bad, c.Counts["missing"], c.Counts["extra"], c.Counts["different"])
	}
	c.Examples = ex.first(in.MaxExamples)
	return c
}

type rrKey struct {
	owner string
	typ   uint16
	ttl   uint32
	rd    string
}

// checkAnswersAndPublished builds the table the way the DNS service does and compares the records before the lease
// names with what the configuration means, then checks the lease names and the digest of the published table.
func checkAnswersAndPublished(in Input) (answers, published Check, digest string) {
	set := dnsdata.ReadSettings(in.View)
	spec, rep := dnsdata.Compile(in.View, dnsdata.CompileConfig{Zones: in.Zones, DefaultTTL: set.DefaultTTL, NegTTL: in.NegTTL, Authoritative: set.Authoritative})
	dnsdata.MergeReserved(spec, dnsdata.ReservedNames(in.Config), set.DefaultTTL)
	answers = compareAnswers(in, spec.RRs, set.DefaultTTL, len(rep.Errors))
	leaseNames := leaseSet(in.Leases)
	authored := map[string]bool{}
	for _, rr := range spec.RRs {
		if leaseNames[rr.Owner] != nil {
			authored[rr.Owner] = true
		}
	}
	n := len(spec.RRs)
	dnsdata.MergeLeases(spec, in.Leases, set.DefaultTTL)
	var ex examples
	checked, lost := leaseCheck(leaseNames, authored, spec.RRs[n:], set.DefaultTTL, &ex)
	answers.Counts["lease names"] = checked
	answers.Counts["lease names not answered"] = lost
	if lost > 0 {
		answers.OK = false
		answers.Reason = joinReason(answers.Reason, fmt.Sprintf("%d lease name(s) not answered", lost))
		answers.Examples = append(answers.Examples, ex.first(in.MaxExamples)...)
		slices.Sort(answers.Examples)
		answers.Examples = answers.Examples[:min(in.MaxExamples, len(answers.Examples))]
	}
	tb, err := spec.Build()
	published = Check{Name: CheckPublished, Available: true}
	switch {
	case err != nil:
		published.Reason = "the table cannot be built: " + err.Error()
		return answers, published, ""
	case in.Published == nil:
		published.Reason = "no table has been published yet"
	case *in.Published != tb.Digest():
		published.Reason = fmt.Sprintf("the published table (%x) is not the verified one (%x)", in.Published[:6], tb.Digest())
	default:
		published.OK = true
	}
	d := tb.Digest()
	return answers, published, hex.EncodeToString(d[:])
}

func joinReason(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// oracle derives the records the configuration means, the way the central dnsmasq reads it: scope records and that
// scope's reservation names (scopes by name), global records, then the local domains; the first address record of an
// address also gives its reverse record. A record's own TTL is kept, every other record gets the default TTL. Every
// value starts false; compareAnswers marks the records the table holds.
func oracle(c *config.Cluster, defTTL uint32) (map[rrKey]bool, int) {
	out := map[rrKey]bool{}
	claimed := map[netip.Addr]bool{}
	ttl := func(own int) uint32 {
		if own > 0 {
			return uint32(own)
		}
		return defTTL
	}
	address := func(owner string, ip netip.Addr, t uint32) {
		typ := uint16(dnsanswer.TypeAAAA)
		if ip.Is4() {
			typ = dnsanswer.TypeA
		}
		out[rrKey{owner, typ, t, string(ip.AsSlice())}] = false
		if !claimed[ip] {
			claimed[ip] = true
			if w, err := dnsanswer.ToWire(owner); err == nil {
				out[rrKey{dnsanswer.ReverseName(ip), dnsanswer.TypePTR, t, string(w)}] = false
			}
		}
	}
	record := func(r config.DNSRecord, own int) {
		owner, typ, rd, err := dnsdata.ConfigRR(r)
		if err != nil {
			return
		}
		if typ == dnsanswer.TypeA || typ == dnsanswer.TypeAAAA {
			if ip, err := netip.ParseAddr(strings.TrimSpace(r.Value)); err == nil {
				address(owner, ip.Unmap(), ttl(own))
				return
			}
		}
		out[rrKey{owner, typ, ttl(own), string(rd)}] = false
	}
	reserved := 0
	names := make([]string, 0, len(c.Scopes))
	for n := range c.Scopes {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		sc := c.Scopes[n]
		for _, r := range sc.DNSRecords {
			record(r, r.TTL)
		}
		for _, rs := range sc.Reservations {
			ip, err := netip.ParseAddr(strings.TrimSpace(rs.IP))
			if err != nil {
				continue
			}
			for _, name := range rs.DNSNames() {
				owner, err := dnsanswer.CanonicalName(name)
				if err != nil {
					continue
				}
				reserved++
				address(owner, ip.Unmap(), defTTL)
			}
		}
	}
	for _, r := range c.GlobalDNSRecords {
		record(r, r.TTL)
	}
	for _, d := range c.LocalDomains {
		for i := range d.Records {
			record(d.ExpandedRecord(i), d.Records[i].TTL)
		}
	}
	return out, reserved
}

func compareAnswers(in Input, rrs []dnsanswer.RR, defTTL uint32, skipped int) Check {
	c := Check{Name: CheckAnswers, Available: true, Counts: map[string]int{}}
	want, reserved := oracle(in.Config, defTTL)
	var ex examples
	for _, rr := range rrs {
		k := rrKey{rr.Owner, rr.Type, rr.TTL, string(rr.RData)}
		if _, ok := want[k]; ok {
			want[k] = true
			continue
		}
		c.Counts["extra"]++
		ex.add("answered but not in the configuration: %s", describeRR(k))
	}
	for k, seen := range want {
		if !seen {
			c.Counts["missing"]++
			ex.add("not answered: %s", describeRR(k))
		}
	}
	c.Counts["records the configuration means"] = len(want)
	c.Counts["records in the table before lease names"] = len(rrs)
	c.Counts["reservation names"] = reserved
	c.Counts["rows the compile skipped"] = skipped
	c.OK = c.Counts["missing"] == 0 && c.Counts["extra"] == 0 && skipped == 0
	if !c.OK {
		c.Reason = fmt.Sprintf("the table would answer differently from the configuration: %d record(s) missing, %d extra, %d row(s) skipped by the compile",
			c.Counts["missing"], c.Counts["extra"], skipped)
	}
	c.Examples = ex.first(in.MaxExamples)
	return c
}

// leaseSet indexes the lease addresses by canonical name; names that do not parse are left out, as the merge does.
func leaseSet(leases []dnsdata.LeaseName) map[string]map[netip.Addr]bool {
	ips := map[string]map[netip.Addr]bool{}
	for _, l := range leases {
		name, err := dnsanswer.CanonicalName(l.Name)
		if err != nil || !l.IP.IsValid() {
			continue
		}
		if ips[name] == nil {
			ips[name] = map[netip.Addr]bool{}
		}
		ips[name][l.IP.Unmap()] = true
	}
	return ips
}

// leaseCheck confirms that every lease name that no authored or reserved name holds is answered with one of its
// lease addresses and the default TTL.
func leaseCheck(ips map[string]map[netip.Addr]bool, authored map[string]bool, got []dnsanswer.RR, ttl uint32, ex *examples) (checked, lost int) {
	answered := map[string]bool{}
	for _, rr := range got {
		if rr.Type != dnsanswer.TypeA && rr.Type != dnsanswer.TypeAAAA || rr.TTL != ttl {
			continue
		}
		if ip, ok := netip.AddrFromSlice(rr.RData); ok && ips[rr.Owner][ip.Unmap()] {
			answered[rr.Owner] = true
		}
	}
	for name := range ips {
		if authored[name] {
			continue
		}
		checked++
		if !answered[name] {
			lost++
			ex.add("lease name not answered: %s", name)
		}
	}
	return checked, lost
}

// checkGate runs the write gate over the batch that would make the store equal to the configuration, with legacy raw
// records allowed because they come from the configuration.
func checkGate(in Input, ops []dnsstore.Op, expected map[rowKey][]byte, mrep dnsdata.MigrateReport) Check {
	c := Check{Name: CheckGate, Available: true, Counts: map[string]int{}}
	batch := slices.Clone(ops)
	for _, typ := range []uint8{dnsdata.TypeHost, dnsdata.TypeRecord} {
		in.View.Range(typ, func(id dnsstore.ID, _ uint64, _ []byte) bool {
			if _, ok := expected[rowKey{typ, id}]; !ok {
				batch = append(batch, dnsstore.Op{Kind: dnsstore.OpDel, Type: typ, ID: id})
			}
			return true
		})
	}
	ctx := in.Gate
	ctx.AllowLegacy = true
	vd := dnsdata.Validate(in.View, batch, ctx)
	var ex examples
	for _, e := range vd.Errors {
		ex.add("refused by the write gate: %s", e)
	}
	for _, s := range mrep.Skipped {
		ex.add("cannot be stored: %s", s)
	}
	c.Counts["refused"] = len(vd.Errors) + len(mrep.Skipped)
	c.Counts["warnings"] = len(vd.Warnings)
	c.OK = c.Counts["refused"] == 0
	if !c.OK {
		c.Reason = fmt.Sprintf("%d item(s) of the configuration cannot go into the store as they are; fix them in the configuration first", c.Counts["refused"])
	}
	c.Examples = ex.first(in.MaxExamples)
	c.Info = slices.Clone(mrep.DomainTTLs)
	slices.Sort(c.Info)
	return c
}

func checkReplication(in Input) Check {
	c := Check{Name: CheckReplication, Available: true, Counts: map[string]int{}}
	if len(in.Cores) == 0 {
		c.Reason = "no core reported its store"
		return c
	}
	rev, man := in.View.Rev(), in.View.Manifest()
	var ex examples
	for _, core := range in.Cores {
		switch {
		case core.Err != "":
			ex.add("%s: no answer: %s", core.Name, core.Err)
		case core.Commit < rev:
			ex.add("%s: at revision %d, %d behind", core.Name, core.Commit, rev-core.Commit)
		case core.Commit > rev:
			ex.add("%s: at revision %d, newer than the verified revision %d", core.Name, core.Commit, rev)
		case core.Manifest != man:
			ex.add("%s: different data at revision %d", core.Name, rev)
		default:
			c.Counts["in step"]++
			continue
		}
		c.Counts["not in step"]++
	}
	c.OK = c.Counts["not in step"] == 0
	if !c.OK {
		c.Reason = fmt.Sprintf("%d of %d core(s) do not hold the verified store", c.Counts["not in step"], len(in.Cores))
	}
	c.Examples = ex.first(in.MaxExamples)
	return c
}

func typeLabel(typ uint8) string {
	if typ == dnsdata.TypeHost {
		return "host"
	}
	return "record"
}

var typeNames = map[uint16]string{
	dnsanswer.TypeA: "A", dnsanswer.TypeAAAA: "AAAA", dnsanswer.TypeCNAME: "CNAME", dnsanswer.TypeTXT: "TXT",
	dnsanswer.TypeSRV: "SRV", dnsanswer.TypePTR: "PTR", dnsanswer.TypeMX: "MX", dnsanswer.TypeNAPTR: "NAPTR", dnsanswer.TypeCAA: "CAA",
}

func typeName(t uint16) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("TYPE%d", t)
}

func describeRow(typ uint8, body []byte) string {
	if typ == dnsdata.TypeHost {
		h, err := dnsdata.DecodeHost(body)
		if err != nil {
			return "host (unreadable)"
		}
		ips := make([]string, 0, len(h.Addrs))
		for _, a := range h.Addrs {
			ips = append(ips, a.IP.String())
		}
		return fmt.Sprintf("host %s in %s at %s", h.Label, strings.Join(h.Domains, ","), strings.Join(ips, ","))
	}
	r, err := dnsdata.DecodeRecord(body)
	if err != nil {
		return "record (unreadable)"
	}
	owner := r.Owner
	if owner == "" {
		owner = r.Sub + " of host " + hex.EncodeToString(r.Host[:4])
	}
	return fmt.Sprintf("record %s %s %s", owner, typeName(r.Type), cmp.Or(r.Value, r.Target, r.Raw))
}

func describeRR(k rrKey) string {
	data := hex.EncodeToString([]byte(k.rd))
	switch k.typ {
	case dnsanswer.TypeA, dnsanswer.TypeAAAA:
		if ip, ok := netip.AddrFromSlice([]byte(k.rd)); ok {
			data = ip.String()
		}
	case dnsanswer.TypeCNAME, dnsanswer.TypePTR:
		if n, err := dnsanswer.FromWire([]byte(k.rd)); err == nil {
			data = n
		}
	}
	if len(data) > 64 {
		data = data[:64] + "…"
	}
	return fmt.Sprintf("%s %s %s ttl %d", k.owner, typeName(k.typ), data, k.ttl)
}
