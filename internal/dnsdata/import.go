// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsdata

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"dnshived/internal/config"
	"dnshived/internal/dnsanswer"
	"dnshived/internal/dnsstore"
)

type ImportReport struct {
	Records int
	Skipped []string
}

// recordTypeCodes maps the configuration's type names to record type codes.
var recordTypeCodes = map[string]uint16{
	"A": dnsanswer.TypeA, "AAAA": dnsanswer.TypeAAAA, "CNAME": dnsanswer.TypeCNAME, "TXT": dnsanswer.TypeTXT,
	"SRV": dnsanswer.TypeSRV, "PTR": dnsanswer.TypePTR, "MX": dnsanswer.TypeMX, "NAPTR": dnsanswer.TypeNAPTR, "CAA": dnsanswer.TypeCAA,
}

// ConfigRecords lists every DNS record the configuration holds: global, per scope and the local domains' own.
func ConfigRecords(c *config.Cluster) []config.DNSRecord {
	var out []config.DNSRecord
	out = append(out, c.GlobalDNSRecords...)
	names := make([]string, 0, len(c.Scopes))
	for n := range c.Scopes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, c.Scopes[n].DNSRecords...)
	}
	return append(out, config.ExpandedLocalDomainRecords(c.LocalDomains)...)
}

func importID(parts ...any) dnsstore.ID {
	sum := sha256.Sum256([]byte("dnshived-dnsstore-import:" + fmt.Sprint(parts...)))
	var id dnsstore.ID
	copy(id[:], sum[:])
	return id
}

// ImportOps turns configuration DNS records into store operations. Every record becomes a stand-alone record with an
// absolute owner, which keeps its meaning exactly; the row id follows the content, so importing twice changes nothing.
func ImportOps(recs []config.DNSRecord) ([]dnsstore.Op, ImportReport) {
	var rep ImportReport
	seen := map[dnsstore.ID]bool{}
	var ops []dnsstore.Op
	for _, r := range recs {
		owner, err := dnsanswer.CanonicalName(r.Name)
		if err != nil {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("%s: %v", r.Name, err))
			continue
		}
		rec := Record{Owner: owner, TTL: uint32(max(r.TTL, 0))}
		typ := strings.ToUpper(r.Type)
		switch typ {
		case "RAW":
			if r.RRType <= 0 || r.RRType > 65535 || r.RRDataHex == "" {
				rep.Skipped = append(rep.Skipped, fmt.Sprintf("%s: a raw record needs a type and data", owner))
				continue
			}
			rec.Type, rec.Raw = uint16(r.RRType), strings.ToLower(r.RRDataHex)
		default:
			code, ok := recordTypeCodes[typ]
			if !ok {
				rep.Skipped = append(rep.Skipped, fmt.Sprintf("%s: type %s", owner, r.Type))
				continue
			}
			rec.Type = code
			switch typ {
			case "A", "AAAA", "TXT":
				rec.Value = r.Value
			case "CNAME", "PTR":
				v, err := dnsanswer.CanonicalName(r.Value)
				if err != nil {
					rep.Skipped = append(rep.Skipped, fmt.Sprintf("%s: target: %v", owner, err))
					continue
				}
				rec.Value = v
			case "MX", "SRV", "NAPTR":
				t, err := dnsanswer.CanonicalName(r.Target)
				if err != nil {
					rep.Skipped = append(rep.Skipped, fmt.Sprintf("%s: target: %v", owner, err))
					continue
				}
				if typ == "NAPTR" {
					rec.Value, rec.Order, rec.Pref = t, uint16(r.NAPTROrder), uint16(r.Priority)
					rec.Flags, rec.Service, rec.Regexp = r.NAPTRFlags, r.NAPTRService, r.NAPTRRegexp
				} else {
					rec.Target = t
					rec.Pref, rec.Prio, rec.Weight, rec.Port = uint16(r.Priority), uint16(r.Priority), uint16(r.Weight), uint16(r.Port)
					if typ == "MX" {
						rec.Prio, rec.Weight, rec.Port = 0, 0, 0
					} else {
						rec.Pref = 0
					}
				}
			case "CAA":
				rec.Value, rec.CAAFlag, rec.CAATag = r.Value, uint8(r.CAAFlags), r.CAATag
			}
		}
		if _, err := recordData(&rec); err != nil {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("%s: %v", owner, err))
			continue
		}
		body := rec.Encode()
		id := importID(string(body))
		if seen[id] {
			continue
		}
		seen[id] = true
		ops = append(ops, dnsstore.Op{Kind: dnsstore.OpPut, Type: TypeRecord, ID: id, Body: body})
		rep.Records++
	}
	return ops, rep
}
