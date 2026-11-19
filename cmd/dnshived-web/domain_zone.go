// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"net/http"
	"strings"

	"dnshived/internal/config"
)

func zoneName(s string) string {
	switch {
	case s == "":
		return "."
	case strings.HasSuffix(s, "."), !strings.Contains(s, "."):
		return s
	}
	return s + "."
}

func zoneText(s string) string {
	s = strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
	var parts []string
	for len(s) > 250 {
		parts = append(parts, `"`+s[:250]+`"`)
		s = s[250:]
	}
	parts = append(parts, `"`+s+`"`)
	return strings.Join(parts, " ")
}

// zoneRData is the record data in zone-file form, ok false for types a zone
// file cannot carry here (the raw type).
func zoneRData(h config.LocalDomainHost) (string, bool) {
	switch strings.ToUpper(h.Type) {
	case "A", "AAAA":
		return h.Value, true
	case "CNAME", "PTR":
		return zoneName(h.Value), true
	case "MX":
		return fmt.Sprintf("%d %s", h.Priority, zoneName(h.Target)), true
	case "SRV":
		return fmt.Sprintf("%d %d %d %s", h.Priority, h.Weight, h.Port, zoneName(h.Target)), true
	case "TXT":
		return zoneText(h.Value), true
	case "CAA":
		return fmt.Sprintf("%d %s %s", h.CAAFlags, h.CAATag, zoneText(h.Value)), true
	case "NAPTR":
		return fmt.Sprintf("%d %d %s %s %s %s", h.NAPTROrder, h.Priority, zoneText(h.NAPTRFlags), zoneText(h.NAPTRService), zoneText(h.NAPTRRegexp), zoneName(h.Target)), true
	}
	return "", false
}

// domainZoneText writes a domain as a BIND-style zone text.
func domainZoneText(d config.LocalDomain) string {
	var b strings.Builder
	origin := strings.TrimSuffix(d.Name, ".") + "."
	ttl := d.TTL
	if ttl <= 0 {
		ttl = 300
	}
	fmt.Fprintf(&b, "; %s, exported by dnshived\n$ORIGIN %s\n$TTL %d\n", d.Name, origin, ttl)
	for _, h := range d.Records {
		rdata, ok := zoneRData(h)
		if !ok {
			fmt.Fprintf(&b, "; %s record at %s skipped: not expressible in a zone file\n", strings.ToUpper(h.Type), domHostLabel(h.Host))
			continue
		}
		t := ""
		if h.TTL > 0 {
			t = fmt.Sprintf("%d ", h.TTL)
		}
		fmt.Fprintf(&b, "%s %sIN %s %s\n", domHostLabel(h.Host), t, strings.ToUpper(h.Type), rdata)
	}
	return b.String()
}

func handleDomainExport(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		cluster, _, _, err := currentEditableConfig(nodesIncludingSelf(ref.Load()))
		if err != nil {
			http.Error(w, "could not read the configuration from any node: "+err.Error(), http.StatusBadGateway)
			return
		}
		for _, d := range cluster.LocalDomains {
			if d.Name != name {
				continue
			}
			body, ext := domainZoneText(d), ".zone"
			if r.URL.Query().Get("format") == "lines" {
				body, ext = formatDomainHostLines(d.Records)+"\n", ".txt"
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="`+strings.NewReplacer(`"`, "", "/", "_").Replace(name)+ext+`"`)
			w.Header().Set("Cache-Control", "no-store")
			fmt.Fprint(w, body)
			return
		}
		http.Error(w, fmt.Sprintf("domain %q not found", name), http.StatusNotFound)
	}
}
