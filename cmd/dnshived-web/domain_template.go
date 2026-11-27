// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"net/http"
	"strings"

	"dnshived/internal/config"
)

func normName(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// recordsForHost collects what belongs to one host name of a domain: its
// A, AAAA and CNAME records, the CNAMEs that point at it, the SRV records
// whose target it is, the TXT records of those service instances, and the PTR
// records that list an instance or name the host.
func recordsForHost(d config.LocalDomain, label string) []config.LocalDomainHost {
	label = domHostLabel(label)
	dom := normName(d.Name)
	fq := func(l string) string {
		if domHostLabel(l) == "@" {
			return dom
		}
		return normName(l) + "." + dom
	}
	hostFQ := fq(label)
	isHost := func(target string) bool {
		t := normName(target)
		return t == hostFQ || !strings.Contains(t, ".") && strings.EqualFold(t, label)
	}
	owners := map[string]bool{}
	picked := make([]bool, len(d.Records))
	for i, r := range d.Records {
		typ := strings.ToUpper(r.Type)
		switch {
		case strings.EqualFold(domHostLabel(r.Host), label) && (typ == "A" || typ == "AAAA" || typ == "CNAME"):
			picked[i] = true
		case typ == "CNAME" && isHost(r.Value):
			picked[i] = true
		case typ == "SRV" && isHost(r.Target):
			picked[i] = true
			owners[fq(r.Host)] = true
		}
	}
	for i, r := range d.Records {
		typ := strings.ToUpper(r.Type)
		switch {
		case typ == "TXT" && owners[fq(r.Host)]:
			picked[i] = true
		case typ == "PTR" && (owners[normName(r.Value)] || isHost(r.Value)):
			picked[i] = true
		}
	}
	var out []config.LocalDomainHost
	for i, r := range d.Records {
		if picked[i] {
			out = append(out, r)
		}
	}
	return out
}

// recordSetBody writes records as a record set body: lines in the app's
// format with the domain replaced by the example domain, so applying it to
// another domain rewrites it.
func recordSetBody(d config.LocalDomain, recs []config.LocalDomainHost) string {
	dom := strings.TrimSuffix(d.Name, ".")
	lines := make([]string, 0, len(recs))
	for _, r := range recs {
		if domHostLabel(r.Host) == "@" {
			r.Host = dom
		} else {
			r.Host = strings.TrimSuffix(r.Host, ".") + "." + dom
		}
		line := formatDomainHostLine(r)
		parts := strings.Split(line, "|")
		for i := range parts {
			parts[i] = strings.ReplaceAll(parts[i], dom, recordSetPlaceholderDomain)
		}
		lines = append(lines, strings.Join(parts, "|"))
	}
	return strings.Join(lines, "\n")
}

func handleDomainMakeTemplate(ref *configRef, templates *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		host := strings.TrimSpace(r.PostForm.Get("host"))
		setName := strings.TrimSpace(r.PostForm.Get("set_name"))
		if setName == "" || len(setName) > 60 || strings.ContainsAny(setName, "<>\"\r\n") {
			http.Redirect(w, r, domBack(name, "err", "give the record set a name of up to 60 characters"), http.StatusSeeOther)
			return
		}
		cluster, _, _, err := currentEditableConfig(nodesIncludingSelf(ref.Load()))
		if err != nil {
			http.Error(w, "could not read the configuration from any node: "+err.Error(), http.StatusBadGateway)
			return
		}
		for _, d := range cluster.LocalDomains {
			if d.Name != name {
				continue
			}
			recs := recordsForHost(d, host)
			if len(recs) == 0 {
				http.Redirect(w, r, domBack(name, "err", "no records belong to "+host), http.StatusSeeOther)
				return
			}
			body := recordSetBody(d, recs)
			if err := validateTemplateBody(TemplateKindDNS, body); err != nil {
				http.Redirect(w, r, domBack(name, "err", "the records do not make a valid set: "+err.Error()), http.StatusSeeOther)
				return
			}
			templates.Upsert("", setName, scopeColorPalette[0], TemplateKindDNS, body)
			if err := templates.Save(ref.Load().TemplatesFile, templateAuthor(r)); err != nil {
				http.Error(w, "save failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, domBack(name, "done", fmt.Sprintf("Record set %q saved with %d record(s) from %s.", setName, len(recs), host)), http.StatusSeeOther)
			return
		}
		http.Error(w, fmt.Sprintf("domain %q not found", name), http.StatusNotFound)
	}
}
