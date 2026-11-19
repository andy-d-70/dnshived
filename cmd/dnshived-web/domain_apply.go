// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"net/http"
	"strings"
)

const recordSetPlaceholderDomain = "fake.lan"

// expandRecordSet rewrites a record set for a domain: the set's own example
// domain (fake.lan) and the {domain} placeholder become the domain, and names
// under the domain turn into the relative hosts a domain stores. Lines come
// out in the app's line format.
func expandRecordSet(domain, body string) []string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		for i := 1; i < len(parts); i++ {
			parts[i] = strings.ReplaceAll(strings.ReplaceAll(parts[i], "{domain}", domain), recordSetPlaceholderDomain, domain)
		}
		if len(parts) > 1 {
			name := strings.TrimSpace(parts[1])
			low, dom := strings.ToLower(name), strings.ToLower(strings.TrimSuffix(domain, "."))
			switch {
			case low == dom:
				parts[1] = "@"
			case strings.HasSuffix(low, "."+dom):
				parts[1] = name[:len(name)-len(dom)-1]
			}
		}
		out = append(out, strings.Join(parts, "|"))
	}
	return out
}

func handleDomainApplyPreview(ref *configRef, templates *TemplateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		set, ok := templates.Get(r.PostForm.Get("set"))
		if !ok || set.Kind != TemplateKindDNS {
			http.Redirect(w, r, domBack(name, "err", "pick a record set"), http.StatusSeeOther)
			return
		}
		cluster, _, pending, err := currentEditableConfig(nodesIncludingSelf(ref.Load()))
		if err != nil {
			http.Error(w, "could not read the configuration from any node: "+err.Error(), http.StatusBadGateway)
			return
		}
		for _, d := range cluster.LocalDomains {
			if d.Name != name {
				continue
			}
			if d.ForkedFrom != "" {
				http.Redirect(w, r, domBack(name, "err", "this domain is linked to "+d.ForkedFrom+"; apply the set to the original"), http.StatusSeeOther)
				return
			}
			p := importPage{Pending: pending, Domain: name, Title: fmt.Sprintf("Apply %q to %s", set.Name, name),
				Rows: parseImport(name, d.Records, strings.Join(expandRecordSet(name, set.Body), "\n"))}
			p.count()
			renderTemplate(w, importTmpl, p, "record set preview")
			return
		}
		http.Error(w, fmt.Sprintf("domain %q not found", name), http.StatusNotFound)
	}
}
