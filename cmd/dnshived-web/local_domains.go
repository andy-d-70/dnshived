// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"dnshived/internal/config"
)

func formatDomainHostLine(h config.LocalDomainHost) string {
	return formatDNSRecordLine(config.DNSRecord{
		Name: h.Host, Type: h.Type, Value: h.Value,
		Target: h.Target, Port: h.Port, Priority: h.Priority, Weight: h.Weight,
		NAPTROrder: h.NAPTROrder, NAPTRFlags: h.NAPTRFlags,
		NAPTRService: h.NAPTRService, NAPTRRegexp: h.NAPTRRegexp,
		CAAFlags: h.CAAFlags, CAATag: h.CAATag,
		RRType: h.RRType, RRDataHex: h.RRDataHex,
		TTL: h.TTL, ProbeDisabled: h.ProbeDisabled,
	})
}

func formatDomainHostLines(records []config.LocalDomainHost) string {
	lines := make([]string, len(records))
	for i, h := range records {
		lines[i] = formatDomainHostLine(h)
	}
	return strings.Join(lines, "\n")
}

func parseDomainHostLine(line string) (config.LocalDomainHost, error) {
	r, err := parseDNSRecordLine(line)
	if err != nil {
		return config.LocalDomainHost{}, err
	}
	return config.LocalDomainHost{
		Host: r.Name, Type: r.Type, Value: r.Value,
		Target: r.Target, Port: r.Port, Priority: r.Priority, Weight: r.Weight,
		NAPTROrder: r.NAPTROrder, NAPTRFlags: r.NAPTRFlags,
		NAPTRService: r.NAPTRService, NAPTRRegexp: r.NAPTRRegexp,
		CAAFlags: r.CAAFlags, CAATag: r.CAATag,
		RRType: r.RRType, RRDataHex: r.RRDataHex,
		TTL: r.TTL, ProbeDisabled: r.ProbeDisabled,
	}, nil
}

// parseDomainHostLines parses a whole textarea's worth of lines, one host
// record per non-blank line.
func parseDomainHostLines(s string) ([]config.LocalDomainHost, error) {
	var records []config.LocalDomainHost
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		h, err := parseDomainHostLine(line)
		if err != nil {
			return nil, err
		}
		records = append(records, h)
	}
	return records, nil
}

// localDomainFormRow is the Local domains & hostnames section's own
// per-domain display/edit row.
type localDomainFormRow struct {
	Name        string
	TTL         int
	TextareaID  string
	RecordsText string
	RecordCount int
	SaveHref    string
	DeleteHref  string
	ForkHref    string
	// ForkedFrom is "" for an independent domain, else the parent domain's own
	// name.
	ForkedFrom string
	UnlinkHref string
	Builder    template.HTML
}

// buildLocalDomainRows turns Cluster.LocalDomains into display rows,
// sorted by name for deterministic, diff-friendly rendering.
func buildLocalDomainRows(domains []config.LocalDomain, existing []dnsExistingRecord) []localDomainFormRow {
	sorted := append([]config.LocalDomain(nil), domains...)
	sortLocalDomains(sorted)
	rows := make([]localDomainFormRow, len(sorted))
	for i, d := range sorted {
		textareaID := "domain_records_" + domainFormID(d.Name)
		rows[i] = localDomainFormRow{
			Name:        d.Name,
			TTL:         d.TTL,
			TextareaID:  textareaID,
			RecordsText: formatDomainHostLines(d.Records),
			RecordCount: len(d.Records),
			SaveHref:    "/config/domains/" + d.Name + "/save",
			DeleteHref:  "/config/domains/" + d.Name + "/delete",
			ForkHref:    "/config/domains/" + d.Name + "/fork",
			ForkedFrom:  d.ForkedFrom,
			UnlinkHref:  "/config/domains/" + d.Name + "/unlink",
			Builder:     dnsRecordBuilderHTML(textareaID, existing),
		}
	}
	return rows
}

// domainFormID turns a domain name into something safe to embed directly
// in an HTML id="" / JS identifier.
func domainFormID(name string) string {
	r := strings.NewReplacer(".", "_", "-", "_")
	return r.Replace(name)
}

func sortLocalDomains(domains []config.LocalDomain) {
	for i := 1; i < len(domains); i++ {
		for j := i; j > 0 && domains[j-1].Name > domains[j].Name; j-- {
			domains[j-1], domains[j] = domains[j], domains[j-1]
		}
	}
}

// handleLocalDomainAddPost (POST /config/domains/new) adds a new,
// initially-empty local domain.
func handleLocalDomainAddPost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		name := strings.TrimSpace(r.PostForm.Get("name"))
		if name == "" {
			http.Error(w, "domain name is required", http.StatusBadRequest)
			return
		}
		ttl, _ := strconv.Atoi(r.PostForm.Get("ttl"))

		current, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		for _, d := range current.LocalDomains {
			if strings.EqualFold(d.Name, name) {
				http.Error(w, fmt.Sprintf("domain %q already exists", name), http.StatusBadRequest)
				return
			}
		}
		payload := clusterPushPayloadFrom(current)
		payload.Scopes = current.Scopes
		payload.LocalDomains = append(append([]config.LocalDomain(nil), current.LocalDomains...),
			config.LocalDomain{Name: name, TTL: ttl})

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/config/dns#domains", "back to DHCP & DNS")
	}
}

func handleLocalDomainForkPost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		source := r.PathValue("name")
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		newName := strings.TrimSpace(r.PostForm.Get("new_name"))
		if newName == "" {
			http.Error(w, "new domain name is required", http.StatusBadRequest)
			return
		}

		current, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		var found *config.LocalDomain
		for _, d := range current.LocalDomains {
			if d.Name == source {
				d := d
				found = &d
			}
			if strings.EqualFold(d.Name, newName) {
				http.Error(w, fmt.Sprintf("domain %q already exists", newName), http.StatusBadRequest)
				return
			}
		}
		if found == nil {
			http.Error(w, fmt.Sprintf("domain %q not found", source), http.StatusNotFound)
			return
		}

		fork := config.LocalDomain{
			Name:       newName,
			TTL:        found.TTL,
			Records:    append([]config.LocalDomainHost(nil), found.Records...),
			ForkedFrom: source,
		}
		payload := clusterPushPayloadFrom(current)
		payload.Scopes = current.Scopes
		payload.LocalDomains = append(append([]config.LocalDomain(nil), current.LocalDomains...), fork)

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/config/dns#domains", "back to DHCP & DNS")
	}
}

// handleLocalDomainUnlinkPost (POST /config/domains/{name}/unlink) breaks
// a fork's link to its parent.
func handleLocalDomainUnlinkPost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		name := r.PathValue("name")

		current, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		found := false
		domains := make([]config.LocalDomain, len(current.LocalDomains))
		for i, d := range current.LocalDomains {
			if d.Name == name {
				d.ForkedFrom = ""
				found = true
			}
			domains[i] = d
		}
		if !found {
			http.Error(w, fmt.Sprintf("domain %q not found", name), http.StatusNotFound)
			return
		}
		payload := clusterPushPayloadFrom(current)
		payload.Scopes = current.Scopes
		payload.LocalDomains = domains

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/config/dns#domains", "back to DHCP & DNS")
	}
}

func handleLocalDomainSavePost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		name := r.PathValue("name")
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		ttl, _ := strconv.Atoi(r.PostForm.Get("ttl"))
		records, err := parseDomainHostLines(r.PostForm.Get("records"))
		if err != nil {
			http.Error(w, "bad input: "+err.Error(), http.StatusBadRequest)
			return
		}

		current, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		found := false
		domains := make([]config.LocalDomain, len(current.LocalDomains))
		for i, d := range current.LocalDomains {
			if d.Name == name {
				d.TTL = ttl
				d.Records = records
				found = true
			}
			domains[i] = d
		}
		if !found {
			http.Error(w, fmt.Sprintf("domain %q not found", name), http.StatusNotFound)
			return
		}
		domains = config.PropagateForkedDomains(domains, name)
		payload := clusterPushPayloadFrom(current)
		payload.Scopes = current.Scopes
		payload.LocalDomains = domains

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/config/dns#domains", "back to DHCP & DNS")
	}
}

// handleLocalDomainDeletePost (POST /config/domains/{name}/delete) removes
// one domain and every host record under it.
func handleLocalDomainDeletePost(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		name := r.PathValue("name")

		current, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		var domains []config.LocalDomain
		for _, d := range current.LocalDomains {
			if d.Name != name {
				domains = append(domains, d)
			}
		}
		payload := clusterPushPayloadFrom(current)
		payload.Scopes = current.Scopes
		payload.LocalDomains = domains

		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, "/config/dns#domains", "back to DHCP & DNS")
	}
}
