// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"dnshived/internal/config"
)

var (
	mailboxRe  = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+$`)
	selectorRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._\-]{0,62}$`)
	hostNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._\-]*$`)
	base64Re   = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
)

// mailRecordLines builds the SPF, DMARC and DKIM records the wizard form asks
// for, in the app's line format. Each part is optional; an invalid field is an
// error that names it.
func mailRecordLines(f url.Values) ([]string, error) {
	var lines []string
	if f.Get("spf") != "" {
		parts := []string{"v=spf1"}
		if f.Get("spf_mx") != "" {
			parts = append(parts, "mx")
		}
		if f.Get("spf_a") != "" {
			parts = append(parts, "a")
		}
		for _, inc := range strings.FieldsFunc(f.Get("spf_include"), func(r rune) bool { return r == ' ' || r == ',' || r == '\n' }) {
			if !hostNameRe.MatchString(inc) {
				return nil, fmt.Errorf("SPF include %q is not a host name", inc)
			}
			parts = append(parts, "include:"+inc)
		}
		end := f.Get("spf_end")
		if end != "-all" && end != "~all" && end != "?all" {
			end = "~all"
		}
		lines = append(lines, "TXT|@|"+strings.Join(append(parts, end), " "))
	}
	if f.Get("dmarc") != "" {
		policy := f.Get("dmarc_policy")
		if policy != "none" && policy != "quarantine" && policy != "reject" {
			return nil, fmt.Errorf("the DMARC policy must be none, quarantine or reject")
		}
		val := "v=DMARC1; p=" + policy
		if rua := strings.TrimSpace(f.Get("dmarc_rua")); rua != "" {
			if !mailboxRe.MatchString(rua) {
				return nil, fmt.Errorf("the DMARC report address %q is not one mailbox address (a list is not supported here)", rua)
			}
			val += "; rua=mailto:" + rua
		}
		if pct := strings.TrimSpace(f.Get("dmarc_pct")); pct != "" {
			n, err := strconv.Atoi(pct)
			if err != nil || n < 0 || n > 100 {
				return nil, fmt.Errorf("the DMARC percentage must be 0 to 100")
			}
			if n != 100 {
				val += "; pct=" + pct
			}
		}
		for _, k := range []string{"adkim", "aspf"} {
			if v := f.Get("dmarc_" + k); v == "r" || v == "s" {
				if v == "s" {
					val += "; " + k + "=s"
				}
			}
		}
		lines = append(lines, "TXT|_dmarc|"+val)
	}
	if sel := strings.TrimSpace(f.Get("dkim_selector")); sel != "" || strings.TrimSpace(f.Get("dkim_key")) != "" {
		if !selectorRe.MatchString(sel) {
			return nil, fmt.Errorf("the DKIM selector %q is not valid (letters, digits, dot, hyphen, underscore)", sel)
		}
		key := strings.TrimSpace(strings.NewReplacer("\r", "", "\n", "", `"`, "").Replace(f.Get("dkim_key")))
		if !strings.HasPrefix(key, "v=DKIM1") {
			key = strings.TrimPrefix(strings.NewReplacer(" ", "", "\t", "").Replace(key), "p=")
		}
		if strings.HasPrefix(key, "v=DKIM1") {
			if strings.ContainsAny(key, ",") {
				return nil, fmt.Errorf("the DKIM record may not contain a comma")
			}
			lines = append(lines, "TXT|"+sel+"._domainkey|"+key)
		} else {
			if len(key) < 40 || !base64Re.MatchString(key) {
				return nil, fmt.Errorf("paste the DKIM public key (base64) or the whole record starting with v=DKIM1")
			}
			lines = append(lines, "TXT|"+sel+"._domainkey|v=DKIM1; k=rsa; p="+key)
		}
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("choose at least one of SPF, DMARC or DKIM")
	}
	return lines, nil
}

// markSecondPolicy flags a generated SPF or DMARC record when the domain has
// one already: a name may carry only one of each.
func markSecondPolicy(rows []importRow, existing []config.LocalDomainHost) {
	has := func(host, prefix string) bool {
		for _, h := range existing {
			if strings.EqualFold(h.Type, "TXT") && strings.EqualFold(domHostLabel(h.Host), host) && strings.HasPrefix(strings.ToLower(h.Value), prefix) {
				return true
			}
		}
		return false
	}
	for i := range rows {
		if rows[i].Status != "new" {
			continue
		}
		switch {
		case strings.HasPrefix(rows[i].Line, "TXT|@|v=spf1") && has("@", "v=spf1"):
			rows[i].Status, rows[i].Note = "conflict", "the domain already has an SPF record; a name may carry only one"
		case strings.HasPrefix(rows[i].Line, "TXT|_dmarc|v=DMARC1") && has("_dmarc", "v=dmarc1"):
			rows[i].Status, rows[i].Note = "conflict", "the domain already has a DMARC record; a name may carry only one"
		}
	}
}

func handleDomainMailPreview(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		lines, err := mailRecordLines(r.PostForm)
		if err != nil {
			http.Redirect(w, r, domBack(name, "err", err.Error()), http.StatusSeeOther)
			return
		}
		cluster, _, pending, cerr := currentEditableConfig(nodesIncludingSelf(ref.Load()))
		if cerr != nil {
			http.Error(w, "could not read the configuration from any node: "+cerr.Error(), http.StatusBadGateway)
			return
		}
		for _, d := range cluster.LocalDomains {
			if d.Name != name {
				continue
			}
			if d.ForkedFrom != "" {
				http.Redirect(w, r, domBack(name, "err", "this domain is linked to "+d.ForkedFrom+"; add the mail records to the original"), http.StatusSeeOther)
				return
			}
			p := importPage{Pending: pending, Domain: name, Title: "Mail records for " + name, Rows: parseImport(name, d.Records, strings.Join(lines, "\n"))}
			markSecondPolicy(p.Rows, d.Records)
			p.count()
			renderTemplate(w, importTmpl, p, "mail records preview")
			return
		}
		http.Error(w, fmt.Sprintf("domain %q not found", name), http.StatusNotFound)
	}
}
