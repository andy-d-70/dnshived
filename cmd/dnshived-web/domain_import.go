// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"html/template"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"dnshived/internal/config"
)

const importMaxBytes = 512 << 10

const importMaxLines = 5000

var importAppLineRe = regexp.MustCompile(`^[A-Za-z]+\|`)

type importRow struct {
	Raw    string
	Line   string
	Status string
	Note   string
}

// splitZoneFields splits a zone-file line into fields; a quoted string stays
// one field, quotes included.
func splitZoneFields(s string) []string {
	var out []string
	var cur strings.Builder
	inQ, esc := false, false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, c := range s {
		switch {
		case esc:
			cur.WriteRune(c)
			esc = false
		case inQ && c == '\\':
			cur.WriteRune(c)
			esc = true
		case c == '"':
			cur.WriteRune(c)
			if inQ {
				flush()
			}
			inQ = !inQ
		case !inQ && (c == ' ' || c == '\t'):
			flush()
		case !inQ && c == ';':
			flush()
			return out
		default:
			cur.WriteRune(c)
		}
	}
	flush()
	return out
}

func unquoteZone(fields []string) string {
	var b strings.Builder
	for _, f := range fields {
		f = strings.TrimPrefix(strings.TrimSuffix(f, `"`), `"`)
		b.WriteString(strings.NewReplacer(`\"`, `"`, `\\`, `\`).Replace(f))
	}
	return b.String()
}

// zoneHost makes an owner or target relative to the domain when it lies in
// it; ok is false for an absolute name outside the domain.
func zoneHost(name, domain string) (string, bool) {
	if name == "@" || name == "" {
		return "@", true
	}
	if !strings.HasSuffix(name, ".") {
		return name, true
	}
	abs, dom := strings.ToLower(name), strings.ToLower(strings.TrimSuffix(domain, "."))+"."
	if abs == dom {
		return "@", true
	}
	if strings.HasSuffix(abs, "."+dom) {
		return name[:len(name)-len(dom)-1], true
	}
	return "", false
}

var zoneTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "PTR": true, "MX": true, "SRV": true, "TXT": true, "CAA": true}

// parseZoneRecord reads one zone-file record line (owner [ttl] [IN] TYPE data).
func parseZoneRecord(domain, last string, fields []string, defTTL int) (config.LocalDomainHost, string, error) {
	var h config.LocalDomainHost
	owner := last
	i := 0
	if len(fields) > 0 && !isZoneTTL(fields[0]) && !strings.EqualFold(fields[0], "IN") && !zoneTypes[strings.ToUpper(fields[0])] {
		owner = fields[0]
		i = 1
	}
	h.TTL = defTTL
	for i < len(fields) {
		if isZoneTTL(fields[i]) {
			h.TTL, _ = strconv.Atoi(fields[i])
			i++
		} else if strings.EqualFold(fields[i], "IN") {
			i++
		} else {
			break
		}
	}
	if i >= len(fields) {
		return h, owner, fmt.Errorf("no record type")
	}
	typ := strings.ToUpper(fields[i])
	data := fields[i+1:]
	if !zoneTypes[typ] {
		return h, owner, fmt.Errorf("%s records are not imported", typ)
	}
	host, ok := zoneHost(owner, domain)
	if !ok {
		return h, owner, fmt.Errorf("the name %s is outside %s", owner, domain)
	}
	h.Host, h.Type = host, typ
	need := func(n int) error {
		if len(data) < n {
			return fmt.Errorf("%s needs %d fields", typ, n)
		}
		return nil
	}
	atoi := func(s string) int { n, _ := strconv.Atoi(s); return n }
	switch typ {
	case "A", "AAAA":
		if err := need(1); err != nil {
			return h, owner, err
		}
		h.Value = data[0]
	case "CNAME", "PTR":
		if err := need(1); err != nil {
			return h, owner, err
		}
		h.Value = data[0]
	case "MX":
		if err := need(2); err != nil {
			return h, owner, err
		}
		h.Priority, h.Target = atoi(data[0]), data[1]
	case "SRV":
		if err := need(4); err != nil {
			return h, owner, err
		}
		h.Priority, h.Weight, h.Port, h.Target = atoi(data[0]), atoi(data[1]), atoi(data[2]), data[3]
	case "TXT":
		if err := need(1); err != nil {
			return h, owner, err
		}
		h.Value = unquoteZone(data)
	case "CAA":
		if err := need(3); err != nil {
			return h, owner, err
		}
		h.CAAFlags, h.CAATag, h.Value = atoi(data[0]), data[1], unquoteZone(data[2:])
	}
	return h, owner, nil
}

func isZoneTTL(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// parseImport turns pasted text (the app's lines or a zone file) into rows
// with a status: new, duplicate, conflict or skipped.
func parseImport(domain string, existing []config.LocalDomainHost, text string) []importRow {
	var rows []importRow
	have := append([]config.LocalDomainHost(nil), existing...)
	defTTL, last := 0, "@"
	for n, raw := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		if n >= importMaxLines {
			rows = append(rows, importRow{Status: "skipped", Note: fmt.Sprintf("only the first %d lines are read", importMaxLines)})
			break
		}
		trim := strings.TrimSpace(raw)
		if trim == "" || strings.HasPrefix(trim, ";") || strings.HasPrefix(trim, "#") {
			continue
		}
		row := importRow{Raw: trim}
		var h config.LocalDomainHost
		var err error
		switch {
		case importAppLineRe.MatchString(trim):
			h, err = parseDomainHostLine(trim)
		case strings.HasPrefix(trim, "$"):
			f := splitZoneFields(trim)
			if strings.EqualFold(f[0], "$TTL") && len(f) > 1 {
				defTTL, _ = strconv.Atoi(f[1])
			}
			continue
		default:
			var owner string
			f := splitZoneFields(raw)
			if len(f) == 0 {
				continue
			}
			if raw[0] == ' ' || raw[0] == '\t' {
				f = append([]string{last}, f...)
			}
			h, owner, err = parseZoneRecord(domain, last, f, defTTL)
			last = owner
		}
		if err != nil {
			row.Status, row.Note = "skipped", err.Error()
			rows = append(rows, row)
			continue
		}
		row.Line = formatDomainHostLine(h)
		if perr := precheckRecord(have, h, -1); perr != nil {
			if strings.Contains(perr.Error(), "already has this record") {
				row.Status, row.Note = "duplicate", "already in the domain"
			} else {
				row.Status, row.Note = "conflict", perr.Error()
			}
		} else {
			row.Status = "new"
			have = append(have, h)
		}
		rows = append(rows, row)
	}
	return rows
}

type importPage struct {
	Pending bool
	Title   string
	Domain  string
	Rows    []importRow
	New     int
	Dup     int
	Conf    int
	Skip    int
	Lines   string
	Text    string
}

var importTmpl = template.Must(template.New("import").Parse(`<!doctype html>
<title>dnshived-web — import records</title>
` + styleHTML + `
` + navHTML + pendingBannerHTML + `
<div class="pagehead"><h1>{{if .Title}}{{.Title}}{{else}}Import into {{.Domain}}{{end}}</h1></div>
<p class="dim">Nothing is staged yet. {{.New}} new, {{.Dup}} duplicate, {{.Conf}} in conflict, {{.Skip}} skipped. Only the new records are staged; duplicates and conflicts are left out.</p>
<div class="table-wrap"><table class="list-table" border="1" cellpadding="4">
<colgroup><col style="width:8rem"><col><col style="width:40%"></colgroup>
<tr><th>Result</th><th>Record</th><th>Note</th></tr>
{{range .Rows}}<tr><td><span class="chip {{if eq .Status "new"}}ok{{else if eq .Status "conflict"}}crit{{else}}warn{{end}}">{{.Status}}</span></td><td class="mono">{{if .Line}}{{.Line}}{{else}}{{.Raw}}{{end}}</td><td class="dim">{{.Note}}</td></tr>
{{else}}<tr><td colspan="3" class="dim">No records found in the text.</td></tr>{{end}}
</table></div>
<form method="post" action="/config/domains/{{.Domain}}/import/stage" style="margin-top:.8rem">
<input type="hidden" name="lines" value="{{.Lines}}">
{{if .New}}<button type="submit" class="btn-success">Stage {{.New}} new record(s)</button>{{end}}
<a href="/config/domains?d={{.Domain}}" style="margin-left:1rem">Cancel</a>
</form>
`))

// count tallies the rows and collects the lines of the new ones.
func (p *importPage) count() {
	var lines []string
	for _, row := range p.Rows {
		switch row.Status {
		case "new":
			p.New++
			lines = append(lines, row.Line)
		case "duplicate":
			p.Dup++
		case "conflict":
			p.Conf++
		default:
			p.Skip++
		}
	}
	p.Lines = strings.Join(lines, "\n")
}

func handleDomainImportPreview(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		r.Body = http.MaxBytesReader(w, r.Body, importMaxBytes)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form or too large: "+err.Error(), http.StatusBadRequest)
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
				http.Redirect(w, r, domBack(name, "err", "this domain is linked to "+d.ForkedFrom+"; import into the original"), http.StatusSeeOther)
				return
			}
			p := importPage{Pending: pending, Domain: name, Rows: parseImport(name, d.Records, r.PostForm.Get("text"))}
			p.count()
			renderTemplate(w, importTmpl, p, "domain import")
			return
		}
		http.Error(w, fmt.Sprintf("domain %q not found", name), http.StatusNotFound)
	}
}

func handleDomainImportStage(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		r.Body = http.MaxBytesReader(w, r.Body, importMaxBytes)
		mutateDomain(ref, w, r, name, func(d *config.LocalDomain) error {
			added := 0
			for _, line := range strings.Split(r.PostForm.Get("lines"), "\n") {
				if strings.TrimSpace(line) == "" {
					continue
				}
				h, err := parseDomainHostLine(strings.TrimSpace(line))
				if err != nil {
					return err
				}
				if err := precheckRecord(d.Records, h, -1); err != nil {
					return err
				}
				d.Records = append(d.Records, h)
				added++
			}
			if added == 0 {
				return fmt.Errorf("nothing to import")
			}
			return nil
		})
	}
}
