// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/csv"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type historyCheck struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Against   string `json:"against"`
	Answered  bool   `json:"answered"`
	Valid     bool   `json:"valid"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error"`
	Reason    string `json:"reason"`
}

// historyRecord mirrors cmd/dnshived-probe.HistoryRecord.
type historyRecord struct {
	Time         time.Time      `json:"ts"`
	Scope        string         `json:"scope"`
	Leg          string         `json:"leg"`
	Interface    string         `json:"interface"`
	VLANID       int            `json:"vlan_id"`
	Outcome      string         `json:"outcome"`
	Verdict      string         `json:"verdict"`
	Reason       string         `json:"reason"`
	Error        string         `json:"error"`
	Servers      []string       `json:"servers"`
	Unexpected   []string       `json:"unexpected"`
	OfferMS      int64          `json:"offer_ms"`
	Checks       []historyCheck `json:"checks"`
	Flags        []string       `json:"flags"`
	FailingForMS int64          `json:"failing_for_ms"`
}

type historySettings struct {
	DHCP       string `json:"dhcp"`
	DNS        string `json:"dns"`
	Syslog     bool   `json:"syslog"`
	MaxFileMB  int    `json:"max_file_mb"`
	MaxFiles   int    `json:"max_files"`
	MaxAgeDays int    `json:"max_age_days"`
}

func (s historySettings) off() bool { return s.DHCP == "none" && s.DNS == "none" }

type historyResponse struct {
	Records   []historyRecord `json:"records"`
	Truncated bool            `json:"truncated"`
	Dropped   uint64          `json:"dropped"`
	SizeBytes int64           `json:"size_bytes"`
	Settings  historySettings `json:"settings"`
}

// fetchHistory asks a probe host for its history; q is passed through.
func fetchHistory(host NodeConfig, q url.Values) (historyResponse, error) {
	var out historyResponse
	status, err := doGet(httpClient, host, "/api/v1/history?"+q.Encode(), &out)
	if err != nil {
		return out, err
	}
	if status != http.StatusOK {
		return out, fmt.Errorf("status %d", status)
	}
	return out, nil
}

// historyRow is one record as the page shows it.
type historyRow struct {
	Time, Scope, Leg, Outcome, Class, Detail, Flags, Failing string
}

func historyDetail(r historyRecord) string {
	var parts []string
	switch r.Leg {
	case "dns":
		for _, c := range r.Checks {
			switch {
			case c.Error != "":
				parts = append(parts, fmt.Sprintf("%s %s @%s: %s", c.Name, c.Type, c.Against, c.Error))
			case !c.Valid:
				why := c.Reason
				if why == "" {
					why = "not valid"
				}
				parts = append(parts, fmt.Sprintf("%s %s @%s: %s", c.Name, c.Type, c.Against, why))
			}
		}
		if len(parts) == 0 && r.Outcome == "ok" {
			parts = append(parts, fmt.Sprintf("%d check(s) answered", len(r.Checks)))
		}
	default:
		if r.Verdict != "" {
			parts = append(parts, r.Verdict)
		}
		if r.Reason != "" {
			parts = append(parts, r.Reason)
		}
		if r.Error != "" {
			parts = append(parts, "error: "+r.Error)
		}
		if len(r.Unexpected) > 0 {
			parts = append(parts, "unexpected: "+strings.Join(r.Unexpected, ", "))
		} else if len(r.Servers) > 0 {
			parts = append(parts, "from "+strings.Join(r.Servers, ", "))
		}
		if r.OfferMS > 0 {
			parts = append(parts, fmt.Sprintf("offer after %d ms", r.OfferMS))
		}
	}
	return strings.Join(parts, "; ")
}

func historyRows(recs []historyRecord) []historyRow {
	out := make([]historyRow, 0, len(recs))
	for _, r := range recs {
		row := historyRow{Time: r.Time.Local().Format("2006-01-02 15:04:05"), Scope: r.Scope, Leg: r.Leg, Outcome: r.Outcome,
			Class: "dim", Detail: historyDetail(r), Flags: strings.Join(r.Flags, ", ")}
		switch r.Outcome {
		case "failed":
			row.Class = "crit"
		case "recovered":
			row.Class = "ok"
			row.Failing = (time.Duration(r.FailingForMS) * time.Millisecond).Round(time.Second).String()
		}
		out = append(out, row)
	}
	return out
}

// csvSafe keeps a spreadsheet from running a cell as a formula.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func historyCSV(w http.ResponseWriter, recs []historyRecord) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="probe-history.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "scope", "leg", "interface", "vlan", "outcome", "detail", "offer_ms", "flags", "failing_for_ms"})
	for _, r := range recs {
		iface := r.Interface
		if r.VLANID != 0 {
			iface += "." + strconv.Itoa(r.VLANID)
		}
		_ = cw.Write([]string{r.Time.UTC().Format(time.RFC3339), csvSafe(r.Scope), r.Leg, csvSafe(iface), strconv.Itoa(r.VLANID), r.Outcome,
			csvSafe(historyDetail(r)), strconv.FormatInt(r.OfferMS, 10), csvSafe(strings.Join(r.Flags, " ")), strconv.FormatInt(r.FailingForMS, 10)})
	}
	cw.Flush()
}

var historyRanges = []struct{ Key, Label string }{{"1h", "last hour"}, {"6h", "6 hours"}, {"24h", "24 hours"}, {"7d", "7 days"}, {"all", "everything kept"}}

func historyRangeSince(key string, now time.Time) time.Time {
	switch key {
	case "1h":
		return now.Add(-time.Hour)
	case "6h":
		return now.Add(-6 * time.Hour)
	case "24h":
		return now.Add(-24 * time.Hour)
	case "7d":
		return now.Add(-7 * 24 * time.Hour)
	}
	return time.Time{}
}

type historyPageData struct {
	Hosts               []NodeConfig
	Host                string
	Scope, Leg, Outcome string
	Range               string
	Ranges              []struct{ Key, Label string }
	Rows                []historyRow
	Err                 string
	Off                 bool
	Truncated           bool
	Dropped             uint64
	Size                string
	OlderURL            string
	CSVURL              string
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

var historyPageTmpl = template.Must(template.New("probe-history").Parse(`<!doctype html>
<title>dnshived-web — probe history</title>
` + styleHTML + `
` + navHTML + `
<h1>Probe history</h1>

<p><a href="/probes">&larr; back to Probes</a></p>
{{if not .Hosts}}<p class="dim">No probe host is configured.</p>{{else}}
<form method="get" action="/probes/history" style="margin-bottom:.8rem">
{{if gt (len .Hosts) 1}}<p>Probe host: {{range .Hosts}}<label><input type="radio" name="host" value="{{.Addr}}"{{if eq .Addr $.Host}} checked{{end}}> {{.Name}}</label> {{end}}</p>{{else}}<input type="hidden" name="host" value="{{.Host}}">{{end}}
<p><label>Scope or manual probe: <input type="text" name="scope" value="{{.Scope}}" size="18" pattern="[A-Za-z0-9_.:-]{1,64}" title="an exact scope name; empty = all"></label>
&nbsp; Check: <label><input type="radio" name="leg" value=""{{if eq .Leg ""}} checked{{end}}> all</label> <label><input type="radio" name="leg" value="dhcp"{{if eq .Leg "dhcp"}} checked{{end}}> DHCP</label> <label><input type="radio" name="leg" value="dns"{{if eq .Leg "dns"}} checked{{end}}> DNS</label> <label><input type="radio" name="leg" value="watch"{{if eq .Leg "watch"}} checked{{end}}> manual probes</label></p>
<p>Show: <label><input type="radio" name="outcome" value=""{{if eq .Outcome ""}} checked{{end}}> all results</label> <label><input type="radio" name="outcome" value="failures"{{if eq .Outcome "failures"}} checked{{end}}> failures and recoveries</label>
&nbsp; Time: {{range .Ranges}}<label><input type="radio" name="range" value="{{.Key}}"{{if eq .Key $.Range}} checked{{end}}> {{.Label}}</label> {{end}}
<button type="submit">Show</button></p>
</form>
{{if .Err}}<p class="crit">{{.Err}}</p>{{end}}
{{if .Off}}<p class="warn" title="Nothing is recorded while both settings are none. Switch it on under Probes, Probe history.">History is switched off for this probe host (DHCP and DNS are both none). <a href="/probes#history">Switch it on</a>.</p>{{end}}
<h2 id="results">{{len .Rows}} result(s){{if .Truncated}} <span class="warn" title="The search stopped at its read limit before the oldest file; narrow the time range.">(search limit reached)</span>{{end}}</h2>
<p class="dim">History on the probe host: {{.Size}} on disk{{if .Dropped}}, <span class="warn" title="The writer could not keep up and dropped the oldest queued entries.">{{.Dropped}} dropped</span>{{end}}.
<a href="{{.CSVURL}}">export as CSV</a></p>
<div class="table-wrap"><table border="1" cellpadding="4">
<tr><th>Time</th><th>Scope</th><th>Check</th><th>Result</th><th>Detail</th><th>Notes</th></tr>
{{range .Rows}}<tr><td style="white-space:nowrap">{{.Time}}</td><td><a href="/probes/history?scope={{.Scope}}">{{.Scope}}</a></td><td>{{.Leg}}</td>
<td class="{{.Class}}">{{.Outcome}}{{if .Failing}} <span class="dim">after {{.Failing}}</span>{{end}}</td><td>{{.Detail}}</td><td class="dim">{{.Flags}}</td></tr>
{{end}}
</table></div>
{{if .OlderURL}}<p><a href="{{.OlderURL}}#results">older &rarr;</a></p>{{end}}
{{end}}`))

// historyQueryFrom turns the page's filters into the probe's query.
func historyQueryFrom(r *http.Request, limit int) (url.Values, string, error) {
	q := url.Values{"limit": {strconv.Itoa(limit)}}
	if s := strings.TrimSpace(r.URL.Query().Get("scope")); s != "" {
		q.Set("scope", s)
	}
	switch leg := r.URL.Query().Get("leg"); leg {
	case "", "dhcp", "dns", "watch":
		if leg != "" {
			q.Set("leg", leg)
		}
	default:
		return nil, "", fmt.Errorf("leg must be dhcp, dns or watch")
	}
	if r.URL.Query().Get("outcome") == "failures" {
		q.Set("outcome", "failures")
	}
	rng := r.URL.Query().Get("range")
	if rng == "" {
		rng = "24h"
	}
	if since := historyRangeSince(rng, time.Now()); !since.IsZero() {
		q.Set("since", since.UTC().Format(time.RFC3339Nano))
	}
	if u := r.URL.Query().Get("until"); u != "" {
		if _, err := time.Parse(time.RFC3339Nano, u); err != nil {
			return nil, "", fmt.Errorf("until must be an RFC 3339 time")
		}
		q.Set("until", u)
	}
	return q, rng, nil
}

// handleProbeHistory serves GET /probes/history, and its CSV export.
func handleProbeHistory(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		data := historyPageData{Hosts: cfg.ProbeHosts, Ranges: historyRanges}
		if len(cfg.ProbeHosts) == 0 {
			renderTemplate(w, historyPageTmpl, data, "probe-history")
			return
		}
		host := cfg.ProbeHosts[0]
		if addr := r.URL.Query().Get("host"); addr != "" {
			if h, ok := probeHostByAddr(cfg, addr); ok {
				host = h
			}
		}
		data.Host = host.Addr
		csvOut := r.URL.Query().Get("format") == "csv"
		limit := 200
		if csvOut {
			limit = 1000
		}
		q, rng, err := historyQueryFrom(r, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		data.Scope, data.Leg, data.Outcome, data.Range = q.Get("scope"), q.Get("leg"), q.Get("outcome"), rng
		resp, err := fetchHistory(host, q)
		if err != nil {
			if csvOut {
				http.Error(w, "probe history: "+err.Error(), http.StatusBadGateway)
				return
			}
			data.Err = "Could not read the history from " + host.Name + ": " + err.Error() + " (a probe host without this feature needs an upgrade)"
			renderTemplate(w, historyPageTmpl, data, "probe-history")
			return
		}
		if csvOut {
			historyCSV(w, resp.Records)
			return
		}
		data.Rows = historyRows(resp.Records)
		data.Off, data.Truncated, data.Dropped, data.Size = resp.Settings.off(), resp.Truncated, resp.Dropped, humanBytes(resp.SizeBytes)
		base := url.Values{"host": {host.Addr}, "range": {rng}}
		for _, k := range []string{"scope", "leg", "outcome"} {
			if v := q.Get(k); v != "" {
				base.Set(k, v)
			}
		}
		csvQ := url.Values{}
		for k, v := range base {
			csvQ[k] = v
		}
		csvQ.Set("format", "csv")
		data.CSVURL = "/probes/history?" + csvQ.Encode()
		if len(resp.Records) >= limit {
			base.Set("until", resp.Records[len(resp.Records)-1].Time.UTC().Format(time.RFC3339Nano))
			data.OlderURL = "/probes/history?" + base.Encode()
		}
		renderTemplate(w, historyPageTmpl, data, "probe-history")
	}
}

// historyHostRow is one probe host's history setting as the Probes page shows it.
type historyHostRow struct {
	Name, Addr, Size string
	Settings         historySettings
	Dropped          uint64
	Err              string
}

func buildHistoryHostRows(hosts []NodeConfig) []historyHostRow {
	out := make([]historyHostRow, 0, len(hosts))
	for _, h := range hosts {
		row := historyHostRow{Name: h.Name, Addr: h.Addr}
		resp, err := fetchHistory(h, url.Values{"limit": {"1"}})
		if err != nil {
			row.Err = err.Error()
		} else {
			row.Settings, row.Dropped, row.Size = resp.Settings, resp.Dropped, humanBytes(resp.SizeBytes)
		}
		out = append(out, row)
	}
	return out
}

// handleProbeHistorySettings serves POST /probes/history.
func handleProbeHistorySettings(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		host, ok := probeHostByAddr(ref.Load(), strings.TrimSpace(r.PostForm.Get("addr")))
		if !ok {
			http.Error(w, "unknown probe host", http.StatusNotFound)
			return
		}
		num := func(k string) (int, error) {
			v := strings.TrimSpace(r.PostForm.Get(k))
			if v == "" {
				return 0, nil
			}
			return strconv.Atoi(v)
		}
		hist := map[string]interface{}{"dhcp": r.PostForm.Get("dhcp"), "dns": r.PostForm.Get("dns"), "syslog": r.PostForm.Get("syslog") != ""}
		for _, k := range []string{"max_file_mb", "max_files", "max_age_days"} {
			n, err := num(k)
			if err != nil {
				http.Error(w, k+" must be a number", http.StatusBadRequest)
				return
			}
			if n != 0 {
				hist[k] = n
			}
		}
		user, _ := userFromContext(r)
		err := postProbeConfig(host, map[string]interface{}{"history": hist})
		summary := fmt.Sprintf("history on %s: dhcp=%v dns=%v syslog=%v", host.Name, hist["dhcp"], hist["dns"], hist["syslog"])
		if err != nil {
			summary += " FAILED: " + err.Error()
		}
		pushAudit(host, user.Name, "probe.history", summary)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/probes#history", http.StatusSeeOther)
	}
}

// attachScopeHistory fills the detail view's recent history from the probe host.
func attachScopeHistory(d *probeDetailData, host NodeConfig) {
	resp, err := fetchHistory(host, url.Values{"scope": {d.Scope}, "limit": {"8"}})
	switch {
	case err != nil:
		d.HistoryErr = err.Error()
	case resp.Settings.off():
		d.HistoryOff = true
	default:
		d.HistoryRows = historyRows(resp.Records)
	}
}
