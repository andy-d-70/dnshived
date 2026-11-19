// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"html/template"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/dhcpcentralrender"
)

const simSlots = 3

const simMaxRecords = 30

var simMACRe = regexp.MustCompile(`^(?i)[0-9a-f]{2}([:-][0-9a-f]{2}){5}$`)

type simClient struct {
	MAC, Name, IP, Scope string
	Known                bool
	Static               bool
}

type simRecord struct{ Name, Type, Data string }

// simResult is what one client would get in one scope.
type simResult struct {
	Error      string
	Notes      []string
	Client     string
	MAC        string
	Scope      string
	Subnet     string
	Address    string
	AddressHow string
	Mask       string
	Gateway    string
	Server     string
	Lease      string
	DNS        string
	Options    []string
	Names      []string
	Records    []simRecord
	MoreRecs   int
}

// resolveClient turns what was typed into a client: a MAC (known or not), or a
// search over name, address and MAC of the known hosts.
func resolveClient(input string, rows []hostRow) (simClient, string, bool) {
	in := strings.TrimSpace(input)
	if in == "" {
		return simClient{}, "", false
	}
	if simMACRe.MatchString(in) {
		mac := strings.ToLower(strings.ReplaceAll(in, "-", ":"))
		for _, r := range rows {
			if strings.EqualFold(r.MAC, mac) {
				return clientFromRow(r), "", true
			}
		}
		return simClient{MAC: mac}, "", true
	}
	low := strings.ToLower(in)
	var found []hostRow
	for _, r := range rows {
		if strings.Contains(strings.ToLower(r.Name), low) || strings.Contains(strings.ToLower(r.ResName), low) || strings.Contains(r.IP, low) || strings.Contains(strings.ToLower(r.MAC), low) {
			found = append(found, r)
		}
	}
	switch len(found) {
	case 0:
		return simClient{}, "no known client matches " + in, true
	case 1:
		return clientFromRow(found[0]), "", true
	}
	return clientFromRow(found[0]), fmt.Sprintf("%d clients match %q; showing the first (%s)", len(found), in, found[0].MAC), true
}

func clientFromRow(r hostRow) simClient {
	name := r.Name
	if name == "" {
		name = r.ResName
	}
	return simClient{MAC: strings.ToLower(r.MAC), Name: name, IP: r.IP, Scope: r.Scope, Known: true, Static: r.Unknown}
}

func findReservation(cluster config.Cluster, mac string) (config.Reservation, string, bool) {
	names := make([]string, 0, len(cluster.Scopes))
	for n := range cluster.Scopes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		for _, res := range cluster.Scopes[n].Reservations {
			if strings.EqualFold(res.MAC, mac) {
				return res, n, true
			}
		}
	}
	return config.Reservation{}, "", false
}

func recordData(r config.DNSRecord) string {
	if strings.EqualFold(r.Type, "SRV") {
		return fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, r.Target)
	}
	return r.Value
}

// simulate works out what a client would get in a scope from the cluster
// configuration and the known leases; it sends nothing.
func simulate(cluster config.Cluster, scope string, cl simClient, rows []hostRow) simResult {
	out := simResult{MAC: cl.MAC, Scope: scope}
	out.Client = cl.MAC
	if cl.Name != "" {
		out.Client = cl.Name + " · " + cl.MAC
	}
	ans, ok := dhcpcentralrender.ScopeAnswer(cluster, scope)
	if !ok {
		out.Error = "scope " + scope + " is unknown or incomplete, so it serves no clients"
		return out
	}
	sc := cluster.Scopes[scope]
	if sc.DNSMasqDisabled {
		out.Notes = append(out.Notes, "DHCP and DNS are switched off for this scope; a client would get no answer")
	}
	if cl.Static {
		out.Notes = append(out.Notes, "this host uses a static address and does not ask for DHCP")
	}
	prefix, perr := netip.ParsePrefix(sc.VIP)
	if perr == nil {
		out.Subnet = prefix.Masked().String()
	}
	out.Mask, out.Gateway, out.Server, out.Lease, out.DNS = ans.Netmask, ans.Router, ans.ServerID, ans.LeaseTime, ans.DNSServers
	out.Options = ans.Options

	inScope := func(ip string) bool {
		a, err := netip.ParseAddr(ip)
		return err == nil && perr == nil && prefix.Contains(a)
	}
	res, resScope, hasRes := findReservation(cluster, cl.MAC)
	switch {
	case hasRes && inScope(res.IP):
		out.Address, out.AddressHow = res.IP, "reserved"
		out.Names = res.DNSNames()
	case cl.MAC == "":
		out.Address, out.AddressHow = ans.RangeStart+" – "+ans.RangeEnd, "from the pool"
	default:
		if hasRes {
			out.Notes = append(out.Notes, fmt.Sprintf("reserved as %s in scope %s, which is another network; here it gets a pool address", res.IP, resScope))
		}
		leased := ""
		for _, r := range rows {
			if strings.EqualFold(r.MAC, cl.MAC) && r.Scope == scope && !r.Unknown {
				leased = r.IP
				break
			}
		}
		if leased != "" {
			out.Address, out.AddressHow = leased, "current lease"
		} else {
			out.Address, out.AddressHow = ans.RangeStart+" – "+ans.RangeEnd, "from the pool"
		}
		if cl.Name != "" {
			out.Names = []string{cl.Name + " (the name the client sends)"}
		}
	}
	add := func(rs []config.DNSRecord) {
		for _, r := range rs {
			if !strings.HasPrefix(r.Name, "_") {
				continue
			}
			if len(out.Records) >= simMaxRecords {
				out.MoreRecs++
				continue
			}
			out.Records = append(out.Records, simRecord{Name: r.Name, Type: strings.ToUpper(r.Type), Data: recordData(r)})
		}
	}
	add(sc.DNSRecords)
	add(cluster.GlobalDNSRecords)
	return out
}

type simRow struct {
	Label string
	Cells []simCell
}

type simCell struct {
	Lines []string
	Class string
}

func one(s string) simCell {
	if s == "" {
		return simCell{Lines: []string{"—"}, Class: "dim"}
	}
	return simCell{Lines: []string{s}}
}

func many(ss []string) simCell {
	if len(ss) == 0 {
		return simCell{Lines: []string{"—"}, Class: "dim"}
	}
	return simCell{Lines: ss}
}

// simRows lays the results out one row per property, one column per slot.
func simRows(rs []simResult) []simRow {
	rows := []simRow{
		{Label: "Client"}, {Label: "Scope"}, {Label: "Address"}, {Label: "Subnet mask"}, {Label: "Gateway"},
		{Label: "DHCP server"}, {Label: "Lease time"}, {Label: "DNS servers"}, {Label: "Other options"},
		{Label: "Published as"}, {Label: "Service records"}, {Label: "Notes"},
	}
	for _, r := range rs {
		if r.Error != "" {
			for i := range rows {
				c := simCell{Lines: []string{"—"}, Class: "dim"}
				switch rows[i].Label {
				case "Client":
					c = one(r.Client)
				case "Scope":
					c = one(r.Scope)
				case "Notes":
					c = simCell{Lines: []string{r.Error}, Class: "crit"}
				}
				rows[i].Cells = append(rows[i].Cells, c)
			}
			continue
		}
		var recs []string
		for _, rec := range r.Records {
			recs = append(recs, rec.Name+"  "+rec.Type+"  "+rec.Data)
		}
		if r.MoreRecs > 0 {
			recs = append(recs, fmt.Sprintf("… and %d more", r.MoreRecs))
		}
		addr := simCell{Lines: []string{r.Address, r.AddressHow}}
		cells := []simCell{
			one(r.Client), one(r.Scope + "  " + r.Subnet), addr, one(r.Mask), one(r.Gateway),
			one(r.Server), one(r.Lease), one(strings.ReplaceAll(r.DNS, ",", ", ")), many(r.Options),
			many(r.Names), many(recs), many(r.Notes),
		}
		cells[len(cells)-1].Class = "warn"
		for i := range rows {
			rows[i].Cells = append(rows[i].Cells, cells[i])
		}
	}
	return rows
}

type simSlotForm struct {
	N      int
	Client string
	Scope  string
}

type simulatorPageData struct {
	Slots   []simSlotForm
	Scopes  []string
	Clients []simClientOption
	Rows    []simRow
	Heads   []string
	Notes   []string
	Error   string
}

type simClientOption struct{ Value, Label string }

var simulatorTmpl = template.Must(template.New("simulator").Parse(`<!doctype html>
<title>dnshived-web — client simulator</title>
` + styleHTML + `
` + navHTML + `
<div class="pagehead"><h1>Client simulator</h1></div>
<p class="dim">What a client would get in a scope, worked out from the configuration and the known leases. Nothing is sent and nothing changes. Leave the scope empty to use the client's current one; compare up to three clients, or the same client in up to three scopes.</p>
{{if .Error}}<p class="crit">{{.Error}}</p>{{end}}
<form method="get" action="/simulator" class="card probe-card">
<div class="table-wrap"><table class="list-table sim-form">
<colgroup><col style="width:3rem"><col><col style="width:22rem"></colgroup>
<tr><th></th><th>Client (MAC, name or address)</th><th>Scope</th></tr>
{{range .Slots}}<tr><td>{{.N}}</td>
<td><input name="c{{.N}}" value="{{.Client}}" list="sim-clients" placeholder="aa:bb:cc:dd:ee:ff or a name" autocomplete="off" style="width:100%"></td>
<td><select name="s{{.N}}" class="js-combo"><option value="">(current scope)</option>{{$s := .Scope}}{{range $.Scopes}}<option value="{{.}}"{{if eq . $s}} selected{{end}}>{{.}}</option>{{end}}</select></td></tr>
{{end}}
</table></div>
<datalist id="sim-clients">{{range .Clients}}<option value="{{.Value}}">{{.Label}}</option>{{end}}</datalist>
<p style="margin:.6rem 0 0"><button type="submit" class="btn-success">Simulate</button></p>
</form>
{{range .Notes}}<p class="warn">{{.}}</p>{{end}}
{{if .Rows}}
<div class="table-wrap"><table class="list-table sim-result" border="1" cellpadding="4">
<tr><th style="width:11rem"></th>{{range .Heads}}<th>{{.}}</th>{{end}}</tr>
{{range .Rows}}<tr><th class="rowhead">{{.Label}}</th>{{range .Cells}}<td class="{{.Class}}">{{range .Lines}}<div>{{.}}</div>{{end}}</td>{{end}}</tr>
{{end}}
</table></div>
{{end}}
` + comboboxScriptHTML + `
`))

func simulatorSlotsFrom(q url.Values) []simSlotForm {
	out := make([]simSlotForm, simSlots)
	for i := range out {
		n := i + 1
		out[i] = simSlotForm{N: n, Client: strings.TrimSpace(q.Get(fmt.Sprintf("c%d", n))), Scope: strings.TrimSpace(q.Get(fmt.Sprintf("s%d", n)))}
	}
	return out
}

func handleSimulator(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		nodes := nodesIncludingSelf(cfg)
		rows := fetchAllStatus(cfg, nodes)
		tokens := fetchArbiterTokens(cfg, rows)
		cluster, _, cerr := firstReachableConfig(nodes)
		data := simulatorPageData{Slots: simulatorSlotsFrom(r.URL.Query())}
		if cerr != nil {
			data.Error = "no node answered with the configuration: " + cerr.Error()
			renderTemplate(w, simulatorTmpl, data, "simulator")
			return
		}
		for n := range cluster.Scopes {
			data.Scopes = append(data.Scopes, n)
		}
		sort.Strings(data.Scopes)
		probeOctet := ""
		if len(cfg.ProbeHosts) > 0 {
			probeOctet = nodeAddrLastOctet(cfg.ProbeHosts[0].Addr)
		}
		scopes := buildScopeRows(rows, cluster.Scopes, tokens, roleByNodeID(rows), iotScopeSet(rows), map[string]bool{})
		hosts := fetchHostRows(scopes, cluster, nodes, probeOctet, time.Now())
		sortHostRows(hosts)
		for _, h := range hosts {
			label := h.Name
			if label == "" {
				label = h.ResName
			}
			data.Clients = append(data.Clients, simClientOption{Value: h.MAC, Label: strings.TrimSpace(label + " " + h.IP + " " + h.Scope)})
		}
		data.Rows, data.Heads, data.Notes = runSimulation(cluster, hosts, data.Slots)
		renderTemplate(w, simulatorTmpl, data, "simulator")
	}
}

// runSimulation simulates every filled slot.
func runSimulation(cluster config.Cluster, hosts []hostRow, slots []simSlotForm) ([]simRow, []string, []string) {
	var results []simResult
	var heads, notes []string
	for _, s := range slots {
		cl, note, ok := resolveClient(s.Client, hosts)
		if !ok {
			continue
		}
		if note != "" {
			notes = append(notes, fmt.Sprintf("Slot %d: %s", s.N, note))
		}
		if cl.MAC == "" {
			results = append(results, simResult{Error: note, Client: s.Client})
			heads = append(heads, fmt.Sprintf("Slot %d", s.N))
			continue
		}
		scope := s.Scope
		if scope == "" {
			scope = cl.Scope
		}
		heads = append(heads, fmt.Sprintf("Slot %d", s.N))
		if scope == "" {
			results = append(results, simResult{Error: "pick a scope: this client has no current scope", Client: cl.MAC, MAC: cl.MAC})
			continue
		}
		results = append(results, simulate(cluster, scope, cl, hosts))
	}
	if len(results) == 0 {
		return nil, nil, notes
	}
	return simRows(results), heads, notes
}
