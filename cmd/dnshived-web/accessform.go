// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"dnshived/internal/access"
)

const (
	accessPathNetworks = "/config/access"
	accessPathHosts    = "/config/access/hosts"
	accessPathReport   = "/config/access/report"
)

// accessTabs is the strip shared by the three Access pages; the first four are the cluster settings tabs.
func accessTabs(string) template.HTML {
	items := [][2]string{
		{"/config#tab-nodes", "Nodes"}, {"/config#tab-interfaces", "Interfaces &amp; VIP"}, {"/config#tab-addresses", "DNS &amp; DHCP addresses"}, {"/config#tab-misc", "Misc"},
		{accessPathNetworks, "Access"},
	}
	return template.HTML(tabLinksHTML(items, accessPathNetworks))
}

func accessSubTabs(active string) template.HTML {
	return template.HTML(tabLinksHTML([][2]string{
		{accessPathNetworks, "Networks"}, {accessPathHosts, "Whitelisted hosts"}, {accessPathReport, "Report and test"},
	}, active))
}

// cloneAccess copies a list so an edit never touches the one it started from.
func cloneAccess(c *access.Config) *access.Config {
	out := &access.Config{}
	if c == nil {
		return out
	}
	out.Mode = c.Mode
	if c.Private != nil {
		p := *c.Private
		out.Private = &p
	}
	out.Entries = append([]access.Entry(nil), c.Entries...)
	out.Hosts = append([]access.Host(nil), c.Hosts...)
	return out
}

func verdictOf(v string) string {
	if v == access.Deny {
		return access.Deny
	}
	return access.Allow
}

func normNet(s string) (string, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return "", fmt.Errorf("%q is not a network like 192.0.2.0/24 or 2001:db8::/32", s)
	}
	return p.Masked().String(), nil
}

func normMAC(s string) (string, error) {
	m, err := access.ParseMAC(s)
	if err != nil {
		return "", err
	}
	return net.HardwareAddr(m[:]).String(), nil
}

func hostKey(h access.Host) string { return h.Addr + "|" + h.MAC }

// wideNetwork reports a network that allows everyone or a very wide public range.
func wideNetwork(netStr string) bool {
	p, err := netip.ParsePrefix(netStr)
	if err != nil {
		return false
	}
	if p.Bits() == 0 {
		return true
	}
	return (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 16)
}

// applyAccessOp applies one form operation to a copy of cur. It never changes cur.
func applyAccessOp(cur *access.Config, f url.Values) (*access.Config, error) {
	c := cloneAccess(cur)
	checked := func(k string) bool { return f.Get(k) == "1" }
	switch op := f.Get("op"); op {
	case "mode":
		m := f.Get("mode")
		if m != access.ModeReport && m != access.ModeEnforce {
			return nil, fmt.Errorf("the mode is report or enforce")
		}
		c.Mode = m
	case "private":
		c.Private = &access.Entry{Off: !checked("on"), DNS: verdictOf(f.Get("dns")), DHCP: verdictOf(f.Get("dhcp")), Web: verdictOf(f.Get("web")), Note: strings.TrimSpace(f.Get("note"))}
	case "entry-add":
		n, err := normNet(f.Get("net"))
		if err != nil {
			return nil, err
		}
		for _, e := range c.Entries {
			if e.Net == n {
				return nil, fmt.Errorf("the network %s is already in the list", n)
			}
		}
		e := access.Entry{Net: n, Note: strings.TrimSpace(f.Get("note")), DNS: verdictOf(f.Get("dns")), DHCP: verdictOf(f.Get("dhcp")), Web: verdictOf(f.Get("web"))}
		if wideNetwork(n) && (e.DNS == access.Allow || e.DHCP == access.Allow || e.Web == access.Allow) && !checked("confirm") {
			return nil, fmt.Errorf("the network %s is very wide: it allows everyone or almost everyone, which turns the list off. Tick \"I understand\" to add it", n)
		}
		c.Entries = append(c.Entries, e)
	case "entry-set":
		i := -1
		for k, e := range c.Entries {
			if e.Net == f.Get("net") {
				i = k
			}
		}
		if i < 0 {
			return nil, fmt.Errorf("the network %q is no longer in the list", f.Get("net"))
		}
		c.Entries[i].Off = !checked("on")
		c.Entries[i].Note = strings.TrimSpace(f.Get("note"))
		c.Entries[i].DNS, c.Entries[i].DHCP, c.Entries[i].Web = verdictOf(f.Get("dns")), verdictOf(f.Get("dhcp")), verdictOf(f.Get("web"))
	case "entry-del":
		out := c.Entries[:0:0]
		found := false
		for _, e := range c.Entries {
			if e.Net == f.Get("net") {
				found = true
				continue
			}
			out = append(out, e)
		}
		if !found {
			return nil, fmt.Errorf("the network %q is no longer in the list", f.Get("net"))
		}
		c.Entries = out
	case "host-add":
		h := access.Host{Addr: strings.TrimSpace(f.Get("addr")), Note: strings.TrimSpace(f.Get("note")), DNS: checked("hdns"), DHCP: checked("hdhcp"), Web: checked("hweb")}
		if h.Addr != "" {
			a, err := netip.ParseAddr(h.Addr)
			if err != nil {
				return nil, fmt.Errorf("%q is not an address", h.Addr)
			}
			h.Addr = a.Unmap().String()
		}
		if m := strings.TrimSpace(f.Get("mac")); m != "" {
			nm, err := normMAC(m)
			if err != nil {
				return nil, err
			}
			h.MAC = nm
		}
		c.Hosts = append(c.Hosts, h)
	case "host-set":
		i := -1
		for k, h := range c.Hosts {
			if hostKey(h) == f.Get("key") {
				i = k
			}
		}
		if i < 0 {
			return nil, fmt.Errorf("that host is no longer in the list")
		}
		c.Hosts[i].Note = strings.TrimSpace(f.Get("note"))
		c.Hosts[i].DNS, c.Hosts[i].DHCP, c.Hosts[i].Web = checked("hdns"), checked("hdhcp"), checked("hweb")
	case "host-del":
		out := c.Hosts[:0:0]
		found := false
		for _, h := range c.Hosts {
			if hostKey(h) == f.Get("key") {
				found = true
				continue
			}
			out = append(out, h)
		}
		if !found {
			return nil, fmt.Errorf("that host is no longer in the list")
		}
		c.Hosts = out
	default:
		return nil, fmt.Errorf("unknown operation %q", op)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// accessLockout refuses a list that would cut the operator off from the web interface.
func accessLockout(c *access.Config, always []string, src netip.Addr) error {
	if !c.Enforcing() || !src.IsValid() {
		return nil
	}
	var addrs []netip.Addr
	for _, a := range always {
		if ip, err := netip.ParseAddr(a); err == nil {
			addrs = append(addrs, ip)
		}
	}
	m, err := access.New(c, addrs)
	if err != nil {
		return err
	}
	if d := m.Check(access.Web, src); !d.Allowed {
		return fmt.Errorf("refused: with this list your own address %s would not be served on the web interface (%s), and you would be locked out", src, d.Rule)
	}
	return nil
}

func requestAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// accessLine is one entry for display.
type accessLine struct {
	Net, Note, DNS, DHCP, Web string
	On                        bool
	Built                     bool
}

type accessHostLine struct {
	Key, Addr, MAC, Note string
	DNS, DHCP, Web       bool
}

type accessTestRow struct{ Service, Verdict, Why string }

type accessReportRow struct {
	Node, Service, Source string
	Count                 uint64
	Last                  string
}

type accessPageData struct {
	Section    string
	Tabs, Sub  template.HTML
	SourceNode string
	Pending    bool
	Notice     string
	Mode       string
	Enforce    bool
	Active     bool
	Required   string
	Blocking   []accessBlock
	YourAddr   string
	YourWeb    string
	Private    accessLine
	Lines      []accessLine
	Hosts      []accessHostLine
	TestAddr   string
	Test       []accessTestRow
	Report     []accessReportRow
	WebDropped int64
	PagerTop   pagerBar
	PagerBot   pagerBar
	NodeErrors []string
}

func privateLine(c *access.Config) accessLine {
	l := accessLine{Net: "Private networks", Note: "RFC 1918 and fc00::/7", On: true, DNS: access.Allow, DHCP: access.Allow, Web: access.Allow, Built: true}
	if c != nil && c.Private != nil {
		l.On = !c.Private.Off
		l.DNS, l.DHCP, l.Web = verdictOf(c.Private.DNS), verdictOf(c.Private.DHCP), verdictOf(c.Private.Web)
		if c.Private.Note != "" {
			l.Note = c.Private.Note
		}
	}
	return l
}

func handleAccessPage(ref *configRef, section string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		nodes := nodesIncludingSelf(cfg)
		cur, node, pending, err := currentEditableConfig(nodes)
		if err != nil {
			http.Error(w, "could not read the configuration from any node: "+err.Error(), http.StatusBadGateway)
			return
		}
		list := cur.Access
		d := accessPageData{Section: section, Tabs: accessTabs(section), Sub: accessSubTabs(section), SourceNode: node.Name, Pending: pending, Mode: access.ModeReport}
		if list != nil && list.Mode != "" {
			d.Mode = list.Mode
		}
		d.Enforce = d.Mode == access.ModeEnforce
		d.Private = privateLine(list)
		d.YourAddr = requestAddr(r).String()
		if n := r.URL.Query().Get("notice"); n != "" {
			d.Notice = n
		}
		always := cur.AccessAlways()
		if list != nil {
			var addrs []netip.Addr
			for _, a := range always {
				if ip, err := netip.ParseAddr(a); err == nil {
					addrs = append(addrs, ip)
				}
			}
			if m, merr := access.New(list, addrs); merr == nil && requestAddr(r).IsValid() {
				dec := m.Check(access.Web, requestAddr(r))
				d.YourWeb = acceptText(dec)
			}
		} else {
			d.YourWeb = "allowed (no list yet: everyone is served)"
		}
		d.WebDropped = webAccessState.failed.Load()
		if section == "report" || section == "networks" {
			for _, n := range nodes {
				st, ferr := fetchAccessState(n)
				if ferr != nil {
					d.NodeErrors = append(d.NodeErrors, n.Name+": "+ferr.Error())
					continue
				}
				if n.Name == node.Name || !d.Active {
					d.Active, d.Required, d.Blocking = st.Active, st.Required, st.Blocking
				}
				if section == "report" {
					for _, it := range st.DNS.Items {
						d.Report = append(d.Report, accessReportRow{Node: n.Name, Service: "DNS", Source: it.Src, Count: it.Count, Last: it.Last.Format("15:04:05")})
					}
					for _, it := range st.DHCP.Items {
						d.Report = append(d.Report, accessReportRow{Node: n.Name, Service: "DHCP (network)", Source: it.Src, Count: it.Count, Last: it.Last.Format("15:04:05")})
					}
				}
			}
		}
		q := r.URL.Query()
		per := pagerPer(q)
		page, _ := strconv.Atoi(q.Get("page"))
		keep := pagerKeep(url.Values{}, per)
		var total int
		switch section {
		case "networks":
			for _, e := range cloneAccess(list).Entries {
				d.Lines = append(d.Lines, accessLine{Net: e.Net, Note: e.Note, On: !e.Off, DNS: verdictOf(e.DNS), DHCP: verdictOf(e.DHCP), Web: verdictOf(e.Web)})
			}
			sort.SliceStable(d.Lines, func(i, j int) bool { return d.Lines[i].Net < d.Lines[j].Net })
			total = len(d.Lines)
		case "hosts":
			for _, h := range cloneAccess(list).Hosts {
				d.Hosts = append(d.Hosts, accessHostLine{Key: hostKey(h), Addr: h.Addr, MAC: h.MAC, Note: h.Note, DNS: h.DNS, DHCP: h.DHCP, Web: h.Web})
			}
			total = len(d.Hosts)
		case "report":
			sort.SliceStable(d.Report, func(i, j int) bool { return d.Report[i].Count > d.Report[j].Count })
			total = len(d.Report)
			if t := strings.TrimSpace(q.Get("test")); t != "" {
				d.TestAddr = t
				d.Test = accessTest(list, always, t)
			}
		}
		size := pagerSize(per, total)
		pages := (total + size - 1) / size
		if pages == 0 {
			pages = 1
		}
		if page < 1 {
			page = 1
		}
		if page > pages {
			page = pages
		}
		start, end := (page-1)*size, page*size
		if end > total {
			end = total
		}
		path := map[string]string{"networks": accessPathNetworks, "hosts": accessPathHosts, "report": accessPathReport}[section]
		d.PagerTop, d.PagerBot = newPagerBars(path, keep, per, total, page, pages, start, end)
		switch section {
		case "networks":
			d.Lines = d.Lines[start:end]
		case "hosts":
			d.Hosts = d.Hosts[start:end]
		case "report":
			d.Report = d.Report[start:end]
		}
		renderTemplate(w, accessPageTmpl, d, "access")
	}
}

func acceptText(d access.Decision) string {
	if d.Allowed {
		return "allowed by " + d.Rule
	}
	return "NOT allowed (" + d.Rule + ")"
}

// accessTest answers for one address or MAC what the list decides for each service.
func accessTest(list *access.Config, always []string, in string) []accessTestRow {
	var addrs []netip.Addr
	for _, a := range always {
		if ip, err := netip.ParseAddr(a); err == nil {
			addrs = append(addrs, ip)
		}
	}
	m, err := access.New(list, addrs)
	if err != nil {
		return []accessTestRow{{Service: "list", Verdict: "invalid", Why: err.Error()}}
	}
	if m == nil {
		return []accessTestRow{{Service: "all", Verdict: "served", Why: "there is no list yet: everyone is served"}}
	}
	if mac, err := access.ParseMAC(in); err == nil {
		v := "dropped"
		why := "not whitelisted for DHCP (a DHCP client is judged by its network)"
		if m.CheckMAC(mac) {
			v, why = "served", "whitelisted host"
		}
		return []accessTestRow{{Service: "DHCP", Verdict: v, Why: why}}
	}
	a, err := netip.ParseAddr(in)
	if err != nil {
		return []accessTestRow{{Service: "input", Verdict: "invalid", Why: fmt.Sprintf("%q is neither an address nor a MAC", in)}}
	}
	var rows []accessTestRow
	for _, s := range []struct {
		svc  access.Service
		name string
	}{{access.DNS, "DNS"}, {access.DHCP, "DHCP (judged by the client's network)"}, {access.Web, "Web interface"}} {
		d := m.Check(s.svc, a)
		v := "dropped"
		if d.Allowed {
			v = "served"
		}
		why := d.Rule
		if !d.Allowed && !m.Enforcing() {
			why += " (report mode: still answered today)"
		}
		rows = append(rows, accessTestRow{Service: s.name, Verdict: v, Why: why})
	}
	return rows
}

func handleAccessSave(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		back := accessPathNetworks
		switch r.PostForm.Get("back") {
		case "hosts":
			back = accessPathHosts
		case "report":
			back = accessPathReport
		}
		current, _, _, err := currentEditableConfig(nodesIncludingSelf(cfg))
		if err != nil {
			http.Error(w, "could not read current config: "+err.Error(), http.StatusBadGateway)
			return
		}
		updated, err := applyAccessOp(current.Access, r.PostForm)
		if err != nil {
			http.Error(w, "bad input: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := accessLockout(updated, current.AccessAlways(), requestAddr(r)); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		payload := clusterPushPayloadFrom(current)
		payload.Scopes = current.Scopes
		raw, err := marshalAccess(updated)
		if err != nil {
			http.Error(w, "encode access list: "+err.Error(), http.StatusInternalServerError)
			return
		}
		payload.Access = raw
		user, _ := userFromContext(r)
		pushCandidateAndRenderResult(w, cfg, payload, user, back, "back to Access")
	}
}

// marshalAccess encodes a list for a push; no list is left out of the push.
func marshalAccess(c *access.Config) (json.RawMessage, error) {
	if c == nil {
		return nil, nil
	}
	return json.Marshal(c)
}
