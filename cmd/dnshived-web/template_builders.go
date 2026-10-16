// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"strings"

	"dnshived/internal/config"
)

// This file backs the template editor's structured field builders
// (templates.go's new/edit pages).

// dnsFieldSpec is one input field a DNS record type needs, in the exact
// order formatDNSRecordLine (dnsrecords_text.go) expects it.
type dnsFieldSpec struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Type  string `json:"type"` // "text" or "number", for the generated <input type=...>
}

// dnsTypeSpec describes one config.DNSRecord type's own field shape.
type dnsTypeSpec struct {
	Type   string         `json:"type"`
	Fields []dnsFieldSpec `json:"fields"`
}

var dnsRecordTypeCatalog = []dnsTypeSpec{
	{"A", []dnsFieldSpec{{"value", "IPv4 address", "text"}}},
	{"AAAA", []dnsFieldSpec{{"value", "IPv6 address", "text"}}},
	{"CNAME", []dnsFieldSpec{{"value", "target hostname", "text"}}},
	{"TXT", []dnsFieldSpec{{"value", "text value", "text"}}},
	{"PTR", []dnsFieldSpec{{"value", "target hostname", "text"}}},
	{"MX", []dnsFieldSpec{{"target", "mail server hostname", "text"}, {"priority", "priority", "number"}}},
	{"SRV", []dnsFieldSpec{{"target", "target hostname", "text"}, {"port", "port", "number"}, {"priority", "priority", "number"}, {"weight", "weight", "number"}}},
	{"NAPTR", []dnsFieldSpec{{"target", "replacement/target", "text"}, {"order", "order", "number"}, {"priority", "priority", "number"}, {"flags", "flags", "text"}, {"service", "service", "text"}, {"regexp", "regexp", "text"}}},
	{"CAA", []dnsFieldSpec{{"flags", "flags", "number"}, {"tag", "tag (issue/issuewild/iodef)", "text"}, {"value", "value", "text"}}},
	{"RAW", []dnsFieldSpec{{"rrtype", "RR type (numeric)", "number"}, {"rrdatahex", "RR data (hex)", "text"}}},
}

// dhcpOption is one curated, commonly-used dnsmasq --dhcp-option name.
type dhcpOption struct {
	Code  int
	Name  string
	Label string
	Hint  string // placeholder text for the value input
}

var dhcpOptionCatalog = []dhcpOption{
	{6, "dns-server", "DNS server", "8.8.8.8 (comma-separate for more than one)"},
	{15, "domain-name", "Domain name", "example.lan"},
	{19, "ip-forwarding", "IP forwarding", "0 or 1"},
	{26, "mtu", "MTU", "1500"},
	{28, "broadcast", "Broadcast address", "192.168.1.255"},
	{40, "nis-domain", "NIS domain", ""},
	{41, "nis-server", "NIS server", ""},
	{42, "ntp-server", "NTP server", "192.168.1.10"},
	{44, "netbios-ns", "NetBIOS name server", ""},
	{46, "netbios-nodetype", "NetBIOS node type", "8"},
	{66, "tftp-server", "TFTP server", "192.168.1.20"},
	{67, "bootfile-name", "Bootfile name (PXE)", "pxelinux.0"},
	{119, "domain-search", "Domain search list", "example.lan"},
	{121, "classless-static-route", "Classless static route", "192.168.2.0/24,192.168.1.1"},
	{252, "wpad", "WPAD (proxy autoconfig) URL", "http://wpad.example.lan/wpad.dat"},
}

// dnsExistingRecord is one already-configured (name, type, value) tuple
// from the live cluster.
type dnsExistingRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	Where string `json:"where"`
}

func collectExistingDNSRecords(c config.Cluster) []dnsExistingRecord {
	var out []dnsExistingRecord
	for _, r := range c.GlobalDNSRecords {
		out = append(out, dnsExistingRecord{Name: r.Name, Type: r.Type, Value: recordCollisionValue(r), Where: "global"})
	}
	for name, sc := range c.Scopes {
		for _, r := range sc.DNSRecords {
			out = append(out, dnsExistingRecord{Name: r.Name, Type: r.Type, Value: recordCollisionValue(r), Where: "scope " + name})
		}
	}
	for _, d := range c.LocalDomains {
		for _, r := range d.ExpandedRecords() {
			out = append(out, dnsExistingRecord{Name: r.Name, Type: r.Type, Value: recordCollisionValue(r), Where: "local domain " + d.Name})
		}
	}
	return out
}

// recordCollisionValue picks the one field worth comparing for the "same
// name, different value" warning.
func recordCollisionValue(r config.DNSRecord) string {
	if r.Target != "" {
		return r.Target
	}
	return r.Value
}

// dnsExistingRecordsJS embeds collectExistingDNSRecords' result as a JSON
// array the record builder's JS reads directly.
func dnsExistingRecordsJS(records []dnsExistingRecord) template.JS {
	b, err := json.Marshal(records)
	if err != nil {
		return "[]"
	}
	return template.JS(b)
}

// dnsRecordBuilderHTML renders the structured "add a DNS record" panel.
func dnsRecordBuilderHTML(textareaID string, existing []dnsExistingRecord) template.HTML {
	var b strings.Builder
	b.WriteString(`<div class="tpl-builder">`)
	b.WriteString(`<select id="` + textareaID + `_type" onchange="dnsBuilderShowFields_` + textareaID + `(this.value)">`)
	for _, spec := range dnsRecordTypeCatalog {
		b.WriteString(`<option value="` + spec.Type + `">` + spec.Type + `</option>`)
	}
	b.WriteString(`</select> `)
	b.WriteString(`<input id="` + textareaID + `_name" placeholder="name" list="` + textareaID + `_names"> `)
	b.WriteString(`<datalist id="` + textareaID + `_names">`)
	seen := make(map[string]bool)
	for _, r := range existing {
		if seen[r.Name] {
			continue
		}
		seen[r.Name] = true
		b.WriteString(`<option value="` + template.HTMLEscapeString(r.Name) + `">`)
	}
	b.WriteString(`</datalist>`)
	for _, spec := range dnsRecordTypeCatalog {
		b.WriteString(`<span class="tpl-builder-fields" id="` + textareaID + `_fields_` + spec.Type + `" style="display:none">`)
		for _, f := range spec.Fields {
			b.WriteString(` <input type="` + f.Type + `" id="` + textareaID + `_` + spec.Type + `_` + f.Key + `" placeholder="` + f.Label + `">`)
		}
		b.WriteString(`</span>`)
	}
	b.WriteString(` <button type="button" onclick="dnsBuilderAdd_` + textareaID + `()">+ add record</button>`)
	b.WriteString(` <span id="` + textareaID + `_warn" class="warn"></span>`)
	b.WriteString(`</div>`)
	b.WriteString(`<script>
(function(){
  var EXISTING = ` + string(dnsExistingRecordsJS(existing)) + `;
  var TYPES = ` + dnsRecordTypeCatalogJS() + `;
  window.dnsBuilderShowFields_` + textareaID + ` = function(type){
    TYPES.forEach(function(t){
      var el = document.getElementById('` + textareaID + `_fields_' + t.type);
      if(el) el.style.display = (t.type === type) ? '' : 'none';
    });
  };
  window.dnsBuilderAdd_` + textareaID + ` = function(){
    var typeSel = document.getElementById('` + textareaID + `_type');
    var type = typeSel.value;
    var name = document.getElementById('` + textareaID + `_name').value.trim();
    var warn = document.getElementById('` + textareaID + `_warn');
    warn.textContent = '';
    if(name === ''){ warn.textContent = 'name is required'; return; }
    var spec = null;
    TYPES.forEach(function(t){ if(t.type === type) spec = t; });
    if(!spec) return;
    var parts = [type, name];
    var compareValue = '';
    for(var i = 0; i < spec.fields.length; i++){
      var f = spec.fields[i];
      var input = document.getElementById('` + textareaID + `_' + type + '_' + f.key);
      var v = input ? input.value.trim() : '';
      parts.push(v);
      if(i === 0) compareValue = v; // first field is always the "points at" value (value/target)
    }
    var line = parts.join('|');
    var ta = document.getElementById('` + textareaID + `');
    var have = ta.value.split("\n").filter(function(l){ return l !== ''; });
    if(have.indexOf(line) === -1){ have.push(line); }
    ta.value = have.join("\n");
    // Same-name-different-value check: warn only, never block.
    var hits = EXISTING.filter(function(e){ return e.name === name && e.type === type && e.value !== compareValue && e.value !== ''; });
    if(hits.length > 0){
      warn.textContent = 'note: ' + name + ' (' + type + ') already resolves to ' + hits[0].value + ' via ' + hits[0].where + ' — fine if that\'s intentional (per-scope names resolve independently)';
    }
  };
  document.addEventListener('DOMContentLoaded', function(){
    window.dnsBuilderShowFields_` + textareaID + `(document.getElementById('` + textareaID + `_type').value);
  });
})();
</script>`)
	return template.HTML(b.String())
}

// dnsRecordTypeCatalogJS embeds dnsRecordTypeCatalog itself for the
// builder's JS (field key list per type) — same inline-JSON idiom as
// dnsExistingRecordsJS.
func dnsRecordTypeCatalogJS() string {
	b, err := json.Marshal(dnsRecordTypeCatalog)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// dhcpOptionBuilderHTML renders the structured "add a DHCP option" panel.
func dhcpOptionBuilderHTML(textareaID string) template.HTML {
	var b strings.Builder
	b.WriteString(`<div class="tpl-builder">`)
	b.WriteString(`<select id="` + textareaID + `_opt" onchange="dhcpBuilderHint_` + textareaID + `(this)">`)
	for _, o := range dhcpOptionCatalog {
		b.WriteString(fmt.Sprintf(`<option value="%s" data-hint="%s">%d - %s</option>`,
			template.HTMLEscapeString(o.Name), template.HTMLEscapeString(o.Hint), o.Code, template.HTMLEscapeString(o.Label)))
	}
	b.WriteString(`</select> `)
	b.WriteString(`<input id="` + textareaID + `_val" placeholder="value"> `)
	b.WriteString(`<button type="button" onclick="dhcpBuilderAdd_` + textareaID + `()">+ add option</button>`)
	b.WriteString(`</div>`)
	b.WriteString(`<script>
function dhcpBuilderHint_` + textareaID + `(sel){
  var val = document.getElementById('` + textareaID + `_val');
  var opt = sel.options[sel.selectedIndex];
  if(val) val.placeholder = opt.getAttribute('data-hint') || 'value';
}
function dhcpBuilderAdd_` + textareaID + `(){
  var sel = document.getElementById('` + textareaID + `_opt');
  var val = document.getElementById('` + textareaID + `_val');
  var name = sel.value, v = val.value.trim();
  if(v === '') return;
  var line = 'option:' + name + ',' + v;
  var ta = document.getElementById('` + textareaID + `');
  var have = ta.value.split("\n").filter(function(l){ return l !== ''; });
  if(have.indexOf(line) === -1){ have.push(line); }
  ta.value = have.join("\n");
  val.value = '';
}
document.addEventListener('DOMContentLoaded', function(){
  var sel = document.getElementById('` + textareaID + `_opt');
  if(sel) dhcpBuilderHint_` + textareaID + `(sel);
});
</script>`)
	return template.HTML(b.String())
}

const templateBuilderStyleHTML = `<style>
.tpl-builder{background:var(--panel);border:1px solid var(--border);border-radius:8px;
padding:.5rem .7rem;margin:0 0 .5rem}
.tpl-builder select,.tpl-builder input{margin:.15rem}
</style>`
