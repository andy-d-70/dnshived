// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsmasqrender

import (
	"bytes"
	"strconv"
	"text/template"

	"dnshived/internal/config"
)

// Data is the template's own input shape — unchanged field-for-field
// from internal/agent's previous unexported dnsmasqData, just exported.
type Data struct {
	Scope, Interface   string
	DHCPStart, DHCPEnd string
	LeaseTime          string
	Gateway            string
	DataDir            string
	HasReservations    bool
	NoPing             bool
	Broadcast          bool
	Authoritative      bool
	DNSRecords         []config.DNSRecord
	DHCPOptions        []string
}

// Template is the exact dnsmasq config template every real scope's
// dnsmasq-<scope>.conf is rendered from.
var Template = template.Must(template.New("dnsmasq").Parse(`# dnshived managed — scope {{.Scope}}
# DO NOT EDIT — this file is rendered by dnshived and will be overwritten.
# user=/group= — direct instruction: "we will not run dnsmasq as root,
# we drop privs." Reuses the "dnshived" system user/group (debian/
# dnshived.postinst already creates it, --shell /usr/sbin/nologin) —
# no new packaging surface. Relies entirely on dnsmasq's own built-in
# privilege-drop mechanism, not a systemd User=: dnsmasq (started as
# root by systemd, unit unchanged) opens its listening socket, the
# lease file, and the log file WHILE STILL ROOT, then calls its own
# setuid/setgid down to user=/group= — the already-open fds stay valid
# afterward regardless of the new (lower) UID, and dnsmasq retains
# exactly the capabilities it still needs (CAP_NET_BIND_SERVICE for
# port 53, CAP_NET_RAW/CAP_NET_ADMIN for DHCP) via its own internal
# capability handling. This is why the fix is these two lines alone —
# no file/directory permission changes needed, no systemd unit change.
user=dnshived
group=dnshived
interface={{.Interface}}
bind-dynamic
except-interface=lo
no-resolv
dhcp-range={{.DHCPStart}},{{.DHCPEnd}},{{.LeaseTime}}
dhcp-option=option:router,{{.Gateway}}
dhcp-leasefile={{.DataDir}}/leases-{{.Scope}}
log-facility={{.DataDir}}/dnsmasq-{{.Scope}}.log
{{- if .HasReservations}}
conf-file={{.DataDir}}/reservations-{{.Scope}}.conf
{{- end}}
{{- if .NoPing}}
no-ping
{{- end}}
{{- if .Broadcast}}
dhcp-broadcast
{{- end}}
{{- if .Authoritative}}
dhcp-authoritative
{{- end}}
{{- template "dnsrecords" .DNSRecords}}
{{- range .DHCPOptions}}
dhcp-option={{.}}
{{- end}}
`))

// dnsRecordsTemplateText is associated into Template's own template set
// below (init) so the main template can invoke it via {{template
// "dnsrecords" .DNSRecords}}.
const dnsRecordsTemplateText = `{{- range .}}
{{- if or (eq .Type "A") (eq .Type "AAAA")}}
host-record={{.Name}},{{.Value}}{{if .TTL}},{{.TTL}}{{end}}
{{- else if eq .Type "CNAME"}}
cname={{.Name}},{{.Value}}{{if .TTL}},{{.TTL}}{{end}}
{{- else if eq .Type "TXT"}}
txt-record={{.Name}},{{.Value}}
{{- else if eq .Type "SRV"}}
srv-host={{.Name}},{{.Target}},{{.Port}},{{.Priority}},{{.Weight}}
{{- else if eq .Type "PTR"}}
ptr-record={{.Name}},{{.Value}}
{{- else if eq .Type "MX"}}
mx-host={{.Name}},{{.Target}},{{.Priority}}
{{- else if eq .Type "NAPTR"}}
naptr-record={{.Name}},{{.NAPTROrder}},{{.Priority}},{{.NAPTRFlags}},{{.NAPTRService}},{{.NAPTRRegexp}},{{.Target}}
{{- else if eq .Type "CAA"}}
caa-record={{.Name}},{{.CAAFlags}},{{.CAATag}},{{.Value}}
{{- else if eq .Type "RAW"}}
dns-rr={{.Name}},{{.RRType}}{{if .RRDataHex}},{{.RRDataHex}}{{end}}
{{- end}}
{{- end}}`

func init() {
	template.Must(Template.New("dnsrecords").Parse(dnsRecordsTemplateText))
}

// RenderDNSRecords returns the exact dnsmasq directive lines for records,
// one per entry, formatted per its own Type.
func RenderDNSRecords(records []config.DNSRecord) (string, error) {
	var buf bytes.Buffer
	if err := Template.ExecuteTemplate(&buf, "dnsrecords", records); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// iotDefaultLeaseTime mirrors internal/agent's own constant of the same
// name (config.ScopeConfig.DHCPIoTDefaults' bundled lease-time value).
const iotDefaultLeaseTime = "24h"

// EffectiveDHCPBool resolves one of DHCPBroadcast/DHCPAuthoritative's
// tri-state overrides against DHCPIoTDefaults' bundle default.
func EffectiveDHCPBool(override *bool, bundleDefault bool) bool {
	if override != nil {
		return *override
	}
	return bundleDefault
}

// ReservationsTemplate renders sc.Reservations into the exact dnsmasq
// dhcp-host= lines that make up reservations-<scope>.conf.
var ReservationsTemplate = template.Must(template.New("reservations").Parse(`{{- range .}}
dhcp-host={{.MAC}},{{.IP}}{{if .Hostname}},{{.Hostname}}{{end}}
{{- end}}
`))

// RenderReservations returns the exact text for a scope's
// reservations-<scope>.conf, straight from its own Reservations field.
func RenderReservations(reservations []config.Reservation) (string, error) {
	var buf bytes.Buffer
	if err := ReservationsTemplate.Execute(&buf, reservations); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func Render(scope string, sc config.ScopeConfig, globalRecords []config.DNSRecord, defaultDHCPOptions []string, dataDir string) (string, error) {
	iface := sc.Parent + "." + strconv.Itoa(sc.VLANID)
	hasReservations := len(sc.Reservations) > 0

	leaseTime := sc.DHCPLeaseTime
	if leaseTime == "" {
		if sc.DHCPIoTDefaults {
			leaseTime = iotDefaultLeaseTime
		} else {
			leaseTime = "12h"
		}
	}

	allRecords := make([]config.DNSRecord, 0, len(globalRecords)+len(sc.DNSRecords))
	allRecords = append(allRecords, globalRecords...)
	allRecords = append(allRecords, sc.DNSRecords...)

	dhcpOptions := sc.DHCPOptions
	if len(dhcpOptions) == 0 {
		dhcpOptions = defaultDHCPOptions
	}

	var buf bytes.Buffer
	if err := Template.Execute(&buf, Data{
		Scope: scope, Interface: iface,
		DHCPStart: sc.DHCPRange[0], DHCPEnd: sc.DHCPRange[1], LeaseTime: leaseTime, Gateway: sc.Gateway,
		DataDir: dataDir, HasReservations: hasReservations, NoPing: sc.DHCPNoPing,
		Broadcast:     EffectiveDHCPBool(sc.DHCPBroadcast, sc.DHCPIoTDefaults),
		Authoritative: EffectiveDHCPBool(sc.DHCPAuthoritative, sc.DHCPIoTDefaults),
		DNSRecords:    allRecords,
		DHCPOptions:   dhcpOptions,
	}); err != nil {
		return "", err
	}
	return buf.String(), nil
}
