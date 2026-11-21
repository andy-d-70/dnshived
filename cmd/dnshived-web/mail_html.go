// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"html/template"
	"strings"
	"time"

	"dnshived/internal/notify"
)

//go:embed mail_logo.png
var mailLogoPNG []byte

const mailLogoCID = "dnshived-logo"

// mailLevel maps a message class to the colour band of its mail.
func mailLevel(class string) string {
	switch class {
	case notify.ClassError:
		return "crit"
	case notify.ClassWarning:
		return "warn"
	case notify.ClassSummary:
		return "ok"
	}
	return "info"
}

type mailView struct {
	Band, Tint, Name, Cluster, Time, Class, Headline, Link, Subject string
	Facts                                                           []notify.Fact
	Details                                                         []notify.Detail
}

var mailColours = map[string][2]string{
	"crit": {"#c0392b", "#fdecea"},
	"warn": {"#955806", "#fff4e0"},
	"ok":   {"#0a7a34", "#e8f6ed"},
	"info": {"#0d9488", "#e6f5f3"},
}

var notifyMailTmpl = template.Must(template.New("mail").Parse(`<!doctype html>
<html><body style="margin:0;padding:0;background:#f3f4f6;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1f2937">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden">
<tr><td style="padding:16px 24px;border-bottom:1px solid #e5e7eb">
<table role="presentation" cellpadding="0" cellspacing="0"><tr>
<td style="padding-right:12px"><img src="cid:` + mailLogoCID + `" width="64" alt="" style="display:block;border:0"></td>
<td style="font-size:22px;font-weight:600;color:#1f2937">{{.Name}}</td></tr></table></td></tr>
<tr><td style="padding:14px 24px;background:{{.Tint}};border-left:6px solid {{.Band}}">
<div style="font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:{{.Band}}">{{.Class}}</div>
<div style="font-size:13px;color:#4b5563;margin-top:4px">Cluster <strong style="color:#1f2937">{{.Cluster}}</strong></div>
<div style="font-size:13px;color:#4b5563;margin-top:2px">{{.Time}}</div></td></tr>
<tr><td style="padding:20px 24px 8px 24px">
<div style="font-size:17px;line-height:1.45;font-weight:600;color:#1f2937">{{.Headline}}</div>
{{if .Link}}<div style="margin-top:10px;font-size:14px"><a href="{{.Link}}" style="color:{{.Band}}">Open dnshived</a></div>{{end}}</td></tr>
{{if or .Facts .Details}}<tr><td style="padding:8px 24px 0 24px"><div style="border-top:1px solid #e5e7eb"></div></td></tr>{{end}}
{{if .Facts}}<tr><td style="padding:12px 24px"><table role="presentation" cellpadding="0" cellspacing="0" style="font-size:14px;line-height:1.6">{{range .Facts}}<tr><td valign="top" style="padding:1px 16px 1px 0;color:#6b7280;white-space:nowrap">{{.Label}}</td><td style="color:#1f2937">{{.Value}}{{if .Link}} <a href="{{.Link}}" style="color:{{$.Band}}">release notes</a>{{end}}</td></tr>{{end}}</table></td></tr>{{end}}
{{range .Details}}<tr><td style="padding:10px 24px">
{{if .Title}}<div style="font-size:14px;font-weight:600;margin-bottom:4px">{{.Title}}</div>{{end}}
<table role="presentation" cellpadding="0" cellspacing="0" style="font-size:13px;line-height:1.5">{{range .Rows}}<tr><td valign="top" style="padding:1px 12px 1px 0;color:#6b7280;white-space:nowrap">{{.Label}}</td><td style="color:#1f2937">{{.Value}}</td></tr>{{end}}</table>
</td></tr>{{end}}
<tr><td style="padding:16px 24px;border-top:1px solid #e5e7eb;font-size:12px;color:#6b7280">{{.Subject}}</td></tr>
</table></td></tr></table></body></html>
`))

// renderMailHTML lays a message out as an HTML mail: logo and name on top,
// class, cluster and exact time, the headline with the link, a separator and
// then the facts or technical details.
func renderMailHTML(m notify.Message, loc *time.Location) string {
	col := mailColours[mailLevel(m.Class)]
	v := mailView{
		Band: col[0], Tint: col[1], Name: "dnshived", Cluster: m.Cluster, Class: m.Class,
		Time: m.At.In(loc).Format("2006-01-02 15:04:05 MST"), Headline: m.Headline, Link: m.Link,
		Subject: m.Subject(), Facts: m.Facts, Details: m.Details,
	}
	var b bytes.Buffer
	if err := notifyMailTmpl.Execute(&b, v); err != nil {
		return ""
	}
	return b.String()
}

// mailLogoBase64 is the logo wrapped to 76 columns for a MIME part.
func mailLogoBase64() string {
	enc := base64.StdEncoding.EncodeToString(mailLogoPNG)
	var b strings.Builder
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc)
	return b.String()
}
