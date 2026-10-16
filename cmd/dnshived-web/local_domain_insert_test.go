// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"regexp"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestLocalDomainInsertHTML_ArgumentStaysInsideOnclick(t *testing.T) {
	d := config.LocalDomain{Name: "office.lan", Records: []config.LocalDomainHost{
		{Host: "printer", Type: "A", Value: "10.1.50.20"},
		{Host: "note", Type: "TXT", Value: `say "hi" onmouseover=alert(1)`},
	}}
	out := string(localDomainInsertHTML("tpl_body", []config.LocalDomain{d}))
	m := regexp.MustCompile(`<button type="button" onclick="([^"]*)">`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("button with a closed onclick attribute not found in:\n%s", out)
	}
	if !strings.HasPrefix(m[1], "domainInsert_tpl_body(&#34;") || !strings.HasSuffix(m[1], "&#34;)") {
		t.Errorf("onclick = %q, want the whole JSON argument inside the attribute", m[1])
	}
	if strings.Contains(out, "onmouseover=alert") && !strings.Contains(m[1], "onmouseover=alert") {
		t.Error("record text escaped the onclick attribute")
	}
}
