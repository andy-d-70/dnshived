// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func nonTestSources(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out[f] = string(b)
	}
	return out
}

func TestNoPageReloadsItself(t *testing.T) {
	for f, src := range nonTestSources(t) {
		if strings.Contains(strings.ToLower(src), `http-equiv="refresh"`) {
			t.Errorf("%s: a page must never reload itself, it wipes whatever is being typed; refresh the changing part in place", f)
		}
	}
	if n := strings.Count(navHTML+logModalScriptHTML, "location.reload()"); n != 1 {
		t.Errorf("location.reload() appears %d times in the shared script, want 1 (only inside dnshivedReloadUnlessEdited)", n)
	}
}

func TestProbesPage_ResultsRefreshInPlace(t *testing.T) {
	var b strings.Builder
	if err := probesTmpl.Execute(&b, probesPageData{ProbeHostNames: []string{"probe"}, Page: 2, TotalPages: 3, UpdatedAt: "12:00:00", Total: 1}); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	for _, want := range []string{`id="probe-results"`, `data-page="2"`, "fragment=results", "X-Probe-Fragment", "Updated 12:00:00", "refreshes every 20s while this tab is open"} {
		if !strings.Contains(page, want) {
			t.Errorf("probes page lacks %q", want)
		}
	}
	b.Reset()
	if err := probesTmpl.ExecuteTemplate(&b, "probe-results-body", probesPageData{ProbeHostNames: []string{"probe"}, Page: 1, TotalPages: 1, UpdatedAt: "12:00:01"}); err != nil {
		t.Fatal(err)
	}
	frag := b.String()
	if !strings.Contains(frag, "Updated 12:00:01") || !strings.Contains(frag, "<table") {
		t.Errorf("fragment lacks the table or the update time: %q", frag)
	}
	for _, not := range []string{"<nav", "<!doctype", "tab-pane", "<script"} {
		if strings.Contains(frag, not) {
			t.Errorf("the fragment must be the results only, found %q", not)
		}
	}
}

func TestProbesLinksPointAtExistingTabs(t *testing.T) {
	var b strings.Builder
	if err := probesTmpl.Execute(&b, probesPageData{ProbeHostNames: []string{"probe"}, Page: 1, TotalPages: 1}); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	re := regexp.MustCompile(`/probes#([a-z-]+)`)
	seen := 0
	for f, src := range nonTestSources(t) {
		for _, m := range re.FindAllStringSubmatch(src, -1) {
			seen++
			if m[1] == "settings" {
				t.Errorf("%s links to /probes#settings, which is the Probe hosts heading, not a tab; use #tab-hosts or #tab-behavior", f)
				continue
			}
			if !strings.Contains(page, `id="`+m[1]+`"`) {
				t.Errorf("%s links to /probes#%s but the probes page has no such id", f, m[1])
			}
		}
	}
	if seen < 4 {
		t.Errorf("found only %d /probes#... links, the scan is broken", seen)
	}
	for _, want := range []struct{ file, text string }{
		{"probes.go", `"/probes#tab-behavior", "back to probes"`},
		{"config_dhcp_dns_form.go", `<a href="/probes#tab-behavior">DNS probe checks</a>`},
	} {
		if !strings.Contains(nonTestSources(t)[want.file], want.text) {
			t.Errorf("%s lacks %q", want.file, want.text)
		}
	}
}

func TestTabsRememberTheOpenTabAcrossReloads(t *testing.T) {
	for _, want := range []string{"sessionStorage.setItem(tabKey", "sessionStorage.getItem(tabKey)", "nav.type==='reload'", "nav.type==='back_forward'"} {
		if !strings.Contains(navHTML, want) {
			t.Errorf("layout script lacks %q", want)
		}
	}
	if !strings.Contains(navHTML, `id="pending-marker"`) || !strings.Contains(navHTML, `style="visibility:hidden;margin-left:.3rem"`) || strings.Contains(navHTML, "m.style.display") {
		t.Error("the pending marker must keep its width: toggle visibility, never display")
	}
	for _, want := range []string{"function dnshivedReloadUnlessEdited(form)", "Reload anyway?", "dnshivedReloadUnlessEdited(form); }, {once:true}"} {
		if !strings.Contains(logModalScriptHTML, want) {
			t.Errorf("layout script lacks %q", want)
		}
	}
}
