// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"strings"
	"testing"
)

func TestNavHTML_PendingChangesIsAHighlightedButtonRightOfLogs(t *testing.T) {
	logsIdx := strings.Index(navHTML, `href="/logs"`)
	pendingIdx := strings.Index(navHTML, `href="/pending"`)
	if logsIdx == -1 || pendingIdx == -1 {
		t.Fatalf("expected both /logs and /pending links in navHTML, got:\n%s", navHTML)
	}
	if pendingIdx < logsIdx {
		t.Errorf("pending changes must come after logs (rightmost regular tab), got navHTML:\n%s", navHTML)
	}
	if !strings.Contains(navHTML, `class="nav-item nav-pending-btn"`) {
		t.Error("expected pending changes to carry the distinct highlighted-button class, not just a plain nav-item")
	}
	if !strings.Contains(navHTML, `id="pending-marker"`) {
		t.Error("expected a #pending-marker element in navHTML")
	}
	if !strings.Contains(navHTML, `style="display:none`) {
		t.Error("expected the pending marker to start hidden (display:none) in static markup")
	}
	if strings.Contains(navHTML, `class="warn"`) {
		t.Error("navHTML must never hardcode class=\"warn\" in static markup — only the marker's own client-side fetch may add it, once a real pending change is confirmed")
	}
	if !strings.Contains(navHTML, "/api/pending-summary") {
		t.Error("expected the marker's own client-side fetch to call /api/pending-summary")
	}
}

func TestNavHTML_PendingButtonSitsOutsideTheNavFrame(t *testing.T) {
	navClose := strings.Index(navHTML, "</nav>")
	pendingIdx := strings.Index(navHTML, `href="/pending"`)
	if navClose == -1 || pendingIdx == -1 {
		t.Fatalf("expected both </nav> and the pending link in navHTML, got:\n%s", navHTML)
	}
	if pendingIdx < navClose {
		t.Errorf("expected the pending button to appear AFTER </nav> (a sibling, not a child inside nav's own frame), got navHTML:\n%s", navHTML)
	}
	if !strings.Contains(navHTML, `<div class="nav-outer">`) {
		t.Error("expected a .nav-outer wrapper containing both nav and the pending button")
	}
}

func TestStyleHTML_BrandDescLinesUpUnderBrandText(t *testing.T) {
	if !strings.Contains(styleHTML, "nav .brand .nav-desc{margin-left:") {
		t.Error("expected nav .brand .nav-desc to have a left margin offsetting the brand icon's own width, so \"overview\" lines up under \"dnshived\" rather than sitting flush left")
	}
}

func TestNavHTML_NeverScrollsHorizontally(t *testing.T) {
	if strings.Contains(styleHTML, "overflow-x:auto") && strings.Contains(styleHTML, "nav{") {
		idx := strings.Index(styleHTML, "nav{")
		end := strings.Index(styleHTML[idx:], "}")
		navRule := styleHTML[idx : idx+end]
		if strings.Contains(navRule, "overflow-x:auto") || strings.Contains(navRule, "flex-wrap:nowrap") {
			t.Errorf("expected nav's own CSS rule to wrap instead of scroll, got:\n%s", navRule)
		}
		if !strings.Contains(navRule, "flex-wrap:wrap") {
			t.Errorf("expected nav's own CSS rule to set flex-wrap:wrap, got:\n%s", navRule)
		}
	}
}

func TestStyleHTML_BrandLogoMatchesTextHeight(t *testing.T) {
	if !strings.Contains(styleHTML, "nav .brand svg.brand-mark{display:block;width:1.5em;height:1.5em}") {
		t.Errorf("expected the brand icon sized to 1.5em (compensating for its own artwork's internal margin), got styleHTML without it")
	}
	if strings.Contains(navHTML, `width="18"`) || strings.Contains(navHTML, `height="18"`) {
		t.Error("expected no fixed-pixel width/height attributes on the brand mark")
	}
}

func TestNavHTML_BrandMarkIsInlineSVGNotImg(t *testing.T) {
	if strings.Contains(navHTML, `<img src="/favicon.svg"`) {
		t.Error("expected the topnav brand mark to no longer be an external <img>, which can't see the page's own data-theme")
	}
	if !strings.Contains(navHTML, `<svg class="brand-mark"`) {
		t.Errorf("expected an inline <svg class=\"brand-mark\"> in navHTML, got:\n%s", navHTML)
	}
	for _, class := range []string{"nd", "ring-dim", "auth"} {
		if !strings.Contains(styleHTML, "nav .brand svg.brand-mark ."+class+"{") {
			t.Errorf("expected styleHTML to color the brand mark's .%s via a page CSS token, got none", class)
		}
	}
	if strings.Contains(navBrandMarkSVG, "#") {
		t.Error("expected the inline brand mark to carry zero hardcoded colors — everything themed via CSS var() in styleHTML")
	}
}

func TestNavHTML_BrandIsNowTheOverviewLink(t *testing.T) {
	if !strings.Contains(navHTML, `<a href="/" class="nav-item brand">`) {
		t.Errorf("expected the brand itself to be a real link to \"/\", got:\n%s", navHTML)
	}
	if !strings.Contains(navHTML, `<span class="nav-desc">overview</span>`) {
		t.Error("expected the brand's second line to read \"overview\"")
	}
	if strings.Count(navHTML, `href="/"`) != 1 {
		t.Errorf("expected exactly one link to \"/\" (the brand) now that the separate overview link is gone, got %d", strings.Count(navHTML, `href="/"`))
	}
}

// TestNavHTML_EveryItemHasATwoLineNameAndDescription guards the two-line
// redesign holding for every nav item, not just the brand.
func TestNavHTML_EveryItemHasATwoLineNameAndDescription(t *testing.T) {
	items := strings.Count(navHTML, `class="nav-item`)
	names := strings.Count(navHTML, `class="nav-name"`)
	descs := strings.Count(navHTML, `class="nav-desc"`)
	if items == 0 {
		t.Fatal("expected at least one .nav-item")
	}
	if names != items || descs != items {
		t.Errorf("expected one .nav-name and one .nav-desc per .nav-item (%d items), got %d names, %d descs", items, names, descs)
	}
}

// TestNavHTML_TopologyAndDaemonsAreNoLongerTopLevelTabs pins the nav
// moves.
func TestNavHTML_TopologyAndDaemonsAreNoLongerTopLevelTabs(t *testing.T) {
	if strings.Contains(navHTML, `href="/topology"`) {
		t.Error("expected /topology to no longer be a top-level nav tab")
	}
	if strings.Contains(navHTML, `href="/daemons"`) {
		t.Error("expected /daemons to no longer be a top-level nav tab")
	}
}

func TestStyleHTML_DefinesAllThreeThemes(t *testing.T) {
	if !strings.Contains(styleHTML, `:root{`) {
		t.Error("expected a bare :root block (the normal/default theme)")
	}
	if !strings.Contains(styleHTML, `:root[data-theme="glowing"]{`) {
		t.Error("expected a :root[data-theme=\"glowing\"] override block")
	}
	if !strings.Contains(styleHTML, `:root[data-theme="dark"]{`) {
		t.Error("expected a :root[data-theme=\"dark\"] override block")
	}
	scriptIdx := strings.Index(styleHTML, "<script>")
	styleIdx := strings.Index(styleHTML, "<style>")
	if scriptIdx == -1 || styleIdx == -1 || scriptIdx > styleIdx {
		t.Error("expected the theme-detection <script> to run BEFORE <style> is parsed, to avoid a flash of the wrong theme")
	}
	if !strings.Contains(styleHTML, "localStorage.getItem('dnshived-theme')") {
		t.Error("expected the detection script to read the same localStorage key the switcher writes")
	}
}

func TestStyleHTML_SemanticColorsAreTokensNotLiterals(t *testing.T) {
	for _, tok := range []string{"--ok", "--warn", "--crit", "--core-1", "--core-2", "--core-3", "--worker-probe", "--tint-1", "--tint-2", "--tint-3", "--tint-crit", "--nav-h"} {
		if !strings.Contains(styleHTML, tok+":") {
			t.Errorf("expected styleHTML to define token %s", tok)
		}
	}
	for _, literal := range []string{".ok{color:#", ".warn{color:#", ".crit{color:#", ".node-core-1{color:#", ".node-core-2{color:#", ".node-core-3{color:#", ".node-probe{color:#"} {
		if strings.Contains(styleHTML, literal) {
			t.Errorf("expected %s to be gone (replaced by a var(...) reference) — a hardcoded literal here would never respond to a theme switch", literal)
		}
	}
}

func TestOtherPagesOwnCSS_UseThemeTokensNotLiterals(t *testing.T) {
	if strings.Contains(topologyStyleHTML, "#c00") || strings.Contains(topologyStyleHTML, "#06c") || strings.Contains(topologyStyleHTML, "#c0392b") || strings.Contains(topologyStyleHTML, "#fdf2f1") {
		t.Error("expected topologyStyleHTML's scope-chip colors to be var(...) tokens, not hardcoded hex literals")
	}
	if !strings.Contains(topologyStyleHTML, "var(--core-1)") || !strings.Contains(topologyStyleHTML, "var(--tint-1)") {
		t.Error("expected topologyStyleHTML's scope-chip colors to reference the shared core/tint tokens")
	}
	if strings.Contains(scopeEditorStyleHTML, "#c0392b") {
		t.Error("expected scopeEditorStyleHTML's field-invalid outline to be var(--crit), not a hardcoded literal")
	}
}

// TestNavHTML_ThemeSwitcherCyclesAllThreeOptionsAndAppliesImmediately pins
// the switcher control, now embedded directly in navHTML.
func TestNavHTML_ThemeSwitcherCyclesAllThreeOptionsAndAppliesImmediately(t *testing.T) {
	if !strings.Contains(navHTML, `<button type="button" id="theme_switcher"`) {
		t.Error("expected the theme switcher to be a single clickable button, not a <select>")
	}
	if strings.Contains(navHTML, `id="theme_switcher"`) && strings.Contains(navHTML, `<select id="theme_switcher"`) {
		t.Error("expected no leftover <select id=\"theme_switcher\">")
	}
	for _, val := range []string{"'normal'", "'glowing'", "'dark'"} {
		if !strings.Contains(navHTML, val) {
			t.Errorf("expected theme value %s present in the cycle", val)
		}
	}
	if !strings.Contains(navHTML, "document.documentElement.setAttribute('data-theme'") {
		t.Error("expected the switcher to apply immediately via document.documentElement, not a reload/server round trip")
	}
	if !strings.Contains(navHTML, "localStorage.setItem('dnshived-theme'") {
		t.Error("expected the switcher to persist its choice under the same key the detection script reads")
	}
	if !strings.Contains(navHTML, "localStorage.getItem('dnshived-theme')") {
		t.Error("expected the switcher to read back the same key on load, so a click on any page continues from wherever it left off")
	}
}

func TestNavHTML_ThemeSwitcherSitsBetweenNavAndPendingButton(t *testing.T) {
	navClose := strings.Index(navHTML, "</nav>")
	selectIdx := strings.Index(navHTML, `id="theme_switcher"`)
	pendingIdx := strings.Index(navHTML, `href="/pending"`)
	if navClose == -1 || selectIdx == -1 || pendingIdx == -1 {
		t.Fatalf("expected </nav>, the theme switcher, and the pending link all in navHTML, got:\n%s", navHTML)
	}
	if !(navClose < selectIdx && selectIdx < pendingIdx) {
		t.Errorf("expected order </nav> -> theme switcher -> pending button, got navHTML:\n%s", navHTML)
	}
}

func TestNavHTML_IncludesComboboxWidget(t *testing.T) {
	for _, want := range []string{
		"function dnshivedInitCombos",
		"select.js-combo",
		"document.addEventListener('DOMContentLoaded', dnshivedInitCombos)",
	} {
		if !strings.Contains(navHTML, want) {
			t.Errorf("expected navHTML to contain %q", want)
		}
	}
}

func TestStyleHTML_NavOuterCentersItsChildrenVertically(t *testing.T) {
	if !strings.Contains(styleHTML, ".nav-outer{display:flex;align-items:center;") {
		t.Errorf("expected .nav-outer to center its children vertically, styleHTML=%s", styleHTML)
	}
}

func TestStyleHTML_DefinesLogModalCSS(t *testing.T) {
	if !strings.Contains(styleHTML, "dialog#log-modal{") {
		t.Error("expected dialog#log-modal to be styled")
	}
	if !strings.Contains(styleHTML, "dialog#log-modal::backdrop{") {
		t.Error("expected a styled backdrop for the log modal")
	}
	if !strings.Contains(styleHTML, "max-height:80vh") {
		t.Error("expected the modal to stay bounded, not fullscreen")
	}
	if !strings.Contains(styleHTML, "white-space:pre-wrap") {
		t.Error("expected the modal's <pre> to wrap long lines (white-space:pre-wrap), not force horizontal scrolling")
	}
}

func TestStyleHTML_DefinesPathsModalAndTrustBarCSS(t *testing.T) {
	if !strings.Contains(styleHTML, "dialog#paths-modal{") {
		t.Error("expected dialog#paths-modal to be styled")
	}
	if !strings.Contains(styleHTML, "dialog#paths-modal::backdrop{") {
		t.Error("expected a styled backdrop for the paths modal")
	}
	if !strings.Contains(styleHTML, ".trust-bar{") || !strings.Contains(styleHTML, ".trust-bar-fill{") {
		t.Error("expected the trust-index bar to be styled")
	}
}

// TestStyleHTML_DefinesComboboxCSS confirms the combobox's own overlay
// styling exists and is theme-aware (tokens, not literal colors).
func TestStyleHTML_DefinesComboboxCSS(t *testing.T) {
	for _, want := range []string{".combo{", ".combo-input{", ".combo-list{", ".combo-item{"} {
		if !strings.Contains(styleHTML, want) {
			t.Errorf("expected styleHTML to define %q", want)
		}
	}
	if !strings.Contains(styleHTML, "position:absolute") {
		t.Error("expected the combobox list to be an absolute-positioned overlay, not something that reflows layout")
	}
}

func TestStyleHTML_DefinesInfoIcoCSS(t *testing.T) {
	if !strings.Contains(styleHTML, ".info-ico{") {
		t.Error("expected .info-ico to be styled")
	}
	if !strings.Contains(styleHTML, "cursor:help") {
		t.Error("expected the info icon to use cursor:help, signaling it's not a link/button")
	}
}
