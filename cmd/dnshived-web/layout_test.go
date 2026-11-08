// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"math"
	"regexp"
	"strconv"
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
	if !strings.Contains(navHTML, `<a href="/" class="nav-item brand"`) {
		t.Errorf("expected the brand itself to be a real link to \"/\", got:\n%s", navHTML)
	}
	if !strings.Contains(navHTML, `title="overview of the whole cluster"`) {
		t.Error("expected the brand to carry an overview tooltip, since it is the only way to the overview")
	}
	if strings.Count(navHTML, `href="/"`) != 1 {
		t.Errorf("expected exactly one link to \"/\" (the brand) now that the separate overview link is gone, got %d", strings.Count(navHTML, `href="/"`))
	}
}

// TestNavHTML_EveryItemHasANameAndATooltip guards the one-row nav: every
// item has a name and explains itself in a tooltip instead of a second line.
func TestNavHTML_EveryItemHasANameAndATooltip(t *testing.T) {
	items := regexp.MustCompile(`<a [^>]*class="nav-item[^>]*>`).FindAllString(navHTML, -1)
	if len(items) == 0 {
		t.Fatal("expected at least one .nav-item")
	}
	for _, it := range items {
		if !strings.Contains(it, `title="`) {
			t.Errorf("nav item without a tooltip: %s", it)
		}
		if !strings.Contains(it, `data-match="`) {
			t.Errorf("nav item without data-match, it can never be highlighted: %s", it)
		}
	}
	if strings.Contains(navHTML, "nav-desc") {
		t.Error("the second description line is gone; the text belongs in the tooltip")
	}
}

func TestNavHTML_ItemsAreInTheAgreedOrder(t *testing.T) {
	order := []string{`href="/"`, `href="/scopes"`, `href="/probes"`, `nav-sep`, `href="/config/dns"`, `href="/security"`, `href="/backup"`, `href="/config"`, `href="/logs"`}
	last := -1
	for _, want := range order {
		idx := strings.Index(navHTML, want)
		if idx == -1 {
			t.Fatalf("navHTML has no %s", want)
		}
		if idx < last {
			t.Errorf("%s is out of order in the nav", want)
		}
		last = idx
	}
	for _, label := range []string{"Scopes", "Probes", "DHCP &amp; DNS", "Security", "Maintenance", "Cluster settings", "Logs"} {
		if !strings.Contains(navHTML, `<span class="nav-name">`+label+`</span>`) {
			t.Errorf("navHTML has no item named %q", label)
		}
	}
}

func TestNavHTML_FoldsIntoAMenuButtonOnNarrowScreens(t *testing.T) {
	if !strings.Contains(navHTML, `id="nav-menu-toggle"`) || !strings.Contains(navHTML, `aria-expanded="false"`) {
		t.Error("expected a Menu toggle button with aria-expanded")
	}
	if !strings.Contains(navHTML, "function dnshivedToggleNav()") {
		t.Error("expected the toggle script")
	}
	if !strings.Contains(styleHTML, "@media (max-width:1180px)") || !strings.Contains(styleHTML, "nav .nav-item:not(.brand)") {
		t.Error("expected the narrow-screen rule that hides the items except the brand")
	}
}

func TestNavHTML_CurrentPageIsHighlightedByLongestPrefix(t *testing.T) {
	if !strings.Contains(navHTML, "aria-current") || !strings.Contains(navHTML, "bestLen") {
		t.Error("expected the script that marks the item with the longest matching prefix")
	}
	if !strings.Contains(styleHTML, ".nav-outer .nav-item[aria-current=page]{") {
		t.Error("expected a style for the current item")
	}
	for path, want := range map[string]string{"/config/dns": `data-match="/config/dns,`, "/config": `data-match="/config"`, "/config/mail": "/config/mail", "/config/scopes": "/config/scopes"} {
		if !strings.Contains(navHTML, want) {
			t.Errorf("no nav item claims %s (%s)", path, want)
		}
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

func TestNavHTML_ThemeSwitcherSitsRightOfTheNavAndPendingButton(t *testing.T) {
	navClose := strings.Index(navHTML, "</nav>")
	selectIdx := strings.Index(navHTML, `id="theme_switcher"`)
	pendingIdx := strings.Index(navHTML, `href="/pending"`)
	if navClose == -1 || selectIdx == -1 || pendingIdx == -1 {
		t.Fatalf("expected </nav>, the theme switcher, and the pending link all in navHTML, got:\n%s", navHTML)
	}
	if !(navClose < pendingIdx && pendingIdx < selectIdx) {
		t.Errorf("expected order </nav> -> pending button -> theme switcher, got navHTML:\n%s", navHTML)
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

func themeTokens(t *testing.T) map[string]map[string]string {
	t.Helper()
	blocks := regexp.MustCompile(`(?s):root(?:\[data-theme="(\w+)"\])?\{(.*?)\}`).FindAllStringSubmatch(styleHTML, -1)
	decl := regexp.MustCompile(`(--[a-z0-9-]+):([^;]+);`)
	out := map[string]map[string]string{"normal": {}}
	for _, b := range blocks {
		name := b[1]
		if name == "" {
			name = "normal"
		}
		if out[name] == nil {
			out[name] = map[string]string{}
			for k, v := range out["normal"] {
				out[name][k] = v
			}
		}
		for _, d := range decl.FindAllStringSubmatch(b[2], -1) {
			out[name][d[1]] = strings.TrimSpace(d[2])
		}
	}
	return out
}

func relLuminance(t *testing.T, hex string) float64 {
	t.Helper()
	h := strings.TrimPrefix(hex, "#")
	if len(h) == 3 {
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	}
	if len(h) != 6 {
		t.Fatalf("colour %q is not #rgb or #rrggbb", hex)
	}
	var ch [3]float64
	for i := range ch {
		v, err := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
		if err != nil {
			t.Fatalf("colour %q: %v", hex, err)
		}
		c := float64(v) / 255
		if c <= 0.03928 {
			ch[i] = c / 12.92
		} else {
			ch[i] = math.Pow((c+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*ch[0] + 0.7152*ch[1] + 0.0722*ch[2]
}

func contrastRatio(t *testing.T, fg, bg string) float64 {
	t.Helper()
	a, b := relLuminance(t, fg), relLuminance(t, bg)
	if a < b {
		a, b = b, a
	}
	return (a + 0.05) / (b + 0.05)
}

func TestStyleHTML_TextAndBackgroundPairsReachContrast45InEveryTheme(t *testing.T) {
	pairs := []struct{ fg, bg string }{
		{"--text", "--bg"}, {"--text", "--panel"}, {"--text", "--head"},
		{"--muted", "--bg"}, {"--muted", "--panel"}, {"--muted", "--head"},
		{"--accent", "--bg"}, {"--accent", "--panel"},
		{"--ok", "--bg"}, {"--ok", "--panel"}, {"--ok", "--head"},
		{"--warn", "--bg"}, {"--warn", "--panel"}, {"--warn", "--head"},
		{"--crit", "--bg"}, {"--crit", "--panel"}, {"--crit", "--head"},
		{"--on-accent", "--accent"}, {"--on-ok", "--ok"}, {"--on-warn", "--warn"}, {"--on-crit", "--crit"},
		{"--core-1", "--panel"}, {"--core-2", "--panel"}, {"--core-3", "--panel"}, {"--worker-probe", "--panel"},
	}
	tokens := themeTokens(t)
	if len(tokens) != 3 {
		t.Fatalf("want 3 themes, found %d", len(tokens))
	}
	for theme, tok := range tokens {
		for _, p := range pairs {
			fg, bg := tok[p.fg], tok[p.bg]
			if fg == "" || bg == "" {
				t.Errorf("%s: %s or %s is not defined", theme, p.fg, p.bg)
				continue
			}
			if r := contrastRatio(t, fg, bg); r < 4.5 {
				t.Errorf("%s: %s %s on %s %s has contrast %.2f, want at least 4.5", theme, p.fg, fg, p.bg, bg, r)
			}
		}
	}
}

func TestStyleHTML_NoHardCodedWhiteTextOnTokenBackgrounds(t *testing.T) {
	if strings.Contains(styleHTML, "color:#fff") {
		t.Error("text on filled elements must use the --on-* tokens, not #fff")
	}
}

func TestStyleHTML_PendingButtonColourBeatsTheGenericNavItemColour(t *testing.T) {
	if !strings.Contains(styleHTML, ".nav-outer .nav-pending-btn{") {
		t.Error("the pending button colour rule must be as specific as `.nav-outer .nav-item`, or the text stays dark on the blue button")
	}
}

func TestStyleHTML_TabsAndLineListsAreDefined(t *testing.T) {
	for _, want := range []string{"function dnshivedInitTabs()", "function dnshivedLineLists()", ".tab-host.tabs-ready .tab-pane{display:none}", ".line-list{", "textarea[data-line-list]"} {
		if !strings.Contains(navHTML+styleHTML, want) {
			t.Errorf("layout lacks %q", want)
		}
	}
	if !strings.Contains(navHTML, "'invalid'") {
		t.Error("an invalid field in a hidden tab must open that tab, or the form cannot be submitted")
	}
}

func TestTabLinksHTML_MarksOnlyTheActivePage(t *testing.T) {
	out := securityTabs("/security")
	if strings.Count(out, `aria-current="page"`) != 1 || !strings.Contains(out, `href="/security" aria-current="page"`) {
		t.Errorf("exactly the active tab must carry aria-current: %s", out)
	}
	for _, href := range []string{"/users", "/security", "/config/mail"} {
		if !strings.Contains(out, `href="`+href+`"`) {
			t.Errorf("security tabs lack %s", href)
		}
	}
}

func TestPageTemplates_UseTheTabLayout(t *testing.T) {
	cases := []struct {
		name string
		tmpl string
		want []string
	}{
		{"maintenance", backupTmpl.Tree.Root.String(), []string{`id="tab-backup"`, `id="tab-restore"`, `id="tab-export"`}},
		{"cluster settings", configFormTmpl.Tree.Root.String(), []string{`id="tab-nodes"`, `id="tab-interfaces"`, `id="tab-addresses"`, `id="tab-misc"`, `class="tab-submit"`}},
		{"dhcp and dns", dhcpDNSConfigFormTmpl.Tree.Root.String(), []string{`id="tab-dhcp"`, `id="tab-dns"`, `id="tab-templates"`, `id="tab-domains"`, `data-line-list`}},
		{"logs", logsTmpl.Tree.Root.String(), []string{`id="tab-general"`, `id="tab-audit"`, `id="daemons"`, `data-extra-tabs`}},
	}
	for _, c := range cases {
		for _, want := range c.want {
			if !strings.Contains(c.tmpl, want) {
				t.Errorf("%s page lacks %s", c.name, want)
			}
		}
		if !strings.Contains(c.tmpl, `class="tab-host`) {
			t.Errorf("%s page has no tab host", c.name)
		}
	}
}

func TestSecurityTabs_TheMenuLandsOnTheFirstTab(t *testing.T) {
	out := securityTabs("/security")
	first := strings.Index(out, `href="`)
	if first == -1 || !strings.HasPrefix(out[first:], `href="/security"`) {
		t.Errorf("the first tab must be the page the Security menu item opens (/security): %s", out)
	}
	menuHref := regexp.MustCompile(`<a href="([^"]+)"[^>]*data-match="/security,`).FindStringSubmatch(navHTML)
	if menuHref == nil || menuHref[1] != "/security" {
		t.Errorf("the Security menu item must open /security, got %v", menuHref)
	}
}

func TestStyleHTML_ThemeButtonHasAFixedWidth(t *testing.T) {
	if !strings.Contains(styleHTML, "#theme_switcher{width:5.6rem;text-align:center}") {
		t.Error("the theme button's label changes (Normal, Glowing, Dark); without a fixed width the nav items beside it jump")
	}
}
