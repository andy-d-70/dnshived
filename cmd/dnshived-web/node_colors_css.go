// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"net/http"
	"strings"
)

// nodeColorsCSS turns the custom node colours into rules for the role
// classes every page already uses. Only colours that pass validNodeColor
// are written.
func nodeColorsCSS(cfg *WebConfig) string {
	var b strings.Builder
	rule := func(sel, color string) {
		fmt.Fprintf(&b, "%s{--nd:%s;--nd-fg:%s;--ns:%s}\n", sel, strings.ToLower(color), dotTextColor(color), strings.ToLower(color))
	}
	for _, n := range nodesIncludingSelf(cfg) {
		if !validNodeColor(n.Color) {
			continue
		}
		switch n.Name {
		case "core-1", "core-2", "core-3":
			num := n.Name[len("core-"):]
			rule(".node-"+n.Name, n.Color)
			fmt.Fprintf(&b, ".scope-chip.serve-%s{border-left-color:%s;background:color-mix(in srgb,%s 12%%,var(--panel))}\n", num, strings.ToLower(n.Color), strings.ToLower(n.Color))
		}
	}
	for _, p := range cfg.ProbeHosts {
		if validNodeColor(p.Color) {
			rule(".node-probe", p.Color)
			break
		}
	}
	return b.String()
}

// handleNodeColorsCSS serves GET /node-colors.css, linked from every page.
func handleNodeColorsCSS(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "private, max-age=15")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprint(w, nodeColorsCSS(ref.Load()))
	}
}
