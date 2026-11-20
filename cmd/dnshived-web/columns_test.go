// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"strings"
	"testing"
)

func TestNavHTML_CarriesTheColumnResizer(t *testing.T) {
	for _, want := range []string{"dnshived-cols|", "table.list-table", "col-grip", "cols-reset", "window.dnshivedCols"} {
		if !strings.Contains(navHTML, want) {
			t.Errorf("navHTML lacks %q, every page with a list table needs the shared column resizer", want)
		}
	}
	if strings.Contains(columnsScriptHTML, "innerHTML") {
		t.Error("the column resizer builds its elements with the DOM API only")
	}
}

func TestStyleHTML_StylesTheColumnResizer(t *testing.T) {
	for _, want := range []string{".col-grip{", "body.col-resizing", "table.cols-custom .cols-reset{display:inline-block}", "table.cols-custom + .cols-reset-bar{display:block}"} {
		if !strings.Contains(styleHTML, want) {
			t.Errorf("styleHTML lacks %q", want)
		}
	}
}

func TestColumnsScript_KeepsItsStorageKeyAndLimits(t *testing.T) {
	for _, want := range []string{"var MIN=3", "PREFIX='dnshived-cols|'", "Math.abs(s-100)<=1.5", "getComputedStyle(t).display==='table'"} {
		if !strings.Contains(columnsScriptHTML, want) {
			t.Errorf("columns script lacks %q; saved layouts of users would silently stop working or accept bad values", want)
		}
	}
}

func TestStyleHTML_ResetButtonIsVisible(t *testing.T) {
	if !strings.Contains(styleHTML, ".cols-reset{display:none;background:var(--panel);border:1px solid var(--accent)") {
		t.Error("the reset button must stand out in every theme")
	}
}

func TestCancelLooksDifferentFromSaveAndSitsOnTheLeft(t *testing.T) {
	if !strings.Contains(styleHTML, "button.btn-cancel,a.btn-cancel{") || !strings.Contains(styleHTML, ".form-actions{display:flex;align-items:center;justify-content:flex-end;gap:1.2rem") {
		t.Error("the shared cancel style and the form-actions row are missing")
	}
	var b strings.Builder
	if err := configFormTmpl.Execute(&b, clusterFormData{AllNodes: []NodeConfig{{Name: "core-1", Addr: "10.0.0.1:9443"}}}); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	c, s := strings.Index(page, `id="nd-cancel" class="btn-cancel"`), strings.Index(page, `class="btn-primary">Save</button>`)
	if c < 0 || s < 0 || c > s {
		t.Errorf("Cancel must come before Save and carry the cancel style (cancel at %d, save at %d)", c, s)
	}
	for name, src := range map[string]string{"domain editor": domEditorTmpl.Tree.Root.String(), "reservation window": hostsTmpl.Tree.Root.String()} {
		if strings.Contains(src, `id="rec-cancel">Cancel`) || strings.Contains(src, `id="res-cancel">Cancel`) {
			t.Errorf("%s still has a Cancel button in the Save style", name)
		}
	}
}

func TestColumnsScript_CanReorderColumnsAndKeepsFixedOnesInPlace(t *testing.T) {
	for _, want := range []string{"OPREFIX='dnshived-colorder|'", "function reorder(", "function validOrder(", "movable", "data-oc", "th.col-dragging"} {
		if !strings.Contains(columnsScriptHTML+columnsStyle, want) {
			t.Errorf("column script lacks %q; saved column orders would silently stop working", want)
		}
	}
}
