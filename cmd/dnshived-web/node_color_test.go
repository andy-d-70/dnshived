// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/discovery"
	"dnshived/internal/webauth"
)

func TestNodeDot(t *testing.T) {
	tests := []struct {
		node      NodeConfig
		label     string
		class     string
		colorVal  string
		hasColor  bool
		styleWant string
	}{
		{NodeConfig{Name: "core-1"}, "1", "d1", "#d6455d", false, ""},
		{NodeConfig{Name: "core-2"}, "2", "d2", "#2f9fd8", false, ""},
		{NodeConfig{Name: "core-3"}, "3", "d3", "#ffffff", false, ""},
		{NodeConfig{Name: "probe-lab"}, "P", "dp", "#7c3aed", false, ""},
		{NodeConfig{Name: "core-1", Color: "#FFFF00"}, "1", "d1", "#ffff00", true, "--nd:#ffff00;--nd-fg:#1b1f24"},
		{NodeConfig{Name: "core-2", Color: "#102030"}, "2", "d2", "#102030", true, "--nd:#102030;--nd-fg:#ffffff"},
		{NodeConfig{Name: "core-2", Color: "red"}, "2", "d2", "#2f9fd8", false, ""},
		{NodeConfig{Name: "core-12"}, "P", "dp", "#7c3aed", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.node.Name+tt.node.Color, func(t *testing.T) {
			if got := tt.node.DotLabel(); got != tt.label {
				t.Errorf("label %q, want %q", got, tt.label)
			}
			if got := tt.node.DotClass(); got != tt.class {
				t.Errorf("class %q, want %q", got, tt.class)
			}
			if got := tt.node.ColorValue(); got != tt.colorVal {
				t.Errorf("colour %q, want %q", got, tt.colorVal)
			}
			if tt.node.HasColor() != tt.hasColor {
				t.Errorf("has colour = %v", tt.node.HasColor())
			}
			if got := string(tt.node.DotStyle()); got != tt.styleWant {
				t.Errorf("style %q, want %q", got, tt.styleWant)
			}
		})
	}
}

func TestValidNodeColor(t *testing.T) {
	for _, ok := range []string{"#000000", "#ABCDEF", "#09afAF"} {
		if !validNodeColor(ok) {
			t.Errorf("%q must be valid", ok)
		}
	}
	for _, bad := range []string{"", "red", "#fff", "#12345g", "#1234567", "000000", "#000000;background:url(x)", "\" onload=\""} {
		if validNodeColor(bad) {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestApplyNodeAppearance_ColourOnlyWhenGiven(t *testing.T) {
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: "10.0.0.1:9443", Color: "#112233"}}, ProbeHosts: []NodeConfig{{Name: "p", Addr: "10.0.0.9:9444"}}}
	if !applyNodeAppearance(cfg, "10.0.0.1:9443", "Main", nil) || cfg.Nodes[0].Color != "#112233" || cfg.Nodes[0].DisplayName != "Main" {
		t.Fatalf("a rename without a colour keeps it: %+v", cfg.Nodes[0])
	}
	blue := "#0000ff"
	applyNodeAppearance(cfg, "10.0.0.1:9443", "Main", &blue)
	if cfg.Nodes[0].Color != "#0000ff" {
		t.Errorf("colour not set: %+v", cfg.Nodes[0])
	}
	empty := ""
	applyNodeAppearance(cfg, "10.0.0.1:9443", "Main", &empty)
	if cfg.Nodes[0].Color != "" {
		t.Errorf("colour not cleared: %+v", cfg.Nodes[0])
	}
	applyNodeAppearance(cfg, "10.0.0.9:9444", "", &blue)
	if cfg.ProbeHosts[0].Color != "#0000ff" {
		t.Errorf("probe host colour not set: %+v", cfg.ProbeHosts[0])
	}
}

func renamePost(t *testing.T, ref *configRef, cfgPath string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/nodes/rename", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(context.WithValue(req.Context(), userContextKey{}, webauth.User{Name: "tester"}))
	rec := httptest.NewRecorder()
	renameNodeFormHandler(cfgPath, ref)(rec, req)
	return rec
}

func TestRenameNodeFormHandler_Colour(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "web.json")
	ref := newConfigRef(&WebConfig{ListenAddr: "127.0.0.1:0", Nodes: []NodeConfig{{Name: "core-1", Addr: "127.0.0.1:1"}}})

	if rec := renamePost(t, ref, cfgPath, url.Values{"addr": {"127.0.0.1:1"}, "display_name": {"a"}, "color": {"#aabbcc"}}); rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if got := ref.Load().Nodes[0].Color; got != "#aabbcc" {
		t.Fatalf("colour = %q", got)
	}
	renamePost(t, ref, cfgPath, url.Values{"addr": {"127.0.0.1:1"}, "display_name": {"b"}})
	if got := ref.Load().Nodes[0].Color; got != "#aabbcc" {
		t.Errorf("an old-style form without a colour must keep it, got %q", got)
	}
	rec := renamePost(t, ref, cfgPath, url.Values{"addr": {"127.0.0.1:1"}, "display_name": {"b"}, "color": {"javascript:x"}})
	if !strings.Contains(rec.Body.String(), "#rrggbb") || ref.Load().Nodes[0].Color != "#aabbcc" {
		t.Errorf("an invalid colour is refused and changes nothing: %s", rec.Body)
	}
	renamePost(t, ref, cfgPath, url.Values{"addr": {"127.0.0.1:1"}, "display_name": {"b"}, "color_default": {"1"}, "color": {"#000000"}})
	if got := ref.Load().Nodes[0].Color; got != "" {
		t.Errorf("default colour must clear it, got %q", got)
	}
}

func TestRenameNodeFormHandler_SelfTargetSetsSelfColor(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "web.json")
	ref := newConfigRef(&WebConfig{ListenAddr: "127.0.0.1:0", Nodes: []NodeConfig{{Name: "core-2", Addr: "127.0.0.1:1"}}})
	renamePost(t, ref, cfgPath, url.Values{"addr": {"127.0.0.1:9443"}, "display_name": {"me"}, "color": {"#123456"}})
	if got := ref.Load().SelfColor; got != "#123456" {
		t.Errorf("SelfColor = %q", got)
	}
}

func TestApplyRenameHandler_ColourAndOlderSenders(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "web.json")
	ref := newConfigRef(&WebConfig{ListenAddr: "127.0.0.1:0", SelfAdminToken: "tok", Nodes: []NodeConfig{{Name: "core-1", Addr: "10.0.0.1:9443", Color: "#112233"}}})
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/internal/nodes/rename", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		applyRenameHandler(cfgPath, ref)(rec, req)
		return rec
	}
	if rec := post(`{"addr":"10.0.0.1:9443","display_name":"x"}`); rec.Code != http.StatusOK || ref.Load().Nodes[0].Color != "#112233" {
		t.Fatalf("a sibling that sends no colour must leave it: %d %+v", rec.Code, ref.Load().Nodes[0])
	}
	if rec := post(`{"addr":"10.0.0.1:9443","display_name":"x","color":"#445566"}`); rec.Code != http.StatusOK || ref.Load().Nodes[0].Color != "#445566" {
		t.Fatalf("%d %+v", rec.Code, ref.Load().Nodes[0])
	}
	if rec := post(`{"addr":"10.0.0.1:9443","display_name":"x","color":""}`); rec.Code != http.StatusOK || ref.Load().Nodes[0].Color != "" {
		t.Fatalf("an empty colour resets it: %d %+v", rec.Code, ref.Load().Nodes[0])
	}
	if rec := post(`{"addr":"10.0.0.1:9443","display_name":"x","color":"red"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("an invalid colour is refused: %d", rec.Code)
	}
}

func TestConfigForm_NodesTableHasTheMenuAndTheDot(t *testing.T) {
	data := clusterFormData{AllNodes: []NodeConfig{{Name: "core-1", Addr: "10.0.0.1:9443", Color: "#ff0000"}, {Name: "core-3", Addr: "10.0.0.3:9443"}}}
	var b strings.Builder
	if err := configFormTmpl.Execute(&b, data); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	for _, want := range []string{`class="ndot d1" style="--nd:#ff0000;--nd-fg:#ffffff"`, `class="ndot d3">3</span>`, `class="node-edit"`, `href="/logs?node=core-1"`, `Offboard…`, `id="node-dialog"`} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(page, `<th>Rename</th>`) || strings.Contains(page, `<th>Offboard</th>`) {
		t.Error("the old Rename and Offboard columns must be gone")
	}
	if strings.Contains(page, "Replace…</a>") {
		t.Error("Replace is offered only while a discovered node exists")
	}
	data.Discovered = []discovery.Candidate{{Hostname: "new-host", Addr: "10.0.0.8"}}
	b.Reset()
	if err := configFormTmpl.Execute(&b, data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `href="#discovered"`) {
		t.Error("Replace is missing although a node was discovered")
	}
}
