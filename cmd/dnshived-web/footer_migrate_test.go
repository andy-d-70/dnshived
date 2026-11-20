// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The footer script's validate() must keep an arrangement saved before the
// optional fields existed, and show none of them until the user adds them.
func TestFooterLayoutScript_MigratesAnOlderSavedArrangement(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	s := footerLayoutScriptHTML
	body := s[strings.Index(s, "<script>")+8 : strings.LastIndex(s, "</script>")]
	js := `
var document={getElementById:function(){return null}};var window={};var localStorage={};
` + body + `
var v=window.dnshivedFooter.validate;
var old={order:['title','upd','state','nodes','dhcp','rev','ev'],off:['dhcp'],w:{nodes:20}};
var r=v(old);
var out={order:r.order,off:r.off,w:r.w,fresh:v(null).off,junk:v({order:['x'],off:['y','clock']}).off};
console.log(JSON.stringify(out));
`
	f := t.TempDir() + "/m.js"
	if err := os.WriteFile(f, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, f).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	got := string(out)
	for _, want := range []string{
		`"order":["title","upd","state","nodes","dhcp","rev","ev","load","nload","uptime","clock","date"]`,
		`"off":["load","nload","uptime","clock","date","dhcp"]`,
		`"w":{"nodes":20}`,
		`"fresh":["load","nload","uptime","clock","date"]`,
		`"junk":["load","nload","uptime","clock","date"]`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
}
