// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestStatusTmpl_EveryOverviewCardIsAWidget(t *testing.T) {
	for _, id := range []string{"nodes", "scopes", "probes", "attn", "paths", "health", "events"} {
		if !strings.Contains(overviewRasterScriptHTML, "'"+id+"'") {
			t.Errorf("raster script does not know widget %q", id)
		}
	}
	if strings.Contains(overviewRasterScriptHTML, "innerHTML") {
		t.Error("the raster builds its elements with the DOM API only")
	}
}

func TestOverviewRasterScript_ValidateAndResolve(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	s := overviewRasterScriptHTML
	body := s[strings.Index(s, "<script>")+8 : strings.LastIndex(s, "</script>")]
	js := `
var document={querySelector:function(){return null}};var window={};var localStorage={};
` + body + `
var o=window.dnshivedOverview, d=o.def();
var res={};
res.defNoOverlap=(function(){var l=o.resolve(d.l,[],null);return JSON.stringify(l)===JSON.stringify(d.l);})();
var bad=o.validate({l:{nodes:{x:11,y:0,w:4,h:14},scopes:{x:'a',y:0,w:4,h:14},probes:{x:0,y:0,w:4,h:2}},off:['scopes','zzz','scopes']});
res.badKeepsDefault=JSON.stringify(bad.l.nodes)===JSON.stringify(d.l.nodes)&&JSON.stringify(bad.l.scopes)===JSON.stringify(d.l.scopes)&&JSON.stringify(bad.l.probes)===JSON.stringify(d.l.probes);
res.off=bad.off;
var l=JSON.parse(JSON.stringify(d.l)); l.paths={x:0,y:0,w:4,h:14};
var r=o.resolve(l,[],'paths');
res.movedWins=r.paths.y===0&&r.nodes.y>=14;
var any=false,ids=o.IDS;
for(var i=0;i<ids.length;i++)for(var j=i+1;j<ids.length;j++){var a=r[ids[i]],b=r[ids[j]];if(a.x<b.x+b.w&&b.x<a.x+a.w&&a.y<b.y+b.h&&b.y<a.y+a.h)any=true;}
res.noOverlap=!any;
var hidden=o.resolve(l,['nodes'],'paths');
res.hiddenFreesSpace=hidden.attn.y<=r.attn.y;
console.log(JSON.stringify(res));
`
	f := t.TempDir() + "/o.js"
	if err := os.WriteFile(f, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, f).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	got := string(out)
	for _, want := range []string{`"defNoOverlap":true`, `"badKeepsDefault":true`, `"off":["scopes"]`, `"movedWins":true`, `"noOverlap":true`, `"hiddenFreesSpace":true`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
}
