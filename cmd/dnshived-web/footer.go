// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// footerAttnMaxAge is how long the Overview's last count of warnings and alerts
// still counts for the footer; the footer itself never recomputes them.
const footerAttnMaxAge = 60 * time.Second

type footerAttn struct {
	Warnings, Alerts int
	At               time.Time
}

var footerAttnLast atomic.Pointer[footerAttn]

// noteOverviewAttention remembers what the Overview's Needs attention card shows.
func noteOverviewAttention(d *overviewData) {
	a := &footerAttn{
		Alerts:   len(d.ProbeIssues),
		Warnings: len(d.DaemonIssues) + len(d.Coherence),
		At:       time.Now(),
	}
	if d.Unreachable > 0 {
		a.Alerts++
	}
	footerAttnLast.Store(a)
}

type footerNode struct {
	Name   string `json:"name"`
	Up     bool   `json:"up"`
	Uptime string `json:"uptime,omitempty"`
	Load   string `json:"load,omitempty"`
}

type footerData struct {
	Version  string       `json:"version"`
	State    string       `json:"state"`
	Level    string       `json:"level"`
	Warnings int          `json:"warnings"`
	Alerts   int          `json:"alerts"`
	Nodes    []footerNode `json:"nodes"`
	Revision int64        `json:"revision,omitempty"`
	AgeSec   int          `json:"age_sec"`
	Event    string       `json:"event,omitempty"`
	Update   updateInfo   `json:"update"`
}

// buildFooter turns the cached cluster status rows into the footer's content.
// It reads only what the snapshot already holds.
func buildFooter(rows []statusRow, att *footerAttn, now time.Time) footerData {
	d := footerData{Version: version, Nodes: []footerNode{}}
	total, reachable, stable := len(rows), 0, 0
	var newest time.Time
	for _, row := range rows {
		if row.FetchedAt.After(newest) {
			newest = row.FetchedAt
		}
		if row.FetchError != "" {
			d.Nodes = append(d.Nodes, footerNode{Name: row.Node.displayName()})
			continue
		}
		reachable++
		if row.Status.State == "STABLE" {
			stable++
		}
		if r := row.Status.ConfigRevision; r != nil && *r > d.Revision {
			d.Revision = *r
		}
		if !isCoreRole(row.Status.Role) {
			continue
		}
		n := footerNode{Name: row.Nickname, Up: true}
		if row.HasSystem {
			n.Uptime = formatUptime(row.System.UptimeSec)
			n.Load = fmt.Sprintf("%.2f", row.System.LoadAvg1)
		}
		d.Nodes = append(d.Nodes, n)
	}
	sort.SliceStable(d.Nodes, func(i, j int) bool { return d.Nodes[i].Name < d.Nodes[j].Name })
	if !newest.IsZero() {
		if age := now.Sub(newest); age > 0 {
			d.AgeSec = int(age / time.Second)
		}
	}
	switch {
	case total == 0 || reachable == 0:
		d.State, d.Level = "NO NODES", "crit"
	case stable == total:
		d.State, d.Level = "STABLE", "ok"
	default:
		d.State, d.Level = "DEGRADED", "warn"
	}
	if total > 0 && reachable*2 <= total {
		d.Level = "crit"
	}
	if att != nil && now.Sub(att.At) <= footerAttnMaxAge {
		d.Warnings, d.Alerts = att.Warnings, att.Alerts
		if att.Alerts > 0 {
			d.Level = "crit"
		} else if att.Warnings > 0 && d.Level == "ok" {
			d.Level = "warn"
		}
	}
	return d
}

// footerEvent shortens the newest event to "HH:MM PREFIX message".
func footerEvent(rows []logRow) string {
	if len(rows) == 0 {
		return ""
	}
	r := rows[0]
	hhmm := r.Time
	if i := strings.LastIndex(hhmm, " "); i >= 0 {
		hhmm = hhmm[i+1:]
	}
	if len(hhmm) > 5 {
		hhmm = hhmm[:5]
	}
	msg := strings.TrimSpace(r.Prefix + " " + r.Message)
	if len(msg) > 120 {
		msg = msg[:120]
	}
	return hhmm + " " + msg
}

// footerCache keeps the last answer so many open tabs, or an idle UI, cost one
// computation per window instead of one per poll.
var footerCache struct {
	mu   sync.Mutex
	at   time.Time
	body []byte
}

const (
	footerCacheActive = 2 * time.Second
	footerCacheIdle   = 20 * time.Second
)

// footerInvalidate drops the cached answer, e.g. after a setting that it shows changed.
func footerInvalidate() {
	footerCache.mu.Lock()
	footerCache.body = nil
	footerCache.mu.Unlock()
}

func footerBody(ref *configRef, now time.Time) []byte {
	maxAge := footerCacheIdle
	if uiActive() {
		maxAge = footerCacheActive
	}
	footerCache.mu.Lock()
	defer footerCache.mu.Unlock()
	if footerCache.body != nil && now.Sub(footerCache.at) < maxAge {
		return footerCache.body
	}
	cfg := ref.Load()
	nodes := nodesIncludingSelf(cfg)
	rows := fetchAllStatus(cfg, nodes)
	d := buildFooter(rows, footerAttnLast.Load(), now)
	d.Event = footerEvent(recentEventRows(cfg, nodes, rows, 1))
	d.Update = updates.status(cfg.UpdateCheck, version)
	b, err := json.Marshal(d)
	if err != nil {
		return nil
	}
	footerCache.at, footerCache.body = now, b
	return b
}

// handleFooter answers the footer's poll from the cached cluster snapshot; the
// quiet auth wrapper keeps the poll from counting as UI activity.
func handleFooter(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b := footerBody(ref, time.Now())
		if b == nil {
			http.Error(w, "footer unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	}
}

const footerHTML = `
<footer class="appfoot" id="appfoot" role="contentinfo" aria-label="Cluster status" data-cs="stale">
  <span class="ft-title" id="ft-title" title="dnshived web interface">dnshived</span>
  <span class="ft-upd" id="ft-upd" role="button" tabindex="0" title="update check"></span>
  <span class="ft-state" id="ft-state" title="waiting for the first cluster reading"><span class="ft-hb" aria-hidden="true"><i class="hb"></i></span><span class="ft-st" id="ft-st">…</span></span>
  <span class="ft-nodes" id="ft-nodes"></span>
  <span class="ft-tele"><span class="w-rev" id="ft-rev"></span><span class="w-ev" id="ft-ev"></span></span>
</footer>
<dialog id="upd-dialog" class="upd-dialog">
  <p id="upd-text"></p>
  <p class="upd-actions"><a id="upd-link" target="_blank" rel="noopener noreferrer" hidden>Release notes</a><button type="button" id="upd-act"></button><button type="button" id="upd-close">Close</button></p>
  <p class="dim" id="upd-msg"></p>
</dialog>
<script>
(function(){
  var f=document.getElementById('appfoot');if(!f)return;
  var lastOK=0,STALE=30000,POLL=10000,busy=false;
  function el(i){return document.getElementById(i)}
  function setCS(v){if(f.getAttribute('data-cs')!==v)f.setAttribute('data-cs',v)}
  var ACK='dnshived-update-ack',U={state:'pending'};
  function acked(v){try{return localStorage.getItem(ACK)===v}catch(e){return false}}
  function renderUpdate(u){
    U=u||{state:'pending'};var s=el('ft-upd'),t='',tip='';
    switch(U.state){
      case 'off':t='update check off';tip='The update check is off. Click to turn it on: once a day this page asks GitHub for the newest release and compares it with this version.';break;
      case 'pending':t='checking…';tip='The first update check has not finished yet.';break;
      case 'fail':t='update: no answer';tip='The last update check got no answer from GitHub. It tries again within an hour.';break;
      case 'new':if(acked(U.latest)){t=U.latest+' known';tip='Version '+U.latest+' is out. You have seen this notice.'}else{t='↑ '+U.latest+' available';tip='Version '+U.latest+' is out. Click for details.'}break;
      default:t='✔ up to date';tip='You run the newest release'+(U.latest?' ('+U.latest+')':'')+'.';
    }
    s.textContent=t;s.title=tip;s.setAttribute('data-st',U.state==='new'&&acked(U.latest)?'known':U.state);
  }
  function openUpdate(){
    var d=el('upd-dialog'),txt=el('upd-text'),act=el('upd-act'),link=el('upd-link'),msg=el('upd-msg');
    msg.textContent='';link.hidden=true;act.hidden=false;act.onclick=null;
    if(U.state==='off'){
      txt.textContent='Update check is off. Turn it on to compare this version with the newest GitHub release once a day. Nothing is downloaded or installed, and the request carries no cluster or user data.';
      act.textContent='Turn on';act.onclick=function(){toggle('1')};
    }else if(U.state==='new'){
      txt.textContent='Version '+U.latest+' is available. Install the package on every node in one window.';
      if(U.url&&U.url.indexOf('https://github.com/')===0){link.href=U.url;link.hidden=false}
      act.textContent='Got it';act.onclick=function(){try{localStorage.setItem(ACK,U.latest)}catch(e){}renderUpdate(U);d.close()};
    }else{
      txt.textContent=U.state==='fail'?'The last check got no answer from GitHub. Nothing else is affected.':(U.state==='pending'?'The first check has not finished yet.':'You run the newest release.');
      act.textContent='Turn off check';act.onclick=function(){toggle('0')};
    }
    var sm=d['show'+'Modal'];if(sm)sm.call(d);
  }
  function toggle(v){
    var b=new URLSearchParams();b.set('enabled',v);
    fetch('/api/update-check',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b.toString()})
      .then(function(r){if(!r.ok)throw 0;el('upd-dialog').close();poll()})
      .catch(function(){el('upd-msg').textContent='Not allowed: changing this needs a role that may edit the configuration.'});
  }
  el('ft-upd').addEventListener('click',openUpdate);
  el('ft-upd').addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();openUpdate()}});
  el('upd-close').addEventListener('click',function(){el('upd-dialog').close()});
  function render(d){
    renderUpdate(d.update);
    el('ft-title').textContent='dnshived '+(d.version||'');
    var txt=d.state,tip='Cluster state: '+d.state+'. The dot pulses while fresh cluster data arrives. Green = all fine, amber = warnings, red = alert, grey = no fresh data.';
    if(d.level==='crit'&&d.alerts>0){txt='ALERT '+d.alerts}else if(d.level==='warn'&&d.warnings>0){txt='WARNINGS '+d.warnings}
    el('ft-st').textContent=txt;el('ft-state').title=tip;
    var box=el('ft-nodes');box.textContent='';
    (d.nodes||[]).forEach(function(n){
      var s=document.createElement('span');s.className='ft-node';
      var b=document.createElement('b');b.textContent=n.name;s.appendChild(b);
      s.appendChild(document.createTextNode(n.up?('up '+(n.uptime||'-')):'down'));
      if(n.up&&n.load){var l=document.createElement('span');l.className='ld';l.textContent=' · ld '+n.load;s.appendChild(l)}
      s.title=n.name+(n.up?(': up '+(n.uptime||'-')+', load '+(n.load||'-')):': not reachable');
      box.appendChild(s)});
    el('ft-rev').textContent=d.revision?('config r'+d.revision):'';el('ft-rev').title=d.revision?('config revision '+d.revision):'';
    el('ft-ev').textContent=d.event||'';el('ft-ev').title=d.event?('newest event: '+d.event):'';
    lastOK=Date.now();setCS(d.age_sec*1000>STALE?'stale':d.level);
  }
  function poll(){
    if(document.hidden||busy)return;busy=true;
    fetch('/api/footer',{credentials:'same-origin',cache:'no-store'}).then(function(r){if(!r.ok)throw 0;return r.json()}).then(render).catch(function(){}).then(function(){busy=false});
  }
  setInterval(function(){if(lastOK&&Date.now()-lastOK>STALE){setCS('stale');el('ft-st').textContent='NO DATA'}},1000);
  poll();setInterval(poll,POLL);
  document.addEventListener('visibilitychange',function(){if(!document.hidden)poll()});
})();
</script>`

const footerStyle = `
html{scrollbar-gutter:stable}
body{padding-bottom:calc(2.5em + 1.2rem)}
.appfoot{--hb:var(--muted);position:fixed;left:0;right:0;bottom:0;z-index:40;display:grid;grid-template-columns:auto auto auto 1fr auto;align-items:center;column-gap:1.1em;
height:2.5em;padding:0 1.1em;background:var(--panel);border-top:1px solid var(--border);color:var(--muted);
font-size:clamp(11px,.42vw + 7.2px,15px);line-height:1.3;white-space:nowrap;font-variant-numeric:tabular-nums}
.appfoot>*{overflow:hidden;text-overflow:ellipsis;min-width:0}
.appfoot .ft-title{color:var(--text);font-weight:650}
.appfoot .ft-upd{display:inline-block;width:10.5em;overflow:hidden;text-overflow:ellipsis;cursor:pointer;color:var(--muted)}
.appfoot .ft-upd[data-st="new"]{color:var(--accent);font-weight:600}
.upd-dialog{max-width:28rem;border:1px solid var(--border);border-radius:10px;background:var(--panel);color:var(--text)}
.upd-dialog::backdrop{background:rgba(0,0,0,.4)}
.upd-actions{display:flex;gap:.8rem;align-items:center;justify-content:flex-end}
.appfoot .ft-state{display:inline-flex;align-items:center;width:11.2em;overflow:visible;color:var(--muted);font-weight:600}
.appfoot .ft-hb{flex:none;display:inline-flex;align-items:center;justify-content:center;width:1.9em;height:1.9em}
.appfoot .ft-st{overflow:hidden;text-overflow:ellipsis;min-width:0}
.appfoot .ft-nodes{display:flex;gap:1.2em;min-width:0}
.appfoot .ft-node{display:inline-block;width:14.6em;overflow:hidden;text-overflow:ellipsis}
.appfoot .ft-node b{color:var(--text);font-weight:600;display:inline-block;width:4.6em;overflow:hidden;text-overflow:ellipsis;vertical-align:bottom}
.appfoot .ft-tele{display:flex;gap:1.1em;justify-content:flex-end}
.appfoot .ft-tele span{display:inline-block;overflow:hidden;text-overflow:ellipsis}
.appfoot .w-rev{width:6.2em}.appfoot .w-ev{width:16em}
.appfoot[data-cs="ok"]{--hb:var(--ok)}.appfoot[data-cs="warn"]{--hb:var(--warn)}.appfoot[data-cs="crit"]{--hb:var(--crit)}
.appfoot[data-cs="ok"] .ft-state{color:var(--ok)}.appfoot[data-cs="warn"] .ft-state{color:var(--warn)}.appfoot[data-cs="crit"] .ft-state{color:var(--crit)}
.hb{position:relative;display:inline-block;width:.7em;height:.7em}
.hb::before,.hb::after{content:"";position:absolute;inset:0;border-radius:50%;background:var(--hb)}
.hb::before{animation:hbdot 2s ease-out infinite}
.hb::after{opacity:0;animation:hbring 2s ease-out infinite}
:root[data-theme="glowing"] .hb::before,:root[data-theme="dark"] .hb::before{box-shadow:0 0 .45em var(--hb)}
.appfoot[data-cs="stale"] .hb::before,.appfoot[data-cs="stale"] .hb::after{animation:none}
.appfoot[data-cs="stale"] .hb::before{box-shadow:none;opacity:.7}
@keyframes hbdot{0%{transform:scale(1.45)}35%{transform:scale(1)}100%{transform:scale(1)}}
@keyframes hbring{0%{transform:scale(1);opacity:.7}100%{transform:scale(3);opacity:0}}
@keyframes hbfade{0%{opacity:1}50%{opacity:.35}100%{opacity:1}}
@media (prefers-reduced-motion:reduce){.hb::before{animation:hbfade 2s ease-in-out infinite}.hb::after{animation:none;opacity:0}.appfoot[data-cs="stale"] .hb::before{animation:none}}
@media (max-width:1500px){.appfoot .ld{display:none}.appfoot .ft-node{width:9.6em}}
@media (max-width:1280px){.appfoot .w-ev{display:none}}
`
