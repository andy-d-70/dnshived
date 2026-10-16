// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"html/template"
	"log"
	"net/http"
)

// navHTML is the shared, two-line nav bar for every page.
const comboboxScriptHTML = `<script>
function dnshivedInitCombos(){
  document.querySelectorAll('select.js-combo').forEach(function(sel){
    if(sel.dataset.comboReady) return;
    sel.dataset.comboReady='1';
    var wrap=document.createElement('span');
    wrap.className='combo';
    sel.parentNode.insertBefore(wrap,sel);
    var input=document.createElement('input');
    input.type='text';
    input.className='combo-input';
    input.autocomplete='off';
    input.setAttribute('role','combobox');
    input.setAttribute('aria-expanded','false');
    input.setAttribute('aria-label',sel.getAttribute('name')||'');
    var list=document.createElement('div');
    list.className='combo-list';
    list.hidden=true;
    wrap.appendChild(input);
    wrap.appendChild(list);
    wrap.appendChild(sel);
    sel.style.display='none';
    sel.tabIndex=-1;
    var active=-1;
    function selectedLabel(){
      var o=sel.options[sel.selectedIndex];
      return o?o.textContent:'';
    }
    function syncFromSelect(){ input.value=selectedLabel(); }
    syncFromSelect();
    function close(){ list.hidden=true; input.setAttribute('aria-expanded','false'); active=-1; }
    function highlight(){
      var items=list.querySelectorAll('.combo-item');
      items.forEach(function(el,i){
        if(i===active){ el.classList.add('combo-item-active'); el.scrollIntoView({block:'nearest'}); }
        else el.classList.remove('combo-item-active');
      });
    }
    function choose(opt){
      sel.value=opt.value;
      input.value=opt.textContent;
      close();
      sel.dispatchEvent(new Event('change',{bubbles:true}));
    }
    function open(query){
      var q=(query||'').toLowerCase();
      var matches=[];
      for(var i=0;i<sel.options.length && matches.length<200;i++){
        var o=sel.options[i];
        if(o.textContent.toLowerCase().indexOf(q)!==-1) matches.push(o);
      }
      list.innerHTML='';
      if(matches.length===0){
        var e=document.createElement('div');
        e.className='combo-empty';
        e.textContent='no match';
        list.appendChild(e);
        list.hidden=false;
        input.setAttribute('aria-expanded','true');
        active=-1;
        return;
      }
      matches.forEach(function(o){
        var item=document.createElement('div');
        item.className='combo-item';
        item.textContent=o.textContent;
        item.addEventListener('mousedown',function(ev){ ev.preventDefault(); choose(o); });
        list.appendChild(item);
      });
      active=0;
      highlight();
      list.hidden=false;
      input.setAttribute('aria-expanded','true');
    }
    input.addEventListener('focus',function(){
      open(input.value===selectedLabel()?'':input.value);
    });
    input.addEventListener('input',function(){ open(input.value); });
    input.addEventListener('keydown',function(ev){
      var items=list.querySelectorAll('.combo-item');
      if(ev.key==='ArrowDown'){
        ev.preventDefault();
        if(list.hidden){ open(input.value); return; }
        active=Math.min(active+1,items.length-1);
        highlight();
      }else if(ev.key==='ArrowUp'){
        ev.preventDefault();
        active=Math.max(active-1,0);
        highlight();
      }else if(ev.key==='Enter'){
        if(!list.hidden && active>=0 && items[active]){
          ev.preventDefault();
          items[active].dispatchEvent(new Event('mousedown'));
        }
      }else if(ev.key==='Escape'){
        close();
        syncFromSelect();
      }
    });
    input.addEventListener('blur',function(){
      setTimeout(function(){
        if(input.value.toLowerCase()!==selectedLabel().toLowerCase()){
          var found=null;
          for(var i=0;i<sel.options.length;i++){
            if(sel.options[i].textContent.toLowerCase()===input.value.toLowerCase()){ found=sel.options[i]; break; }
          }
          if(found){
            sel.value=found.value;
            input.value=found.textContent;
            sel.dispatchEvent(new Event('change',{bubbles:true}));
          }else{
            syncFromSelect();
          }
        }
        close();
      },150);
    });
  });
}
document.addEventListener('DOMContentLoaded', dnshivedInitCombos);
</script>`

const logModalScriptHTML = `<script>
function showLogModal(title, url, linkEl){
  var dlg=document.getElementById('log-modal');
  if(!dlg) return true; // no modal on this page — let the real link navigate
  document.getElementById('log-modal-title').textContent=title;
  document.getElementById('log-modal-body').textContent='loading…';
  dlg.showModal();
  fetch(url).then(function(r){ return r.text(); }).then(function(t){
    document.getElementById('log-modal-body').textContent=t || '(empty)';
  }).catch(function(e){
    document.getElementById('log-modal-body').textContent='fetch failed: '+e;
  });
  return false;
}

// submitFormInModal POSTs the form via fetch, shows the plain-text result
// in the log modal and reloads the page on close.
function submitFormInModal(form, title){
  var dlg=document.getElementById('log-modal');
  if(!dlg) return true; // no modal on this page — let the form submit normally
  document.getElementById('log-modal-title').textContent=title;
  document.getElementById('log-modal-body').textContent='working…';
  dlg.showModal();
  fetch(form.action, {method:'POST', body:new FormData(form)}).then(function(r){ return r.text(); }).then(function(t){
    document.getElementById('log-modal-body').textContent=t || '(empty)';
  }).catch(function(e){
    document.getElementById('log-modal-body').textContent='request failed: '+e;
  });
  dlg.addEventListener('close', function(){ location.reload(); }, {once:true});
  return false;
}

// submitFormAsConsole narrates steps line by line while the real request
// runs, then shows the server's actual response.
function submitFormAsConsole(form, title, steps){
  var dlg=document.getElementById('log-modal');
  if(!dlg) return true; // no modal on this page — let the form submit normally
  document.getElementById('log-modal-title').textContent=title;
  var body=document.getElementById('log-modal-body');
  body.textContent='';
  dlg.showModal();
  var i=0;
  var timer=setInterval(function(){
    if(i>=steps.length){ clearInterval(timer); return; }
    body.textContent += (body.textContent?'\n':'') + steps[i];
    i++;
  }, 450);
  fetch(form.action, {method:'POST', body:new FormData(form)}).then(function(r){ return r.text(); }).then(function(t){
    clearInterval(timer);
    body.textContent = steps.join('\n') + '\n\n' + (t || '(empty)');
  }).catch(function(e){
    clearInterval(timer);
    body.textContent = steps.join('\n') + '\n\nrequest failed: '+e;
  });
  dlg.addEventListener('close', function(){ location.reload(); }, {once:true});
  return false;
}
</script>`

const navBrandMarkSVG = `<svg class="brand-mark" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" aria-hidden="true"><path d="M 16 46 A 24 24 0 0 1 32 10" fill="none" class="ring-dim" stroke-width="4" stroke-linecap="round"/><path d="M 48 46 A 24 24 0 0 1 16 46" fill="none" class="ring-dim" stroke-width="4" stroke-linecap="round"/><path d="M 32 10 A 24 24 0 0 1 48 46" fill="none" class="auth" stroke-width="5" stroke-linecap="round"/><circle cx="32" cy="10" r="6" class="nd" stroke="none"/><circle cx="16" cy="46" r="6" class="nd" stroke="none"/><circle cx="48" cy="46" r="6" class="nd" stroke="none"/></svg>`

const navHTML = `<div class="nav-outer">
<nav>
<a href="/" class="nav-item brand"><span class="nav-name">` + navBrandMarkSVG + ` dnshived</span><span class="nav-desc">overview</span></a>
<a href="/scopes" class="nav-item"><span class="nav-name">scopes</span><span class="nav-desc">manage dhcp scopes</span></a>
<a href="/config/dns" class="nav-item"><span class="nav-name">dhcp &amp; dns</span><span class="nav-desc">defaults &amp; templates</span></a>
<a href="/probes" class="nav-item"><span class="nav-name">probes</span><span class="nav-desc">dhcp/dns checks</span></a>
<a href="/scopes/options" class="nav-item"><span class="nav-name">scope options</span><span class="nav-desc">vip &amp; new-scope defaults</span></a>
<a href="/security" class="nav-item"><span class="nav-name">security</span><span class="nav-desc">tokens &amp; users</span></a>
<a href="/backup" class="nav-item"><span class="nav-name">config management</span><span class="nav-desc">export, import, backup</span></a>
<a href="/config" class="nav-item"><span class="nav-name">cluster config</span><span class="nav-desc">nodes &amp; settings</span></a>
<a href="/logs" class="nav-item"><span class="nav-name">logs</span><span class="nav-desc">system &amp; audit log</span></a>
</nav>
<button type="button" id="theme_switcher" class="nav-theme-select" onclick="dnshivedCycleTheme()" title="color scheme — click to cycle">Normal</button>
<form method="post" action="/logout" style="margin:0;display:flex"><button type="submit" class="nav-theme-select" title="end this web-UI session">Log out</button></form>
<a href="/pending" class="nav-item nav-pending-btn"><span class="nav-name">pending changes<span id="pending-marker" title="a change is staged and waiting to be committed" style="display:none;margin-left:.3rem">&#9679;</span></span><span class="nav-desc">review &amp; commit</span></a>
</div>
<script>
function pollPendingMarker(){
  fetch('/api/pending-summary').then(function(r){return r.json();}).then(function(d){
    var m=document.getElementById('pending-marker');
    if(d.hasChanges){
      m.className='warn';
      m.style.display='inline';
    }else{
      m.style.display='none';
    }
  }).catch(function(){});
}
pollPendingMarker();
setInterval(pollPendingMarker, 1000);
// Click-to-cycle color scheme, persisted in
// localStorage['dnshived-theme'].
var DNSHIVED_THEME_CYCLE = ['normal', 'glowing', 'dark'];
var DNSHIVED_THEME_LABELS = {normal: 'Normal', glowing: 'Glowing', dark: 'Dark'};
function dnshivedApplyTheme(t){
  if(t==='normal'){ document.documentElement.removeAttribute('data-theme'); }
  else { document.documentElement.setAttribute('data-theme', t); }
  var btn=document.getElementById('theme_switcher');
  if(btn) btn.textContent=DNSHIVED_THEME_LABELS[t]||'Normal';
}
(function(){
  try{ dnshivedApplyTheme(localStorage.getItem('dnshived-theme')||'normal'); }catch(e){}
})();
function dnshivedCycleTheme(){
  var cur='normal';
  try{ cur=localStorage.getItem('dnshived-theme')||'normal'; }catch(e){}
  var idx=DNSHIVED_THEME_CYCLE.indexOf(cur);
  var next=DNSHIVED_THEME_CYCLE[(idx+1)%DNSHIVED_THEME_CYCLE.length];
  try{ localStorage.setItem('dnshived-theme', next); }catch(e){}
  dnshivedApplyTheme(next);
}
</script>` + comboboxScriptHTML

// styleHTML is inserted right after <title> on every page (see its call
// sites).
const styleHTML = `<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<script>(function(){try{var t=localStorage.getItem('dnshived-theme');if(t==='glowing'||t==='dark'){document.documentElement.setAttribute('data-theme',t);}}catch(e){}})();</script>
<style>
:root{
--bg:#f2f4f7;--panel:#fff;--border:#dde1e7;--text:#1b1f24;--muted:#68707b;
--accent:#2563eb;--head:#eaedf2;
--ok:#0a7a34;--warn:#a6640a;--crit:#c0392b;
--core-1:#c00;--core-2:#06c;--core-3:#000;--worker-probe:#080;
--tint-1:#fdf2f1;--tint-2:#f0f6fd;--tint-3:#f0f0f0;--tint-crit:#fdeceb;
/* --nav-h is the sticky nav's height; other sticky elements offset below it. */
--nav-h:3.3rem;
}
:root[data-theme="glowing"]{
--bg:#e6f2ff;--panel:#fff;--border:#b7d3f5;--text:#0b1220;--muted:#4a5b7a;
--accent:#0066ff;--head:#d2e8ff;
--ok:#00c853;--warn:#ff9500;--crit:#ff3b30;
--core-1:#ff1a1a;--core-2:#00aaff;--core-3:#111;--worker-probe:#00e676;
--tint-1:#ffd9d4;--tint-2:#cfe9ff;--tint-3:#dcdcdc;--tint-crit:#ffd6d0;
}
:root[data-theme="dark"]{
--bg:#0f1318;--panel:#171c23;--border:#2a323d;--text:#e7ebf0;--muted:#8f9bab;
--accent:#5b9dff;--head:#20262f;
--ok:#3ddc84;--warn:#ffb84d;--crit:#ff6b6b;
--core-1:#ff6b6b;--core-2:#5b9dff;--core-3:#e7ebf0;--worker-probe:#3ddc84;
--tint-1:rgba(255,107,107,.14);--tint-2:rgba(91,157,255,.14);--tint-3:rgba(231,235,240,.14);--tint-crit:rgba(255,107,107,.14);
}
*{box-sizing:border-box}
body{margin:0;padding:1.5rem;max-width:1400px;background:var(--bg);color:var(--text);
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
font-size:14px;line-height:1.5}
h1{font-size:1.35rem;margin:0 0 .75rem;font-weight:650}
h2,h3{font-weight:600}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.nav-outer{display:flex;align-items:center;gap:.5rem;margin:0 0 1.1rem;
position:sticky;top:0;z-index:20}
nav{display:flex;flex-wrap:wrap;align-items:stretch;gap:.15rem;background:var(--panel);
border:1px solid var(--border);border-radius:8px;padding:.35rem .5rem;
box-shadow:0 1px 2px rgba(0,0,0,.06);font-size:.87rem;flex:1;min-width:0}
/* scoped to .nav-outer so the Pending Changes button outside nav matches too. */
.nav-outer .nav-item{flex-shrink:0;display:flex;flex-direction:column;justify-content:center;gap:.05rem;
padding:.25rem .55rem;border-radius:6px;color:var(--text);text-decoration:none;line-height:1.2}
.nav-outer .nav-item:hover{background:var(--bg);text-decoration:none}
.nav-outer .nav-name{font-weight:600;font-size:.85rem;display:flex;align-items:center;gap:.3rem}
.nav-outer .nav-desc{font-size:.65rem;color:var(--muted);font-weight:400}
nav .brand .nav-name{font-weight:700}
/* 1.5em: the mark's artwork has empty margin, so 1em reads smaller than the text. */
nav .brand svg.brand-mark{display:block;width:1.5em;height:1.5em}
/* logo colors follow the selected theme, not the OS dark-mode preference. */
nav .brand svg.brand-mark .nd{fill:var(--text)}
nav .brand svg.brand-mark .ring-dim{stroke:var(--border)}
nav .brand svg.brand-mark .auth{stroke:var(--accent)}
/* lines the second row up with the text after the brand icon. */
nav .brand .nav-desc{margin-left:calc(1.5em + .3rem)}
.nav-pending-btn{flex-shrink:0;background:var(--accent);color:#fff;
box-shadow:0 1px 2px rgba(0,0,0,.06)}
.nav-pending-btn:hover{background:var(--accent);opacity:.9}
.nav-pending-btn .nav-desc{color:rgba(255,255,255,.75)}
.nav-theme-select{flex-shrink:0;align-self:center}
/* view-tabs: pill tabs linking two related pages. */
.view-tabs{display:flex;gap:.3rem;margin:0 0 1rem}
.view-tabs a,.view-tabs .active{padding:.3rem .7rem;border-radius:6px;font-size:.9rem;font-weight:600}
.view-tabs .active{background:var(--accent);color:#fff}
.view-tabs a{background:var(--panel);border:1px solid var(--border);color:var(--text);text-decoration:none}
.view-tabs a:hover{background:var(--bg);text-decoration:none}
table{border-collapse:collapse;width:100%;background:var(--panel);border:1px solid var(--border);
border-radius:8px;overflow:hidden;margin:0 0 1.1rem}
.table-wrap{overflow-x:auto;margin:0 0 1.1rem}
.table-wrap table{margin:0}
/* fixed-table: explicit <colgroup> widths, never reflowed by content. */
.fixed-table{table-layout:fixed}
.fixed-table td,.fixed-table th{overflow-wrap:break-word}
.fixed-table td{vertical-align:top;line-height:1.3}
th,td{padding:.4rem .6rem;text-align:left;border-bottom:1px solid var(--border);font-size:.92rem}
th{background:var(--head);font-weight:600}
tr:last-child td{border-bottom:none}
details{background:var(--panel);border:1px solid var(--border);border-radius:8px;
margin:0 0 .5rem;padding:.05rem .8rem}
details>summary{cursor:pointer;padding:.55rem 0;font-weight:500}
details details{margin:.4rem 0 .6rem;box-shadow:none}
p{margin:.5rem 0}
ul{margin:.3rem 0 .8rem 0}
input,select,textarea{font:inherit;padding:.35rem .5rem;border:1px solid var(--border);border-radius:5px;
background:var(--panel);color:var(--text)}
button,input[type=submit]{font:inherit;padding:.35rem .75rem;border:1px solid var(--accent);
border-radius:5px;background:var(--accent);color:#fff;cursor:pointer}
button:hover,input[type=submit]:hover{opacity:.9}
/* btn-success for commit-shaped actions, btn-danger for discard/delete. */
button.btn-success{background:var(--ok);border-color:var(--ok)}
button.btn-danger{background:var(--crit);border-color:var(--crit)}
/* btn-warn for disable (reversible, keeps VLAN/VIP up). */
button.btn-warn{background:var(--warn);border-color:var(--warn)}
/* loading-dots: pure-CSS animated dots, static under prefers-reduced-motion. */
.loading-dots span{animation:loading-dots-pulse 1.4s ease-in-out infinite}
.loading-dots span:nth-child(2){animation-delay:.2s}
.loading-dots span:nth-child(3){animation-delay:.4s}
@keyframes loading-dots-pulse{0%,80%,100%{opacity:.25}40%{opacity:1}}
@media (prefers-reduced-motion:reduce){.loading-dots span{animation:none;opacity:1}}
/* find-as-you-type combobox (dnshivedInitCombos); the list overlays, never reflows. */
.combo{position:relative;display:inline-block;min-width:12rem}
.combo-input{width:100%}
.combo-list{position:absolute;z-index:30;top:100%;left:0;right:0;margin-top:2px;
max-height:14rem;overflow-y:auto;background:var(--panel);border:1px solid var(--border);
border-radius:6px;box-shadow:0 4px 10px rgba(0,0,0,.15)}
.combo-item{padding:.3rem .5rem;font-size:.92rem;cursor:pointer}
.combo-item:hover,.combo-item-active{background:var(--accent);color:#fff}
.combo-empty{padding:.3rem .5rem;font-size:.85rem;color:var(--muted)}
/* log-modal: a small window over the page; dialog::backdrop and showModal() do the rest. */
dialog#log-modal{background:var(--panel);color:var(--text);border:1px solid var(--border);
border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.25);padding:1rem 1.2rem;
width:min(900px,90vw);max-height:80vh}
dialog#log-modal::backdrop{background:rgba(0,0,0,.45)}
dialog#log-modal .table-wrap{max-height:60vh;overflow:auto}
/* paths-modal: the dialog is the one vertical scroll region; inner tables scroll sideways only. */
dialog#paths-modal{background:var(--panel);color:var(--text);border:1px solid var(--border);
border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.25);padding:1rem 1.2rem;
width:min(900px,90vw);max-height:80vh;overflow-y:auto}
dialog#paths-modal::backdrop{background:rgba(0,0,0,.45)}
dialog#paths-modal .table-wrap{overflow-x:auto;overflow-y:visible;max-height:none}
/* .modal-head keeps the title and Close button visible while the content scrolls. */
dialog#paths-modal .modal-head{display:flex;align-items:center;justify-content:space-between;
gap:1rem;position:sticky;top:0;background:var(--panel);padding-bottom:.4rem;
margin-bottom:.4rem;border-bottom:1px solid var(--border)}
dialog#paths-modal .modal-head h2{margin:0}
dialog#paths-modal .modal-head form{margin:0}
/* trust-bar: a smooth green-to-red gradient (trustBarColor, status.go). */
.trust-bar{display:inline-block;width:80px;height:8px;background:var(--border);
border-radius:4px;overflow:hidden;vertical-align:middle;margin-right:.4rem}
.trust-bar-fill{height:100%}
/* pre-wrap so long note lines wrap instead of scrolling sideways. */
dialog#log-modal pre{font-size:.82rem;white-space:pre-wrap;word-break:break-word}
dialog#log-modal form{margin:.8rem 0 0;text-align:right}
.ok{color:var(--ok);font-weight:600}
.warn{color:var(--warn);font-weight:600}
.crit{color:var(--crit);font-weight:600}
.dim{color:var(--muted)}
/* .info-ico: a visible info glyph carrying a title= tooltip. */
.info-ico{display:inline-block;color:var(--muted);cursor:help;
font-size:1.28em;margin-left:.25em;text-decoration:none}
.info-ico:hover{color:var(--accent)}
/* .rogue-badge: solid crit badge for a rogue DHCP server finding. */
.rogue-badge{background:var(--crit);color:#fff;font-weight:700;
padding:.1rem .4rem;border-radius:3px;font-size:.82rem}
/* .vip-badge: marks the node holding the mgmt VIP; a location, not a health state. */
.vip-badge{background:var(--accent);color:#fff;font-weight:700;
padding:.1rem .4rem;border-radius:3px;font-size:.82rem}
.name-dot{display:inline-block;width:.6rem;height:.6rem;border-radius:50%;margin-right:.3rem;
vertical-align:middle;border:1px solid var(--border)}
.pool-bar{display:inline-block;width:70px;height:8px;background:var(--border);border-radius:4px;
overflow:hidden;vertical-align:middle;margin-right:.4rem}
.pool-fill{display:block;height:100%}
.pool-fill.ok{background:var(--ok)}
.pool-fill.warn{background:var(--warn)}
.pool-fill.crit{background:var(--crit)}
.node-core-1{color:var(--core-1)}
.node-core-2{color:var(--core-2)}
.node-core-3{color:var(--core-3)}
.node-probe{color:var(--worker-probe)}
</style>`

// renderTemplate executes tmpl and logs (rather than panics or 500s on) a
// render failure.
func renderTemplate(w http.ResponseWriter, tmpl *template.Template, data interface{}, name string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("[ERROR] render %s page: %v", name, err)
	}
}
