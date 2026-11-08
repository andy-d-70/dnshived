// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"html/template"
	"log"
	"net/http"
	"strings"
)

// navHTML is the shared, two-line nav bar for every page.
const comboboxScriptHTML = `<script>
var comboMax=200;
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
      var exact=[],prefix=[],rest=[];
      for(var i=0;i<sel.options.length;i++){
        var o=sel.options[i];
        var t=o.textContent.toLowerCase();
        if(t===q || o.value.toLowerCase()===q) exact.push(o);
        else if(t.indexOf(q)===0) prefix.push(o);
        else if(t.indexOf(q)!==-1) rest.push(o);
      }
      var all=exact.concat(prefix,rest);
      var matches=all.slice(0,comboMax);
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
      if(all.length>matches.length){
        var more=document.createElement('div');
        more.className='combo-more';
        more.textContent=(all.length-matches.length)+' more — type to narrow';
        more.addEventListener('mousedown',function(ev){ ev.preventDefault(); });
        list.appendChild(more);
      }
      active=0;
      highlight();
      list.hidden=false;
      input.setAttribute('aria-expanded','true');
    }
    var keepSelection=false;
    input.addEventListener('focus',function(){
      open(input.value===selectedLabel()?'':input.value);
      input.select();
      keepSelection=true;
    });
    input.addEventListener('mouseup',function(ev){
      if(keepSelection){ ev.preventDefault(); keepSelection=false; }
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
      keepSelection=false;
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
<nav id="mainnav" aria-label="Main">
<a href="/" class="nav-item brand" title="overview of the whole cluster" data-match="/,/status"><span class="nav-name">` + navBrandMarkSVG + ` dnshived</span></a>
<button type="button" class="nav-menu-toggle" id="nav-menu-toggle" aria-expanded="false" aria-controls="mainnav" onclick="dnshivedToggleNav()">&#9776; Menu</button>
<a href="/scopes" class="nav-item" title="manage dhcp scopes, defaults for new scopes, topology" data-match="/scopes,/topology,/config/scopes"><span class="nav-name">Scopes</span></a>
<a href="/probes" class="nav-item" title="dhcp and dns checks from the probe host" data-match="/probes,/config/probe-parallel"><span class="nav-name">Probes</span></a>
<span class="nav-sep" aria-hidden="true"></span>
<a href="/config/dns" class="nav-item" title="defaults, templates, local domains" data-match="/config/dns,/config/domains,/templates,/optionsets,/groups,/rollout"><span class="nav-name">DHCP &amp; DNS</span></a>
<a href="/security" class="nav-item" title="users, tokens, mail, password policy" data-match="/security,/users,/config/mail,/password"><span class="nav-name">Security</span></a>
<a href="/backup" class="nav-item" title="export, import, backup and restore" data-match="/backup,/config/export"><span class="nav-name">Maintenance</span></a>
<a href="/config" class="nav-item" title="nodes, interfaces, cluster-wide settings" data-match="/config"><span class="nav-name">Cluster settings</span></a>
<a href="/logs" class="nav-item" title="system log, audit log, daemons" data-match="/logs,/audit,/daemons"><span class="nav-name">Logs</span></a>
</nav>
<a href="/pending" class="nav-item nav-pending-btn" title="review and commit staged changes" data-match="/pending"><span class="nav-name">Pending changes<span id="pending-marker" title="a change is staged and waiting to be committed" style="display:none;margin-left:.3rem">&#9679;</span></span></a>
<button type="button" id="theme_switcher" class="nav-theme-select" onclick="dnshivedCycleTheme()" title="color scheme — click to cycle">Normal</button>
<form method="post" action="/logout" style="margin:0;display:flex"><button type="submit" class="nav-theme-select" title="end this web-UI session">Log out</button></form>
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
function dnshivedToggleNav(){
  var n=document.getElementById('mainnav'),b=document.getElementById('nav-menu-toggle');
  var open=n.classList.toggle('open');
  b.setAttribute('aria-expanded',open?'true':'false');
}
// The item with the longest matching path prefix is the current page.
(function(){
  var path=location.pathname,best=null,bestLen=-1;
  document.querySelectorAll('.nav-outer a[data-match]').forEach(function(a){
    a.getAttribute('data-match').split(',').forEach(function(p){
      var hit=(p==='/')?(path==='/'):(path===p||path.indexOf(p+'/')===0);
      if(hit&&p.length>bestLen){best=a;bestLen=p.length;}
    });
  });
  if(best)best.setAttribute('aria-current','page');
})();
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
// Tabs: every .tab-host holds .tab-pane[data-tab] sections, in any nesting. Without
// this script all panes simply stay visible. A hash such as #discovered opens the
// pane that holds that element; an invalid field in a hidden pane opens its pane.
function dnshivedInitTabs(){
  document.querySelectorAll('.tab-host').forEach(function(host){
    var panes=[].slice.call(host.querySelectorAll('.tab-pane[data-tab]'));
    var extra=[];
    try{ extra=JSON.parse(host.getAttribute('data-extra-tabs')||'[]'); }catch(e){}
    if(panes.length+extra.length<2) return;
    panes.forEach(function(p,i){p.__i=i;});
    panes.sort(function(a,b){return ((+a.dataset.tabOrder||999)-(+b.dataset.tabOrder||999))||(a.__i-b.__i);});
    var strip=document.createElement('div');
    strip.className='tabs';
    strip.setAttribute('role','tablist');
    var btns=[];
    function show(p){
      panes.forEach(function(x){x.classList.toggle('active',x===p);});
      btns.forEach(function(b){b.setAttribute('aria-selected',b.__pane===p?'true':'false');});
      host.querySelectorAll('.tab-submit').forEach(function(el){
        var f=el.closest('form');
        el.style.display=(f&&f.contains(p))?'':'none';
      });
    }
    panes.forEach(function(p){
      var b=document.createElement('button');
      b.type='button';
      b.setAttribute('role','tab');
      b.textContent=p.getAttribute('data-tab');
      b.__pane=p;
      b.onclick=function(){
        show(p);
        try{ if(p.id) history.replaceState(null,'','#'+p.id); }catch(e){}
      };
      strip.appendChild(b);
      btns.push(b);
    });
    extra.forEach(function(x){
      var a=document.createElement('a');
      a.className='tab-link';
      a.textContent=x[0];
      a.href=x[1];
      strip.appendChild(a);
    });
    host.insertBefore(strip,host.firstChild);
    host.classList.add('tabs-ready');
    function fromHash(){
      var id=decodeURIComponent(location.hash.slice(1));
      if(!id) return null;
      var el=document.getElementById(id);
      if(!el) return null;
      for(var i=0;i<panes.length;i++){ if(panes[i]===el||panes[i].contains(el)) return {p:panes[i],el:el}; }
      return null;
    }
    var h=fromHash();
    var first=panes.filter(function(p){return p.hasAttribute('data-tab-default');})[0]||panes[0];
    show(h?h.p:first);
    if(h&&h.el!==h.p) h.el.scrollIntoView();
    window.addEventListener('hashchange',function(){var n=fromHash(); if(n) show(n.p);});
    host.addEventListener('invalid',function(e){
      for(var i=0;i<panes.length;i++){
        if(panes[i].contains(e.target)){ if(!panes[i].classList.contains('active')) show(panes[i]); break; }
      }
    },true);
  });
}
document.addEventListener('DOMContentLoaded', dnshivedInitTabs);
// Line lists: a textarea marked data-line-list is shown as one line per entry with a
// menu (Edit, Copy, Delete). The textarea stays the source of truth and is what the
// form submits, so the server side does not change; "Edit as text" brings it back.
function dnshivedLineLists(){
  var menu=null,menuOwner=null,menuTimer=null;
  function closeMenu(){ if(menu){menu.hidden=true;} menuOwner=null; if(menuTimer){clearTimeout(menuTimer);menuTimer=null;} }
  function ensureMenu(){
    if(menu) return menu;
    menu=document.createElement('div');
    menu.className='row-menu-list ll-menu';
    menu.setAttribute('role','menu');
    menu.hidden=true;
    document.body.appendChild(menu);
    menu.addEventListener('mouseenter',function(){ if(menuTimer){clearTimeout(menuTimer);menuTimer=null;} });
    menu.addEventListener('mouseleave',function(){ menuTimer=setTimeout(closeMenu,400); });
    document.addEventListener('click',function(e){ if(menu&&!menu.hidden&&!menu.contains(e.target)&&!(e.target.closest&&e.target.closest('.ll-menu-btn'))) closeMenu(); });
    document.addEventListener('keydown',function(e){ if(e.key==='Escape') closeMenu(); });
    window.addEventListener('scroll',closeMenu,true);
    window.addEventListener('resize',closeMenu);
    return menu;
  }
  document.querySelectorAll('textarea[data-line-list]').forEach(function(ta){
    if(ta.dataset.llReady) return;
    ta.dataset.llReady='1';
    var wrap=document.createElement('div');
    wrap.className='line-list';
    var tools=document.createElement('div');
    tools.className='line-list-tools';
    var filter=document.createElement('input');
    filter.type='text';
    filter.placeholder='filter…';
    filter.setAttribute('aria-label','filter the lines');
    var count=document.createElement('span');
    count.className='dim';
    var spacer=document.createElement('span');
    spacer.style.flex='1';
    var toggle=document.createElement('button');
    toggle.type='button';
    toggle.className='mini';
    toggle.textContent='Edit as text';
    tools.appendChild(filter); tools.appendChild(count); tools.appendChild(spacer); tools.appendChild(toggle);
    var body=document.createElement('div');
    wrap.appendChild(tools); wrap.appendChild(body);
    ta.parentNode.insertBefore(wrap,ta);
    ta.hidden=true;
    var last=ta.value,editing=-1,showAll=false,LIMIT=100;
    function lines(){ return ta.value.split('\n').map(function(l){return l.replace(/\s+$/,'');}).filter(function(l){return l!=='';}); }
    function setLines(a){ ta.value=a.join('\n'); last=ta.value; ta.dispatchEvent(new Event('input',{bubbles:true})); render(); }
    function openMenu(btn,i){
      var m=ensureMenu();
      if(menuOwner===btn){ closeMenu(); return; }
      m.innerHTML='';
      [['Edit…',function(){editing=i;render();}],['Copy',function(){var a=lines();a.splice(i+1,0,a[i]);setLines(a);}],['Delete',function(){var a=lines();a.splice(i,1);setLines(a);},'danger']].forEach(function(it){
        var b=document.createElement('button');
        b.type='button';
        b.setAttribute('role','menuitem');
        b.textContent=it[0];
        if(it[2]) b.className=it[2];
        b.onclick=function(){ closeMenu(); it[1](); };
        m.appendChild(b);
      });
      m.hidden=false; m.style.visibility='hidden'; m.style.left='0px'; m.style.top='0px';
      var r=btn.getBoundingClientRect(),w=m.offsetWidth,h=m.offsetHeight;
      var left=Math.max(8,Math.min(r.right-w,window.innerWidth-w-8)),top=r.bottom+4;
      if(top+h>window.innerHeight-8) top=Math.max(8,r.top-h-4);
      m.style.left=left+'px'; m.style.top=top+'px'; m.style.visibility='visible';
      menuOwner=btn;
      m.querySelector('button').focus();
    }
    function render(){
      var a=lines(),q=filter.value.toLowerCase();
      filter.style.display=(a.length>8||q)?'':'none';
      body.innerHTML='';
      var shown=0,total=0;
      a.forEach(function(text,i){
        if(q&&text.toLowerCase().indexOf(q)<0) return;
        total++;
        if(!showAll&&shown>=LIMIT&&editing!==i) return;
        shown++;
        var row=document.createElement('div');
        row.className='line-list-row';
        if(editing===i){
          var inp=document.createElement('input');
          inp.type='text'; inp.className='edit'; inp.value=text;
          inp.setAttribute('aria-label','edit line '+(i+1));
          var ok=document.createElement('button'); ok.type='button'; ok.className='mini'; ok.textContent='Save';
          var no=document.createElement('button'); no.type='button'; no.className='mini'; no.textContent='Cancel';
          function save(){ var b=lines(); var v=inp.value.replace(/\s+$/,''); if(v==='') b.splice(i,1); else b[i]=v; editing=-1; setLines(b); }
          ok.onclick=save;
          no.onclick=function(){ editing=-1; render(); };
          inp.onkeydown=function(e){ if(e.key==='Enter'){e.preventDefault();save();} else if(e.key==='Escape'){editing=-1;render();} };
          row.appendChild(inp); row.appendChild(ok); row.appendChild(no);
          body.appendChild(row);
          setTimeout(function(){inp.focus();},0);
          return;
        }
        var code=document.createElement('code');
        code.textContent=text;
        var mb=document.createElement('button');
        mb.type='button';
        mb.className='mini ll-menu-btn';
        mb.textContent='☰';
        mb.setAttribute('aria-haspopup','menu');
        mb.setAttribute('aria-label','Actions for line '+(i+1));
        mb.onclick=function(e){ e.stopPropagation(); openMenu(mb,i); };
        row.appendChild(code); row.appendChild(mb);
        body.appendChild(row);
      });
      if(!a.length){ var e0=document.createElement('div'); e0.className='line-list-row dim'; e0.textContent='none yet'; body.appendChild(e0); }
      else if(total>shown){
        var more=document.createElement('div'); more.className='line-list-row';
        var mbtn=document.createElement('button'); mbtn.type='button'; mbtn.className='mini'; mbtn.textContent='Show all '+total;
        mbtn.onclick=function(){ showAll=true; render(); };
        more.appendChild(mbtn); body.appendChild(more);
      }
      count.textContent=a.length+(a.length===1?' line':' lines')+(q?' ('+total+' shown)':'');
    }
    filter.oninput=function(){ showAll=false; render(); };
    toggle.onclick=function(){
      var asText=ta.hidden;
      ta.hidden=!asText;
      body.hidden=asText; filter.hidden=asText; count.hidden=asText;
      toggle.textContent=asText?'Edit as text':'Show as list';
      if(!asText){ ta.focus(); } else { last=ta.value; render(); }
    };
    setInterval(function(){ if(!document.hidden&&ta.value!==last&&editing<0){ last=ta.value; render(); } },500);
    render();
  });
}
document.addEventListener('DOMContentLoaded', dnshivedLineLists);
// Stacked tables: a table marked data-stack turns each row into a small card on a phone;
// every cell gets its column heading as data-label for the CSS to show.
function dnshivedStackTables(){
  document.querySelectorAll('table[data-stack]').forEach(function(t){
    var rows=[].slice.call(t.rows),head=null,labels=[];
    for(var i=0;i<rows.length;i++){ if(rows[i].querySelector('th')){ head=rows[i]; break; } }
    if(!head) return;
    head.classList.add('stack-head');
    [].forEach.call(head.cells,function(c){ labels.push(c.textContent.replace(/\s+/g,' ').trim()); });
    rows.forEach(function(r){
      if(r===head) return;
      [].forEach.call(r.cells,function(c,i){ if(labels[i]&&!c.hasAttribute('colspan')) c.setAttribute('data-label',labels[i]); });
    });
  });
}
document.addEventListener('DOMContentLoaded', dnshivedStackTables);
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
--bg:#f2f4f7;--panel:#fff;--border:#dde1e7;--text:#1b1f24;--muted:#5f6772;
--accent:#2563eb;--head:#eaedf2;
--ok:#0a7a34;--warn:#955806;--crit:#c0392b;
--on-accent:#fff;--on-ok:#fff;--on-warn:#fff;--on-crit:#fff;
--core-1:#c00;--core-2:#06c;--core-3:#000;--worker-probe:#080;
--tint-1:#fdf2f1;--tint-2:#f0f6fd;--tint-3:#f0f0f0;--tint-crit:#fdeceb;
/* --nav-h is the sticky nav's height; other sticky elements offset below it. */
--nav-h:3.3rem;
}
:root[data-theme="glowing"]{
--bg:#e6f2ff;--panel:#fff;--border:#b7d3f5;--text:#0b1220;--muted:#4a5b7a;
--accent:#0057e6;--head:#d2e8ff;
--ok:#006b27;--warn:#8f5200;--crit:#b8231a;
--on-accent:#fff;--on-ok:#fff;--on-warn:#fff;--on-crit:#fff;
--core-1:#c40d0d;--core-2:#0058a8;--core-3:#111;--worker-probe:#006b27;
--tint-1:#ffd9d4;--tint-2:#cfe9ff;--tint-3:#dcdcdc;--tint-crit:#ffd6d0;
}
:root[data-theme="dark"]{
--bg:#0f1318;--panel:#171c23;--border:#2a323d;--text:#e7ebf0;--muted:#8f9bab;
--accent:#5b9dff;--head:#20262f;
--ok:#3ddc84;--warn:#ffb84d;--crit:#ff6b6b;
--on-accent:#0b1220;--on-ok:#0b1220;--on-warn:#0b1220;--on-crit:#0b1220;
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
.nav-outer .nav-item{flex-shrink:0;display:flex;align-items:center;
padding:.4rem .7rem;border-radius:7px;color:var(--text);text-decoration:none;line-height:1.2;border-bottom:2px solid transparent}
.nav-outer .nav-item:hover{background:var(--head);text-decoration:none}
.nav-outer .nav-item[aria-current=page]{background:var(--head);border-bottom-color:var(--accent)}
.nav-outer .nav-name{font-weight:600;font-size:.9rem;display:flex;align-items:center;gap:.4rem;white-space:nowrap}
nav .brand .nav-name{font-weight:700}
/* 1.5em: the mark's artwork has empty margin, so 1em reads smaller than the text. */
nav .brand svg.brand-mark{display:block;width:1.5em;height:1.5em}
/* logo colors follow the selected theme, not the OS dark-mode preference. */
nav .brand svg.brand-mark .nd{fill:var(--text)}
nav .brand svg.brand-mark .ring-dim{stroke:var(--border)}
nav .brand svg.brand-mark .auth{stroke:var(--accent)}
.nav-sep{width:1px;height:1.4rem;background:var(--border);margin:0 .3rem;align-self:center}
.nav-menu-toggle{display:none;background:transparent;color:var(--text);border:1px solid var(--border);font-weight:600}
.nav-outer .nav-pending-btn{flex-shrink:0;background:var(--accent);color:var(--on-accent);
box-shadow:0 1px 2px rgba(0,0,0,.06)}
.nav-outer .nav-pending-btn:hover{background:var(--accent);opacity:.9}
.nav-outer .nav-pending-btn[aria-current=page]{border-bottom-color:var(--on-accent)}
.nav-theme-select{flex-shrink:0;align-self:center}
/* the label changes with the theme; a fixed width keeps the buttons beside it from moving */
#theme_switcher{width:5.6rem;text-align:center}
/* below this width the items fold into the Menu button; the brand stays visible */
@media (max-width:1180px){
nav .nav-item:not(.brand),nav .nav-sep{display:none}
.nav-menu-toggle{display:inline-flex}
nav.open .nav-item:not(.brand){display:flex}
}
@media (max-width:520px){
body{padding:.7rem}
.nav-outer{flex-wrap:wrap}
nav{flex-basis:100%}
.nav-outer .nav-item{min-height:44px}
button,input,select,textarea{min-height:44px}
button.btn-sm,.row-menu>summary{min-height:36px}
.table-wrap,table{max-width:100%}
}
/* cards: the Overview grid and every later page built from cards. */
.card-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.9rem;margin:0 0 1rem}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:.8rem 1rem;min-width:0}
.card h2{margin:0 0 .5rem;font-size:1rem}
.card p{margin:.3rem 0}
.card table{border:0;margin:0;border-radius:0}
.card-big{font-size:1.15rem}
.card-list{list-style:none;margin:0;padding:0}
.card-list li{padding:.35rem 0;border-bottom:1px solid var(--border)}
.card-list li:last-child{border-bottom:0}
.banner{background:var(--panel);border:1px solid var(--border);border-left-width:4px;border-radius:8px;padding:.55rem .9rem;margin:0 0 1rem}
.banner.ok{border-left-color:var(--ok)}
.banner.warn{border-left-color:var(--warn)}
.banner.crit{border-left-color:var(--crit)}
table.small th,table.small td{padding:.3rem .5rem;font-size:.9rem}
.kv-table td:first-child{color:var(--muted);white-space:nowrap}
td.ver{white-space:nowrap;font-size:.85rem}
.events li{padding:.3rem 0;overflow-wrap:anywhere}
.ev-time{white-space:nowrap;margin-right:.3rem}
details.card-details{padding:.05rem 1rem}
.card-wide{margin:0 0 1rem}
.meter{display:block;height:.55rem;background:var(--border);border-radius:4px;overflow:hidden;margin:.35rem 0 .5rem}
.meter>i{display:block;height:100%;background:var(--ok)}
.meter.warn>i{background:var(--warn)}
.meter.crit>i{background:var(--crit)}
.meter.mini{display:inline-block;width:5rem;height:.5rem;margin:0 .4rem 0 0;vertical-align:middle}
.scrollbox{max-height:12rem;overflow:auto}
@media (max-width:1180px){.card-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:700px){.card-grid{grid-template-columns:1fr}.card-attn{order:-1}}
/* tabs: one strip above a set of panes; script-built (dnshivedInitTabs) or plain links (tabLinksHTML). */
.tabs{display:flex;gap:.2rem;border-bottom:1px solid var(--border);margin:0 0 1rem;overflow-x:auto;scrollbar-width:thin}
.tabs button,.tabs a.tab-link{font:inherit;flex:0 0 auto;white-space:nowrap;background:none;border:0;
border-bottom:3px solid transparent;border-radius:0;color:var(--muted);padding:.5rem .9rem;cursor:pointer;font-weight:550;text-decoration:none}
.tabs button:hover,.tabs a.tab-link:hover{color:var(--text);opacity:1;text-decoration:none}
.tabs button[aria-selected=true],.tabs a.tab-link[aria-current=page]{color:var(--text);border-bottom-color:var(--accent)}
.tab-host.tabs-ready .tab-pane{display:none}
.tab-host.tabs-ready .tab-pane.active{display:block}
.tab-pane>h2:first-child{margin-top:0}
/* line lists (dnshivedLineLists) */
.line-list{border:1px solid var(--border);border-radius:8px;background:var(--panel);margin:.4rem 0 .8rem}
.line-list-tools{display:flex;gap:.6rem;align-items:center;padding:.4rem .6rem;border-bottom:1px solid var(--border);background:var(--head);border-radius:8px 8px 0 0}
.line-list-tools input{min-width:12rem}
.line-list-row{display:flex;gap:.5rem;align-items:center;padding:.25rem .6rem;border-bottom:1px solid var(--border)}
.line-list-row:last-child{border-bottom:0}
.line-list-row code{flex:1;min-width:0;overflow-wrap:anywhere;font-size:.9rem}
.line-list-row input.edit{flex:1;min-width:0}
button.mini{font-size:.85em;padding:.05rem .5rem;background:transparent;color:var(--text);border:1px solid var(--border)}
button.mini:hover{background:var(--head);opacity:1}
.ll-menu button.danger{color:var(--crit)}
@media (max-width:520px){
table[data-stack]{border:0;background:transparent;border-radius:0}
table[data-stack],table[data-stack] tbody,table[data-stack] tr,table[data-stack] td{display:block;width:auto}
table[data-stack] tr.stack-head{display:none}
table[data-stack] tr{background:var(--panel);border:1px solid var(--border);border-radius:8px;margin:0 0 .6rem;padding:.4rem .7rem}
table[data-stack] td{border:0;padding:.15rem 0;display:flex;gap:.6rem;align-items:baseline;white-space:normal}
table[data-stack] td[data-label]::before{content:attr(data-label);color:var(--muted);min-width:5.5rem;flex:0 0 auto;font-size:.86em}
table[data-stack] td:first-child{font-weight:600}
}
/* view-tabs: pill tabs linking two related pages. */
.view-tabs{display:flex;gap:.3rem;margin:0 0 1rem}
.view-tabs a,.view-tabs .active{padding:.3rem .7rem;border-radius:6px;font-size:.9rem;font-weight:600}
.view-tabs .active{background:var(--accent);color:var(--on-accent)}
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
border-radius:5px;background:var(--accent);color:var(--on-accent);cursor:pointer}
button:hover,input[type=submit]:hover{opacity:.9}
/* btn-sm: a small button inside a table cell; keeps the normal button text colour. */
button.btn-sm{font-size:.85em;padding:.05rem .45rem}
/* btn-quiet: a deliberately plain button for a serious but rare action. */
button.btn-quiet{background:transparent;color:var(--text);border:1px solid var(--warn);font-size:.85em;padding:.2rem .6rem}
button.btn-quiet:hover{background:var(--head);opacity:1}
/* row-menu: the per-row actions menu of the scope list (a details element). */
.row-menu{position:relative;display:inline-block;background:transparent;border:0;box-shadow:none;padding:0;margin:0}
.row-menu>summary{list-style:none;cursor:pointer;user-select:none;width:2rem;text-align:center;padding:.15rem 0;font-weight:400;
border:1px solid var(--border);border-radius:5px;background:var(--panel);color:var(--text);font-size:1.1rem;line-height:1.2}
.row-menu>summary::-webkit-details-marker{display:none}
.row-menu[open]>summary{background:var(--head)}
.row-menu-list{position:fixed;z-index:60;min-width:13rem;background:var(--panel);border:1px solid var(--border);
border-radius:8px;box-shadow:0 6px 20px rgba(0,0,0,.2);padding:.3rem}
.row-menu-list form{margin:0}
.row-menu-list a,.row-menu-list button{display:block;width:100%;box-sizing:border-box;text-align:left;padding:.4rem .6rem;
border:0;border-radius:5px;background:transparent;color:var(--text);font:inherit;text-decoration:none;cursor:pointer}
.row-menu-list a:hover,.row-menu-list button:hover,.row-menu-list a:focus,.row-menu-list button:focus{background:var(--head);outline:none}
.row-menu-list .danger{color:var(--crit)}
/* btn-success for commit-shaped actions, btn-danger for discard/delete. */
button.btn-success{background:var(--ok);border-color:var(--ok);color:var(--on-ok)}
button.btn-danger{background:var(--crit);border-color:var(--crit);color:var(--on-crit)}
/* btn-warn for disable (reversible, VIP released, VLAN stays). */
button.btn-warn{background:var(--warn);border-color:var(--warn);color:var(--on-warn)}
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
.combo-item:hover,.combo-item-active{background:var(--accent);color:var(--on-accent)}
.combo-empty,.combo-more{padding:.3rem .5rem;font-size:.85rem;color:var(--muted)}
.combo-more{border-top:1px solid var(--border);cursor:default}
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
.rogue-badge{background:var(--crit);color:var(--on-crit);font-weight:700;
padding:.1rem .4rem;border-radius:3px;font-size:.82rem}
/* .vip-badge: marks the node holding the mgmt VIP; a location, not a health state. */
.vip-badge{background:var(--accent);color:var(--on-accent);font-weight:700;
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

// tabLinksHTML renders a tab strip whose tabs are links to separate pages.
func tabLinksHTML(items [][2]string, active string) string {
	var b strings.Builder
	b.WriteString(`<div class="tabs" role="tablist">`)
	for _, it := range items {
		cur := ""
		if it[0] == active {
			cur = ` aria-current="page"`
		}
		b.WriteString(`<a class="tab-link" href="` + it[0] + `"` + cur + `>` + it[1] + `</a>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// securityTabs is the strip shared by the three pages of the Security group. The
// menu item leads to /security, so that page is the first tab.
func securityTabs(active string) string {
	return tabLinksHTML([][2]string{
		{"/security", "API tokens"},
		{"/users", "Users &amp; password policy"},
		{"/config/mail", "Mail &amp; reset"},
	}, active)
}

// renderTemplate executes tmpl and logs (rather than panics or 500s on) a
// render failure.
func renderTemplate(w http.ResponseWriter, tmpl *template.Template, data interface{}, name string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("[ERROR] render %s page: %v", name, err)
	}
}
