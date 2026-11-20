// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

// footerLayoutStyle styles the user-arranged footer: hidden fields, the
// resize handles, the drop marker and the right-click menu.
const footerLayoutStyle = `
.appfoot [data-f].ft-user-off,.appfoot [data-f].ft-auto-off{display:none}
.appfoot [data-f].ft-dragging{position:relative;z-index:6;background:var(--head);box-shadow:0 2px 8px rgba(0,0,0,.3);border-radius:4px;opacity:.9;cursor:grabbing}
.appfoot .ft-grips{position:absolute;inset:0;pointer-events:none}
.appfoot .ft-grip{position:absolute;top:0;width:9px;height:100%;margin-left:-5px;cursor:col-resize;pointer-events:auto;touch-action:none}
.appfoot .ft-grip::after{content:"";position:absolute;top:22%;bottom:22%;left:4px;width:2px;border-radius:1px;background:var(--muted);opacity:.45;transition:opacity .15s,background .15s}
.appfoot .ft-grip:hover::after,.appfoot .ft-grip.on::after{opacity:.95;background:var(--accent)}
.appfoot .ft-drop{position:absolute;top:12%;bottom:12%;width:3px;margin-left:-2px;border-radius:2px;background:var(--accent);pointer-events:none}
.ft-menu{position:fixed;z-index:90;min-width:15.5rem;background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.3);padding:.4rem;font-size:13.5px;line-height:1.3}
.ft-menu-h{font-weight:650;color:var(--muted);padding:.2rem .5rem .35rem;font-size:.85em;text-transform:uppercase;letter-spacing:.04em}
.ft-menu-row{display:flex;align-items:center;gap:.3rem;padding:.1rem .3rem;border-radius:5px}
.ft-menu-row:hover{background:var(--head)}
.ft-menu-row label{flex:1;display:flex;align-items:center;gap:.5rem;cursor:pointer;padding:.25rem .2rem}
.ft-menu-row input[type=checkbox]{min-height:0;width:1rem;height:1rem;margin:0}
.ft-menu button{min-height:0;background:transparent;color:var(--text);border:1px solid var(--border);border-radius:5px;padding:.1rem .45rem;font:inherit;cursor:pointer}
.ft-menu button:hover:not(:disabled){background:var(--accent);color:var(--on-accent);border-color:var(--accent)}
.ft-menu button:disabled{opacity:.35;cursor:default}
.ft-menu .ft-menu-reset{margin:.35rem .3rem .1rem;width:calc(100% - .6rem);padding:.3rem .5rem}
.ft-menu .nr{color:var(--muted);font-size:.85em}
.ft-menu-name{flex:1;padding:.25rem .2rem}
.ft-menu .ft-add{display:block;width:calc(100% - .6rem);margin:.1rem .3rem;text-align:left;padding:.25rem .5rem;border-color:transparent}
.ft-menu .ft-add:disabled{opacity:.4;cursor:default}
.ft-menu .ft-add:hover:not(:disabled){background:var(--accent)}
`

// footerLayoutScriptHTML lets the footer be arranged by the user: a right click
// opens a menu to show or hide fields and move them, a field can be dragged to
// another place, and the edge between two fields can be dragged to resize the
// left one. The arrangement is kept per browser in localStorage
// ("dnshived-footer"). A field that has no room is dropped automatically, in a
// fixed order, instead of being squeezed. All elements are built with the DOM
// API, no markup is composed from strings.
const footerLayoutScriptHTML = `
<script>
(function(){
var IDS=['title','upd','state','nodes','dhcp','rev','ev','load','nload','uptime','clock','date'];
var NEW=['load','nload','uptime','clock','date'];
var LABELS={title:'Version',upd:'Update check',state:'Cluster state',nodes:'Nodes',dhcp:'DHCP',rev:'Config revision',ev:'Newest event',load:'Load, all cores combined',nload:'Load per core',uptime:'Uptime (shortest)',clock:'Clock',date:'Date'};
var DROP=['date','uptime','nload','upd','ev','dhcp','rev','clock','load','title'];
var KEY='dnshived-footer', MINW=3, MAXW=60, DRAG=6;
function def(){return {order:IDS.slice(),off:NEW.slice(),w:{}};}
function validate(c){
  var out=def();
  if(!c||typeof c!=='object') return out;
  var known=Array.isArray(c.order)?c.order.filter(function(i,k,a){return IDS.indexOf(i)>=0&&a.indexOf(i)===k;}):[];
  if(known.length>0){
    var added=IDS.filter(function(i){return known.indexOf(i)<0;});
    out.order=known.concat(added);
    out.off=added.filter(function(i){return NEW.indexOf(i)>=0;});
    if(Array.isArray(c.off)) out.off=out.off.concat(c.off.filter(function(i,k,a){return IDS.indexOf(i)>=0&&a.indexOf(i)===k&&out.off.indexOf(i)<0;}));
  }else if(Array.isArray(c.off)){
    out.off=NEW.concat(c.off.filter(function(i,k,a){return IDS.indexOf(i)>=0&&a.indexOf(i)===k&&NEW.indexOf(i)<0;}));
  }
  if(c.w&&typeof c.w==='object') IDS.forEach(function(i){var v=c.w[i]; if(typeof v==='number'&&isFinite(v)&&v>=MINW&&v<=MAXW) out.w[i]=Math.round(v*100)/100;});
  return out;
}
function moveBy(order,id,d){
  var i=order.indexOf(id), j=i+d;
  if(i<0||j<0||j>=order.length) return order.slice();
  var o=order.slice(); o.splice(i,1); o.splice(j,0,id); return o;
}
function placeBefore(order,id,beforeId){
  var o=order.filter(function(x){return x!==id;});
  var k=beforeId?o.indexOf(beforeId):-1;
  o.splice(k<0?o.length:k,0,id); return o;
}
function dropOrder(visible){ return DROP.filter(function(i){return visible.indexOf(i)>=0;}); }
window.dnshivedFooter={validate:validate,moveBy:moveBy,placeBefore:placeBefore,dropOrder:dropOrder,IDS:IDS};
var f=document.getElementById('appfoot');
if(!f||typeof document.createElement!=='function') return;

function load(){ try{ return validate(JSON.parse(localStorage.getItem(KEY)||'null')); }catch(e){ return def(); } }
function save(){ try{ localStorage.setItem(KEY,JSON.stringify(cfg)); }catch(e){} }
var cfg=load();
function field(id){ return f.querySelector('[data-f="'+id+'"]'); }
function px(){ return parseFloat(getComputedStyle(f).fontSize)||13; }

var grips=document.createElement('div'); grips.className='ft-grips'; f.appendChild(grips);
var queued=false, dragging=false;
function visible(id){ var e=field(id); return e&&!e.classList.contains('ft-user-off')&&!e.classList.contains('ft-auto-off'); }

function layoutGrips(){
  while(grips.firstChild) grips.removeChild(grips.firstChild);
  var order=cfg.order.filter(visible), fr=f.getBoundingClientRect();
  order.slice(0,-1).forEach(function(id){
    var r=field(id).getBoundingClientRect(), g=document.createElement('span');
    g.className='ft-grip'; g.title='Drag to resize this field'; g.setAttribute('data-for',id);
    g.style.left=(r.right-fr.left+(parseFloat(getComputedStyle(f).columnGap)||0)/2)+'px';
    g.addEventListener('pointerdown',function(e){ startResize(e,id,g); });
    g.addEventListener('dblclick',function(e){ e.preventDefault(); delete cfg.w[id]; save(); apply(); });
    grips.appendChild(g);
  });
}
function fit(){
  IDS.forEach(function(id){ field(id).classList.remove('ft-auto-off'); });
  var order=dropOrder(IDS.filter(function(i){return visible(i);})), n=0;
  while(f.scrollWidth>f.clientWidth+1&&n<order.length){ field(order[n]).classList.add('ft-auto-off'); n++; }
}
function apply(){
  IDS.forEach(function(id){
    var e=field(id); if(!e) return;
    e.style.order=String(cfg.order.indexOf(id));
    e.classList.toggle('ft-user-off',cfg.off.indexOf(id)>=0);
    if(cfg.w[id]){ e.style.width=cfg.w[id]+'em'; e.classList.add('ft-fixed'); } else { e.style.width=''; e.classList.remove('ft-fixed'); }
  });
  fit(); layoutGrips();
  if(menu) fillMenu();
}
function schedule(){ if(queued||dragging) return; queued=true; (window.requestAnimationFrame||setTimeout)(function(){ queued=false; fit(); layoutGrips(); if(menu) fillMenu(); }); }

function startResize(e,id,g){
  if(e.button!==undefined&&e.button!==0) return;
  e.preventDefault(); e.stopPropagation();
  var el=field(id), x0=e.clientX, w0=el.getBoundingClientRect().width, fs=px();
  dragging=true; g.classList.add('on');
  try{ g.setPointerCapture(e.pointerId); }catch(x){}
  function mv(ev){
    var em=Math.max(MINW,Math.min(MAXW,(w0+ev.clientX-x0)/fs));
    cfg.w[id]=Math.round(em*100)/100; el.style.width=cfg.w[id]+'em'; el.classList.add('ft-fixed');
    var fr=f.getBoundingClientRect(), r=el.getBoundingClientRect();
    g.style.left=(r.right-fr.left+(parseFloat(getComputedStyle(f).columnGap)||0)/2)+'px';
  }
  function up(){
    g.removeEventListener('pointermove',mv); g.removeEventListener('pointerup',up); g.removeEventListener('pointercancel',up);
    g.classList.remove('on'); dragging=false; save(); fit(); layoutGrips();
  }
  g.addEventListener('pointermove',mv); g.addEventListener('pointerup',up); g.addEventListener('pointercancel',up);
}

var press=null, marker=null;
f.addEventListener('pointerdown',function(e){
  if((e.button!==undefined&&e.button!==0)||e.target.closest('.ft-grips')) return;
  var el=e.target.closest('[data-f]'); if(!el) return;
  press={id:el.getAttribute('data-f'),el:el,x:e.clientX,on:false,pid:e.pointerId,before:null};
});
function targetBefore(x,id){
  var order=cfg.order.filter(function(i){return i!==id&&visible(i);}), before=null;
  for(var k=0;k<order.length;k++){ var r=field(order[k]).getBoundingClientRect(); if(x<r.left+r.width/2){ before=order[k]; break; } }
  return before;
}
f.addEventListener('pointermove',function(e){
  if(!press) return;
  var dx=e.clientX-press.x;
  if(!press.on){ if(Math.abs(dx)<DRAG) return; press.on=true; dragging=true; press.el.classList.add('ft-dragging'); try{ f.setPointerCapture(press.pid); }catch(x){} }
  press.el.style.transform='translateX('+dx+'px)';
  press.before=targetBefore(e.clientX,press.id);
  if(!marker){ marker=document.createElement('div'); marker.className='ft-drop'; f.appendChild(marker); }
  var fr=f.getBoundingClientRect(), left;
  if(press.before){ left=field(press.before).getBoundingClientRect().left-fr.left-(parseFloat(getComputedStyle(f).columnGap)||0)/2; }
  else { var vis=cfg.order.filter(function(i){return i!==press.id&&visible(i);}); var lastEl=vis.length?field(vis[vis.length-1]):null; left=lastEl?lastEl.getBoundingClientRect().right-fr.left+(parseFloat(getComputedStyle(f).columnGap)||0)/2:0; }
  marker.style.left=left+'px';
});
function endPress(commit){
  if(!press) return;
  var p=press; press=null;
  if(!p.on) return;
  p.el.classList.remove('ft-dragging'); p.el.style.transform='';
  if(marker&&marker.parentNode) marker.parentNode.removeChild(marker); marker=null;
  dragging=false;
  var swallow=function(ev){ ev.stopPropagation(); ev.preventDefault(); };
  f.addEventListener('click',swallow,true); setTimeout(function(){ f.removeEventListener('click',swallow,true); },0);
  if(commit){ cfg.order=placeBefore(cfg.order,p.id,p.before); save(); }
  apply();
}
f.addEventListener('pointerup',function(){ endPress(true); });
f.addEventListener('pointercancel',function(){ endPress(false); });

var menu=null, menuAt=null;
function closeMenu(){ if(menu&&menu.parentNode) menu.parentNode.removeChild(menu); menu=null; document.removeEventListener('pointerdown',outside,true); document.removeEventListener('keydown',esc,true); }
function outside(e){ if(menu&&!menu.contains(e.target)) closeMenu(); }
function esc(e){ if(e.key==='Escape') closeMenu(); }
function btn(text,title,disabled,fn){ var b=document.createElement('button'); b.type='button'; b.textContent=text; b.title=title; b.setAttribute('aria-label',title); b.disabled=!!disabled; b.addEventListener('click',fn); return b; }
function section(text){ var h=document.createElement('div'); h.className='ft-menu-h'; h.textContent=text; menu.appendChild(h); }
function fillMenu(){
  var keep=menu.querySelector('button:focus')?menu.querySelector('button:focus').getAttribute('data-id'):null;
  while(menu.firstChild) menu.removeChild(menu.firstChild);
  section('In the footer');
  cfg.order.filter(function(id){return cfg.off.indexOf(id)<0;}).forEach(function(id,i,shown){
    var row=document.createElement('div'); row.className='ft-menu-row';
    var lab=document.createElement('span'); lab.className='ft-menu-name'; lab.textContent=LABELS[id];
    var fe=field(id); if(fe&&fe.classList.contains('ft-auto-off')){ var nr=document.createElement('span'); nr.className='nr'; nr.textContent=' (no room)'; lab.appendChild(nr); }
    row.appendChild(lab);
    row.appendChild(btn('◀','Move '+LABELS[id]+' left',cfg.order.indexOf(id)===0,function(){ cfg.order=moveBy(cfg.order,id,-1); save(); apply(); }));
    row.appendChild(btn('▶','Move '+LABELS[id]+' right',cfg.order.indexOf(id)===cfg.order.length-1,function(){ cfg.order=moveBy(cfg.order,id,1); save(); apply(); }));
    var rm=btn('✕','Remove '+LABELS[id]+' from the footer',false,function(){ if(cfg.off.indexOf(id)<0) cfg.off.push(id); save(); apply(); }); rm.setAttribute('data-id',id);
    row.appendChild(rm);
    menu.appendChild(row);
  });
  section('Add to the footer');
  cfg.order.forEach(function(id){
    var shown=cfg.off.indexOf(id)<0;
    var b=btn((shown?'✓ ':'+ ')+LABELS[id],shown?LABELS[id]+' is in the footer already':'Add '+LABELS[id]+' to the footer',shown,function(){ var k=cfg.off.indexOf(id); if(k>=0) cfg.off.splice(k,1); cfg.order=placeBefore(cfg.order,id,null); save(); apply(); });
    b.className='ft-add'; b.setAttribute('data-id','add-'+id); menu.appendChild(b);
  });
  var rs=btn('Reset footer','Show the default fields in the default order and widths',false,function(){ cfg=def(); try{ localStorage.removeItem(KEY); }catch(e){} apply(); });
  rs.className='ft-menu-reset'; menu.appendChild(rs);
  if(keep){ var k=menu.querySelector('button[data-id="'+keep+'"]'); if(k&&!k.disabled) k.focus(); }
  placeMenu();
}
function placeMenu(){
  if(!menu||!menuAt) return;
  var fr=f.getBoundingClientRect(), w=menu.offsetWidth, h=menu.offsetHeight;
  menu.style.left=Math.max(8,Math.min(menuAt.x,window.innerWidth-w-8))+'px';
  menu.style.top=Math.max(8,fr.top-h-8)+'px';
}
f.addEventListener('contextmenu',function(e){
  e.preventDefault(); closeMenu();
  menu=document.createElement('div'); menu.className='ft-menu'; menu.setAttribute('role','menu');
  menu.addEventListener('contextmenu',function(ev){ ev.preventDefault(); });
  menuAt={x:e.clientX,y:e.clientY};
  document.body.appendChild(menu); fillMenu();
  document.addEventListener('pointerdown',outside,true); document.addEventListener('keydown',esc,true);
  var first=menu.querySelector('button:not(:disabled)'); if(first) first.focus();
});

window.addEventListener('resize',schedule);
window.addEventListener('storage',function(e){ if(e.key===KEY){ cfg=load(); apply(); } });
if(window.MutationObserver) new MutationObserver(function(ms){
  for(var i=0;i<ms.length;i++){ if(!grips.contains(ms[i].target)&&ms[i].target!==marker&&!(marker&&marker.contains(ms[i].target))&&ms[i].target!==f) { schedule(); return; } }
}).observe(f,{childList:true,subtree:true,characterData:true});
apply();
})();
</script>`
