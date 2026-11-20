// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

// overviewRasterScriptHTML lets the Overview be arranged on a 12 column grid:
// every card carries data-w, can be moved and resized in whole grid cells, and
// can be shown or hidden. The arrangement is kept per browser in localStorage
// ("dnshived-overview"). Below 1181 px the page keeps its stacked layout and
// ignores the arrangement. Elements are built with the DOM API only.
const overviewRasterScriptHTML = `
<style>
.ov-h1{display:flex;align-items:center;gap:1rem}
.ov-h1 .ov-arrange{margin-left:auto;font-size:var(--fs-sm);font-weight:400;min-height:0;padding:.2rem .7rem}
.card-grid.ov-on{grid-template-columns:repeat(12,minmax(0,1fr));grid-template-rows:none;grid-auto-rows:1.5rem;gap:0}
.card-grid.ov-on>.card{margin:.45rem;height:auto;position:relative}
.card-grid.ov-on>.card[hidden]{display:none}
.card-grid.ov-on>.card-wide{display:flex;flex-direction:column}
.card-grid.ov-on>.card-wide .scrollbox{flex:1;height:auto;max-height:none;min-height:0}
.ov-edit>.card{outline:2px dashed var(--accent);outline-offset:-2px}
.ov-bar{position:absolute;left:0;right:0;top:0;height:1.8rem;cursor:grab;touch-action:none;z-index:4;background:var(--accent);opacity:.18;border-radius:10px 10px 0 0}
.ov-bar:hover{opacity:.3}
.ov-rs{position:absolute;right:0;bottom:0;width:1.3rem;height:1.3rem;cursor:nwse-resize;touch-action:none;z-index:5;background:linear-gradient(135deg,transparent 50%,var(--accent) 50%);border-radius:0 0 10px 0}
.ov-moving{opacity:.85;box-shadow:0 6px 20px rgba(0,0,0,.35);z-index:6}
.ov-menu{position:fixed;z-index:90;min-width:15rem;background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.3);padding:.4rem;font-size:13.5px;line-height:1.3}
.ov-menu .ft-menu-h{font-weight:650;color:var(--muted);padding:.2rem .5rem .35rem;font-size:.85em;text-transform:uppercase;letter-spacing:.04em}
.ov-menu-row{display:flex;align-items:center;gap:.3rem;padding:.1rem .3rem;border-radius:5px}
.ov-menu-row:hover{background:var(--head)}
.ov-menu-name{flex:1;padding:.25rem .2rem}
.ov-menu button{min-height:0;background:transparent;color:var(--text);border:1px solid var(--border);border-radius:5px;padding:.1rem .45rem;font:inherit;cursor:pointer}
.ov-menu button:hover:not(:disabled){background:var(--accent);color:var(--on-accent);border-color:var(--accent)}
.ov-menu button:disabled{opacity:.4;cursor:default}
.ov-menu .ov-add{display:block;width:calc(100% - .6rem);margin:.1rem .3rem;text-align:left;padding:.25rem .5rem;border-color:transparent}
.ov-menu .ov-wide{display:block;width:calc(100% - .6rem);margin:.35rem .3rem .1rem;padding:.3rem .5rem}
</style>
<script>
(function(){
var IDS=['nodes','scopes','probes','attn','paths','health','events'];
var LABELS={nodes:'Cluster nodes',scopes:'Scopes',probes:'Probes',attn:'Needs attention',paths:'Cluster paths',health:'Health checks',events:'Recent events'};
var DEF={nodes:{x:0,y:0,w:4,h:14},scopes:{x:4,y:0,w:4,h:14},probes:{x:8,y:0,w:4,h:14},attn:{x:0,y:14,w:4,h:16},paths:{x:4,y:14,w:4,h:16},health:{x:8,y:14,w:4,h:16},events:{x:0,y:30,w:12,h:14}};
var COLS=12,MINW=2,MINH=4,MAXH=60,KEY='dnshived-overview',MIN_WIDTH=1181;
function def(){var l={};IDS.forEach(function(i){l[i]={x:DEF[i].x,y:DEF[i].y,w:DEF[i].w,h:DEF[i].h}});return {l:l,off:[]};}
function int(v){return typeof v==='number'&&isFinite(v)&&Math.floor(v)===v;}
function validate(c){
  var out=def();
  if(!c||typeof c!=='object') return out;
  if(c.l&&typeof c.l==='object') IDS.forEach(function(i){
    var r=c.l[i]; if(!r||!int(r.x)||!int(r.y)||!int(r.w)||!int(r.h)) return;
    if(r.w<MINW||r.w>COLS||r.x<0||r.x+r.w>COLS||r.y<0||r.y>200||r.h<MINH||r.h>MAXH) return;
    out.l[i]={x:r.x,y:r.y,w:r.w,h:r.h};
  });
  if(Array.isArray(c.off)) out.off=c.off.filter(function(i,k,a){return IDS.indexOf(i)>=0&&a.indexOf(i)===k;});
  return out;
}
function hit(a,b){return a.x<b.x+b.w&&b.x<a.x+a.w&&a.y<b.y+b.h&&b.y<a.y+a.h;}
function resolve(l,off,first){
  var ids=IDS.filter(function(i){return off.indexOf(i)<0;});
  ids.sort(function(a,b){
    if(a===first) return -1; if(b===first) return 1;
    return l[a].y-l[b].y||l[a].x-l[b].x;
  });
  var placed=[],out={};
  ids.forEach(function(i){
    var r={x:l[i].x,y:l[i].y,w:l[i].w,h:l[i].h},moved=true;
    while(moved){
      moved=false;
      for(var k=0;k<placed.length;k++) if(hit(r,placed[k])){ r.y=placed[k].y+placed[k].h; moved=true; }
    }
    placed.push(r); out[i]=r;
  });
  IDS.forEach(function(i){ if(!out[i]) out[i]=l[i]; });
  return out;
}
window.dnshivedOverview={validate:validate,resolve:resolve,IDS:IDS,def:def};
var g=document.querySelector('.card-grid');
if(!g||typeof document.createElement!=='function') return;

function load(){ try{ return validate(JSON.parse(localStorage.getItem(KEY)||'null')); }catch(e){ return def(); } }
function save(){ try{ localStorage.setItem(KEY,JSON.stringify(cfg)); }catch(e){} }
var cfg=load(),editing=false,menu=null;
function widget(i){ return g.querySelector('[data-w="'+i+'"]'); }
function rowPx(){ return (parseFloat(getComputedStyle(document.documentElement).fontSize)||14.5)*1.5; }
function raster(){ return window.innerWidth>=MIN_WIDTH; }

function fitEvents(){
  var c=widget('events'); if(!c) return;
  if(raster()){ c.style.height=''; return; }
  var f=document.getElementById('appfoot'),fh=f?f.offsetHeight:0;
  var top=c.getBoundingClientRect().top;
  c.style.height=Math.max(180,window.innerHeight-top-fh-20)+'px';
}
function decorate(){
  IDS.forEach(function(i){
    var w=widget(i); if(!w) return;
    var bar=w.querySelector(':scope>.ov-bar'),rs=w.querySelector(':scope>.ov-rs');
    if(editing&&raster()){
      if(!bar){ bar=document.createElement('div'); bar.className='ov-bar'; bar.title='Drag to move '+LABELS[i]; bar.addEventListener('pointerdown',function(e){ start(e,i,'move'); }); w.appendChild(bar); }
      if(!rs){ rs=document.createElement('div'); rs.className='ov-rs'; rs.title='Drag to resize '+LABELS[i]; rs.addEventListener('pointerdown',function(e){ start(e,i,'size'); }); w.appendChild(rs); }
    }else{ if(bar) bar.remove(); if(rs) rs.remove(); }
  });
}
function apply(){
  var on=raster();
  g.classList.toggle('ov-on',on); g.classList.toggle('ov-edit',on&&editing);
  var l=on?resolve(cfg.l,cfg.off,null):null;
  IDS.forEach(function(i){
    var w=widget(i); if(!w) return;
    var off=on&&cfg.off.indexOf(i)>=0;
    if(off) w.setAttribute('hidden',''); else w.removeAttribute('hidden');
    if(on){ var r=l[i]; w.style.gridColumn=(r.x+1)+' / span '+r.w; w.style.gridRow=(r.y+1)+' / span '+r.h; }
    else{ w.style.gridColumn=''; w.style.gridRow=''; }
  });
  decorate(); fitEvents();
  if(menu) fillMenu();
}
var drag=null;
function start(e,id,mode){
  if(e.button!==undefined&&e.button!==0) return;
  e.preventDefault();
  var gr=g.getBoundingClientRect(), r=cfg.l[id]||DEF[id];
  drag={id:id,mode:mode,x0:e.clientX,y0:e.clientY,r:{x:r.x,y:r.y,w:r.w,h:r.h},cw:gr.width/COLS,rh:rowPx(),el:widget(id)};
  var el=drag.el; el.classList.add('ov-moving');
  try{ e.target.setPointerCapture(e.pointerId); }catch(x){}
  document.addEventListener('pointermove',move); document.addEventListener('pointerup',end); document.addEventListener('pointercancel',end);
}
function move(e){
  if(!drag) return;
  var dx=Math.round((e.clientX-drag.x0)/drag.cw), dy=Math.round((e.clientY-drag.y0)/drag.rh), r=drag.r, n={x:r.x,y:r.y,w:r.w,h:r.h};
  if(drag.mode==='move'){ n.x=Math.max(0,Math.min(COLS-r.w,r.x+dx)); n.y=Math.max(0,r.y+dy); }
  else{ n.w=Math.max(MINW,Math.min(COLS-r.x,r.w+dx)); n.h=Math.max(MINH,Math.min(MAXH,r.h+dy)); }
  cfg.l[drag.id]=n;
  var l=resolve(cfg.l,cfg.off,drag.id);
  IDS.forEach(function(i){ var w=widget(i); if(!w||cfg.off.indexOf(i)>=0) return; var q=l[i]; w.style.gridColumn=(q.x+1)+' / span '+q.w; w.style.gridRow=(q.y+1)+' / span '+q.h; });
}
function end(){
  if(!drag) return;
  document.removeEventListener('pointermove',move); document.removeEventListener('pointerup',end); document.removeEventListener('pointercancel',end);
  drag.el.classList.remove('ov-moving');
  cfg.l=resolve(cfg.l,cfg.off,drag.id); drag=null; save(); apply();
}

function closeMenu(){ if(menu&&menu.parentNode) menu.parentNode.removeChild(menu); menu=null; editing=false; document.removeEventListener('pointerdown',outside,true); document.removeEventListener('keydown',esc,true); apply(); }
function outside(e){ if(menu&&!menu.contains(e.target)&&e.target.id!=='ov-arrange'&&!e.target.closest('.ov-bar,.ov-rs')) closeMenu(); }
function esc(e){ if(e.key==='Escape') closeMenu(); }
function btn(text,title,disabled,fn){ var b=document.createElement('button'); b.type='button'; b.textContent=text; b.title=title; b.setAttribute('aria-label',title); b.disabled=!!disabled; b.addEventListener('click',fn); return b; }
function section(t){ var h=document.createElement('div'); h.className='ft-menu-h'; h.textContent=t; menu.appendChild(h); }
function fillMenu(){
  while(menu.firstChild) menu.removeChild(menu.firstChild);
  section('On the overview');
  IDS.filter(function(i){return cfg.off.indexOf(i)<0;}).forEach(function(id){
    var row=document.createElement('div'); row.className='ov-menu-row';
    var n=document.createElement('span'); n.className='ov-menu-name'; n.textContent=LABELS[id]; row.appendChild(n);
    row.appendChild(btn('✕','Hide '+LABELS[id],false,function(){ cfg.off.push(id); save(); apply(); }));
    menu.appendChild(row);
  });
  section('Add to the overview');
  IDS.forEach(function(id){
    var shown=cfg.off.indexOf(id)<0;
    var b=btn((shown?'✓ ':'+ ')+LABELS[id],shown?LABELS[id]+' is on the overview already':'Show '+LABELS[id],shown,function(){
      cfg.off.splice(cfg.off.indexOf(id),1); cfg.l[id]={x:0,y:200,w:DEF[id].w,h:DEF[id].h}; cfg.l=resolve(cfg.l,cfg.off,id); save(); apply();
    });
    b.className='ov-add'; menu.appendChild(b);
  });
  var rs=btn('Reset the overview','Show every widget at its default place and size',false,function(){ cfg=def(); try{ localStorage.removeItem(KEY); }catch(e){} apply(); });
  rs.className='ov-wide'; menu.appendChild(rs);
  var done=btn('Done','Leave arrange mode',false,closeMenu); done.className='ov-wide'; menu.appendChild(done);
  placeMenu();
}
function placeMenu(){
  var b=document.getElementById('ov-arrange'); if(!menu||!b) return;
  var r=b.getBoundingClientRect(), w=menu.offsetWidth;
  menu.style.left=Math.max(8,Math.min(r.right-w,window.innerWidth-w-8))+'px';
  menu.style.top=(r.bottom+6)+'px';
}
var ab=document.getElementById('ov-arrange');
if(ab) ab.addEventListener('click',function(){
  if(menu){ closeMenu(); return; }
  if(!raster()){ ab.title='The arrangement needs a window at least '+MIN_WIDTH+' px wide'; return; }
  editing=true; menu=document.createElement('div'); menu.className='ov-menu'; menu.setAttribute('role','menu');
  document.body.appendChild(menu); apply();
  document.addEventListener('pointerdown',outside,true); document.addEventListener('keydown',esc,true);
});
window.addEventListener('resize',function(){ if(menu&&!raster()) closeMenu(); else apply(); });
document.addEventListener('dnshived-pager',fitEvents);
window.addEventListener('storage',function(e){ if(e.key===KEY){ cfg=load(); apply(); } });
apply();
})();
</script>`
