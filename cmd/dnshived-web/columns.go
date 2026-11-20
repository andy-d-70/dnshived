// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

// columnsStyle styles the drag handle and the reset control of resizable
// list-table columns.
const columnsStyle = `
.col-grip{position:absolute;top:0;right:0;width:9px;height:100%;cursor:col-resize;touch-action:none;z-index:3}
.col-grip::after{content:"";position:absolute;top:20%;bottom:20%;right:4px;width:2px;border-radius:1px;background:var(--accent);opacity:0;transition:opacity .15s}
th:hover>.col-grip::after,.col-grip.on::after{opacity:.9}
body.col-resizing,body.col-resizing *{cursor:col-resize!important;user-select:none!important}
th.col-dragging{opacity:.55;background:var(--head)}
.col-drop{position:fixed;width:3px;margin-left:-2px;border-radius:2px;background:var(--accent);z-index:70;pointer-events:none}
body.col-moving,body.col-moving *{cursor:grabbing!important;user-select:none!important}
.cols-reset{display:none;background:var(--panel);border:1px solid var(--accent);border-radius:5px;color:var(--accent);cursor:pointer;font:inherit;font-size:var(--fs-md);font-weight:600;line-height:1;min-height:1.7rem;padding:.2rem .5rem}
.cols-reset:hover{background:var(--accent);color:var(--on-accent)}
table.cols-custom .cols-reset{display:inline-block}
.cols-reset-bar{display:none;text-align:right;margin:.2rem 0}
table.cols-custom + .cols-reset-bar{display:block}
`

// columnsScriptHTML lets every list-table's columns be resized by dragging the
// edge of a header cell. The widths are kept per browser (localStorage, one
// entry per page path, table position and column count) as percentages that
// add up to 100, so the table keeps its width; a missing or malformed entry
// leaves the built-in widths. A header cell can also be dragged to another
// place (a second entry holds the order; columns without header text or with a
// control in the header stay where they are). A reset control shows while a
// layout is saved.
const columnsScriptHTML = `<script>
(function(){
var MIN=3, PREFIX='dnshived-cols|', OPREFIX='dnshived-colorder|', DRAG=6;
function validate(w,n){
  if(!Array.isArray(w)||w.length!==n) return null;
  var s=0;
  for(var i=0;i<n;i++){ if(typeof w[i]!=='number'||!isFinite(w[i])||w[i]<MIN||w[i]>100) return null; s+=w[i]; }
  return Math.abs(s-100)<=1.5?w:null;
}
function move(w,i,d){
  var a=w[i], b=w[i+1];
  if(d>0) d=Math.min(d,b-MIN); else d=-Math.min(-d,a-MIN);
  var out=w.slice(); out[i]=a+d; out[i+1]=b-d; return out;
}
function moveOrig(w,a,b,d){
  var x=w[a], y=w[b];
  if(d>0) d=Math.min(d,y-MIN); else d=-Math.min(-d,x-MIN);
  var out=w.slice(); out[a]=x+d; out[b]=y-d; return out;
}
function normalize(px){
  var s=0,i; for(i=0;i<px.length;i++) s+=px[i];
  if(!(s>0)) return null;
  return px.map(function(p){return p/s*100;});
}
function identity(n){ var o=[]; for(var i=0;i<n;i++) o.push(i); return o; }
function validOrder(o,n,movable){
  if(!Array.isArray(o)||o.length!==n) return null;
  var seen={};
  for(var i=0;i<n;i++){ if(typeof o[i]!=='number'||o[i]%1!==0||o[i]<0||o[i]>=n||seen[o[i]]) return null; seen[o[i]]=1; }
  for(var j=0;j<n;j++){ if(!movable[j]&&o[j]!==j) return null; }
  return o;
}
function reorder(ord,movable,id,before){
  if(!movable[id]) return ord.slice();
  var slots=[],list=[];
  ord.forEach(function(o,pos){ if(movable[o]){ slots.push(pos); list.push(o); } });
  list=list.filter(function(o){return o!==id;});
  var k=before===null||before===undefined?-1:list.indexOf(before);
  list.splice(k<0?list.length:k,0,id);
  var out=ord.slice(); slots.forEach(function(pos,idx){ out[pos]=list[idx]; });
  return out;
}
window.dnshivedCols={validate:validate,move:move,moveOrig:moveOrig,normalize:normalize,identity:identity,validOrder:validOrder,reorder:reorder,MIN:MIN};
if(typeof document==='undefined'||!document.querySelectorAll) return;

function store(k,v){ try{ if(v===null) localStorage.removeItem(k); else localStorage.setItem(k,JSON.stringify(v)); }catch(e){} }
function load(k){ try{ return JSON.parse(localStorage.getItem(k)||'null'); }catch(e){ return null; } }

function bind(t,index){
  if(t.__cols) return;
  var tr=t.querySelector('tr'); if(!tr) return;
  var cells=[].slice.call(tr.children);
  if(cells.length<2||cells.some(function(c){return c.tagName!=='TH'||c.colSpan>1;})) return;
  var n=cells.length, tail=location.pathname+'|'+index+'|'+n, k=PREFIX+tail, ko=OPREFIX+tail;
  var cg=t.querySelector(':scope>colgroup'), made=false;
  if(!cg){ cg=document.createElement('colgroup'); for(var i=0;i<n;i++) cg.appendChild(document.createElement('col')); t.insertBefore(cg,t.firstChild); made=true; }
  if(cg.children.length!==n){ if(made) cg.remove(); return; }
  var cols=[].slice.call(cg.children);
  var movable=cells.map(function(c){ return c.textContent.trim()!==''&&!c.querySelector('input,select,button,textarea'); });
  var orig={layout:t.style.tableLayout, widths:cols.map(function(c){return c.style.width;})};
  var st={k:k,n:n,cols:cols,cells:cells,orig:orig,w:null,ord:identity(n),movable:movable};
  t.__cols=st;
  [].forEach.call(t.rows,function(r){
    var cs=[].slice.call(r.children);
    if(cs.length===n&&cs.every(function(c){return !(c.colSpan>1);})) cs.forEach(function(c,i){ c.setAttribute('data-oc',String(i)); });
  });
  function isTable(){ return getComputedStyle(t).display==='table'; }
  function custom(){ var d=false; for(var i=0;i<n;i++) if(st.ord[i]!==i) d=true; t.classList.toggle('cols-custom',!!st.w||d); }

  function apply(w){
    st.w=w; t.style.tableLayout='fixed';
    cols.forEach(function(c,o){ c.style.width=w[o].toFixed(3)+'%'; });
    custom();
  }
  function applyOrder(ord){
    st.ord=ord;
    [].forEach.call(t.rows,function(r){
      var cs=[].slice.call(r.children);
      if(cs.length!==n||!cs.every(function(c){return c.hasAttribute('data-oc');})) return;
      var by={}; cs.forEach(function(c){ by[c.getAttribute('data-oc')]=c; });
      ord.forEach(function(o){ r.appendChild(by[o]); });
    });
    ord.forEach(function(o){ cg.appendChild(cols[o]); });
    grips(); custom();
  }
  function reset(){
    st.w=null; store(k,null); store(ko,null);
    t.style.tableLayout=orig.layout;
    cols.forEach(function(c,o){ c.style.width=orig.widths[o]; });
    applyOrder(identity(n));
  }
  st.reset=reset;

  var last=cells[n-1];
  if(last.textContent.trim()===''&&!last.querySelector('*')){
    var rb=document.createElement('button'); rb.type='button'; rb.className='cols-reset'; rb.textContent='\u21d4';
    rb.title='Reset the column widths and order of this table'; rb.setAttribute('aria-label',rb.title);
    rb.addEventListener('click',function(e){ e.preventDefault(); reset(); });
    last.appendChild(rb);
  } else if(t.parentNode){
    var bar=document.createElement('div'); bar.className='cols-reset-bar';
    var b2=document.createElement('button'); b2.type='button'; b2.className='cols-reset'; b2.style.display='inline-block';
    b2.textContent='\u21d4 Reset columns'; b2.addEventListener('click',function(e){ e.preventDefault(); reset(); });
    bar.appendChild(b2); t.parentNode.insertBefore(bar,t.nextSibling);
  }

  function grips(){
    cells.forEach(function(c){ var g=c.querySelector(':scope>.col-grip'); if(g) g.remove(); });
    st.ord.slice(0,n-1).forEach(function(o){
      var cell=cells[o];
      if(getComputedStyle(cell).position==='static') cell.style.position='relative';
      var g=document.createElement('span'); g.className='col-grip'; g.setAttribute('aria-hidden','true');
      g.title='Drag to resize the column; double click resets all columns of this table';
      cell.appendChild(g);
      g.addEventListener('click',function(e){ e.stopPropagation(); e.preventDefault(); });
      g.addEventListener('dblclick',function(e){ e.preventDefault(); reset(); });
      g.addEventListener('pointerdown',function(e){
        if(e.button!==undefined&&e.button!==0) return;
        e.preventDefault(); e.stopPropagation();
        if(!isTable()) return;
        var tw=t.getBoundingClientRect().width; if(!(tw>0)) return;
        var base=st.w||normalize(cells.map(function(c){return c.getBoundingClientRect().width;}));
        if(!base) return;
        var pos=st.ord.indexOf(o), b=st.ord[pos+1];
        apply(base);
        var x0=e.clientX, cur=base;
        g.classList.add('on'); document.body.classList.add('col-resizing');
        try{ g.setPointerCapture(e.pointerId); }catch(x){}
        function mv(ev){ cur=moveOrig(base,o,b,(ev.clientX-x0)/tw*100); apply(cur); }
        function up(){
          g.removeEventListener('pointermove',mv); g.removeEventListener('pointerup',up); g.removeEventListener('pointercancel',up);
          g.classList.remove('on'); document.body.classList.remove('col-resizing');
          store(k,cur);
        }
        g.addEventListener('pointermove',mv); g.addEventListener('pointerup',up); g.addEventListener('pointercancel',up);
      });
    });
  }

  var press=null, marker=null;
  cells.forEach(function(cell,o){
    if(!movable[o]) return;
    cell.addEventListener('pointerdown',function(e){
      if((e.button!==undefined&&e.button!==0)||e.target.closest('.col-grip,.cols-reset')) return;
      if(!isTable()) return;
      press={o:o,x:e.clientX,on:false,before:null,pid:e.pointerId};
    });
  });
  function beforeFor(x,o){
    var list=st.ord.filter(function(i){return movable[i]&&i!==o;});
    for(var q=0;q<list.length;q++){ var r=cells[list[q]].getBoundingClientRect(); if(x<r.left+r.width/2) return list[q]; }
    return null;
  }
  t.addEventListener('pointermove',function(e){
    if(!press) return;
    var dx=e.clientX-press.x;
    if(!press.on){ if(Math.abs(dx)<DRAG) return; press.on=true; cells[press.o].classList.add('col-dragging'); document.body.classList.add('col-moving'); try{ cells[press.o].setPointerCapture(press.pid); }catch(x){} }
    press.before=beforeFor(e.clientX,press.o);
    var list=st.ord.filter(function(i){return movable[i]&&i!==press.o;}), x;
    if(press.before!==null) x=cells[press.before].getBoundingClientRect().left;
    else if(list.length) x=cells[list[list.length-1]].getBoundingClientRect().right; else return;
    if(!marker){ marker=document.createElement('div'); marker.className='col-drop'; document.body.appendChild(marker); }
    var hr=cells[press.o].getBoundingClientRect(), tr2=t.getBoundingClientRect();
    marker.style.left=x+'px'; marker.style.top=hr.top+'px'; marker.style.height=Math.max(hr.height,Math.min(tr2.bottom,window.innerHeight)-hr.top)+'px';
  });
  function endPress(commit){
    if(!press) return;
    var p=press; press=null;
    if(!p.on) return;
    cells[p.o].classList.remove('col-dragging'); document.body.classList.remove('col-moving');
    if(marker&&marker.parentNode) marker.parentNode.removeChild(marker); marker=null;
    var swallow=function(ev){ ev.stopPropagation(); ev.preventDefault(); };
    t.addEventListener('click',swallow,true); setTimeout(function(){ t.removeEventListener('click',swallow,true); },0);
    if(!commit) return;
    var next=reorder(st.ord,movable,p.o,p.before);
    var same=next.every(function(v,i){return v===st.ord[i];});
    if(same) return;
    applyOrder(next);
    var ident=next.every(function(v,i){return v===i;});
    store(ko,ident?null:next);
  }
  t.addEventListener('pointerup',function(){ endPress(true); });
  t.addEventListener('pointercancel',function(){ endPress(false); });

  grips();
  var savedO=validOrder(load(ko),n,movable);
  if(savedO&&isTable()) applyOrder(savedO);
  var saved=validate(load(k),n);
  if(saved&&isTable()) apply(saved);
}

var queued=false;
function scan(){
  queued=false;
  [].forEach.call(document.querySelectorAll('table.list-table'),function(t,i){ bind(t,i); });
}
function queue(){ if(queued) return; queued=true; (window.requestAnimationFrame||setTimeout)(scan); }
if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',scan); else scan();
if(window.MutationObserver) new MutationObserver(queue).observe(document.documentElement,{childList:true,subtree:true});
})();
</script>`
