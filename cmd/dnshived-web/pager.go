// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

// pagerScriptHTML is the shared list pager. An element with data-pager="5,10,25,50,all"
// (its children are the rows: <tbody> or <ul>) gets a bar above it with the page-size
// choice, range and prev/next, and a slim bar below with range and prev/next. The first
// size is the default; a list with no more rows than the default shows no bar. The
// choice is remembered per data-pager-key in this browser only.
const pagerScriptHTML = `<script>
(function(){
  function key(el){return 'dnshived-pager:'+(el.getAttribute('data-pager-key')||el.id||'')}
  function bar(sizes,withSize,cur){
    var d=document.createElement('div');d.className='pager '+(withSize?'top':'bottom');
    var r=document.createElement('span');r.className='pg-range';d.appendChild(r);
    var m=document.createElement('span');m.className='pg-size';
    if(withSize){
      m.appendChild(document.createTextNode('Show '));
      var seg=document.createElement('span');seg.className='seg';
      sizes.forEach(function(n){var b=document.createElement('button');b.type='button';b.setAttribute('data-n',n);b.setAttribute('aria-pressed',String(n===cur));b.textContent=n;seg.appendChild(b)});
      m.appendChild(seg);
    }
    d.appendChild(m);
    var nav=document.createElement('span');nav.className='pg-nav';
    var p=document.createElement('button');p.type='button';p.setAttribute('data-d','-1');p.textContent='‹ prev';
    var pg=document.createElement('span');pg.className='pg-page';
    var n=document.createElement('button');n.type='button';n.setAttribute('data-d','1');n.textContent='next ›';
    nav.appendChild(p);nav.appendChild(pg);nav.appendChild(n);d.appendChild(nav);
    return d;
  }
  function init(el){
    var sizes=el.getAttribute('data-pager').split(',').map(function(s){return s.trim()}).filter(Boolean);
    if(!sizes.length)return;
    var cur=sizes[0];
    try{var s=localStorage.getItem(key(el));if(s&&sizes.indexOf(s)>=0)cur=s}catch(e){}
    var wrap=el.closest('.scrollbox')||el.closest('.table-wrap')||el;
    var top=bar(sizes,true,cur),bot=bar(sizes,false,cur),bars=[top,bot],page=1;
    wrap.parentNode.insertBefore(top,wrap);wrap.parentNode.insertBefore(bot,wrap.nextSibling);
    function render(){
      var rows=[].slice.call(el.children),n=rows.length,def=+sizes[0]||10;
      var short=n<=def;
      bars.forEach(function(b){b.hidden=short});
      if(short){rows.forEach(function(r){r.hidden=false});return}
      var size=cur==='all'?n:+cur,pages=Math.max(1,Math.ceil(n/size));
      page=Math.min(Math.max(page,1),pages);
      var a=(page-1)*size,e=Math.min(a+size,n);
      rows.forEach(function(r,i){r.hidden=i<a||i>=e});
      bars.forEach(function(b){
        b.querySelector('.pg-range').textContent=(a+1)+'–'+e+' of '+n;
        b.querySelector('.pg-page').textContent=cur==='all'?'all rows':('page '+page+' / '+pages);
        [].forEach.call(b.querySelectorAll('.pg-nav button'),function(x){var d=+x.getAttribute('data-d');x.disabled=cur==='all'||(d<0&&page<=1)||(d>0&&page>=pages)});
      });
      document.dispatchEvent(new Event('dnshived-pager'));
    }
    bars.forEach(function(b){b.addEventListener('click',function(ev){
      var t=ev.target.closest('button');if(!t)return;
      if(t.hasAttribute('data-n')){
        cur=t.getAttribute('data-n');page=1;
        [].forEach.call(top.querySelectorAll('.seg button'),function(x){x.setAttribute('aria-pressed',String(x===t))});
        try{localStorage.setItem(key(el),cur)}catch(e){}
      }else if(t.hasAttribute('data-d')){page+=+t.getAttribute('data-d')}
      render();
    })});
    render();
  }
  function start(){[].forEach.call(document.querySelectorAll('[data-pager]'),init)}
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',start);else start();
})();
</script>`

const pagerStyle = `
.pager{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap;color:var(--muted)}
.pager[hidden]{display:none}
.pager.top{margin:.2rem 0 .6rem}.pager.bottom{margin:.6rem 0 0}
.pager .pg-range{display:inline-block;min-width:9.5em;font-variant-numeric:tabular-nums}
.pager .pg-size{display:inline-flex;align-items:center;gap:.5rem}
.pager .seg{display:inline-flex;border:1px solid var(--border);border-radius:8px;overflow:hidden;background:var(--panel)}
.pager .seg button{font:inherit;border:0;border-right:1px solid var(--border);border-radius:0;background:transparent;color:var(--text);padding:.15rem .6rem;min-height:0;cursor:pointer}
.pager .seg button:last-child{border-right:0}
.pager .seg button[aria-pressed=true]{background:var(--accent);color:var(--on-accent);font-weight:600}
.pager .pg-nav{display:inline-flex;align-items:center;gap:.7rem;font-variant-numeric:tabular-nums}
.pager .pg-page{display:inline-block;min-width:6.5em;text-align:center}
.pager .pg-nav button{font:inherit;background:none;border:0;color:var(--accent);cursor:pointer;padding:0;min-width:3.5em;min-height:0}
.pager .pg-nav button:disabled{color:var(--muted);cursor:default;opacity:.55}
.pager .seg a{display:inline-block;padding:.15rem .6rem;border-right:1px solid var(--border);color:var(--text);text-decoration:none}
.pager .seg a:last-child{border-right:0}
.pager .seg a[aria-pressed=true]{background:var(--accent);color:var(--on-accent);font-weight:600}
.pager .pg-nav a,.pager .pg-nav .dis{display:inline-block;min-width:3.5em;text-align:center}
.pager .pg-nav .dis{color:var(--muted);opacity:.55}
.card-list li[hidden],tr[hidden]{display:none}
#events-card{display:flex;flex-direction:column;margin-bottom:0}
#events-card .scrollbox{flex:1 1 auto;height:auto;min-height:5rem;max-height:none}
`
