// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"dnshived/internal/passpolicy"
	"dnshived/internal/webauth"
)

// policyContext is what a password for this user is judged against.
func policyContext(store *webauth.Store, name, email string) passpolicy.Context {
	host, _ := os.Hostname()
	return passpolicy.Context{
		MinLength: store.PasswordMinLength(),
		Names:     passpolicy.NamesFor(name, email, host),
	}
}

// tooWeakMessage turns the unmet requirements into one sentence.
func tooWeakMessage(problems []string) string {
	return "the password is too weak: it " + strings.Join(problems, ", ")
}

// handlePasswordStrength (POST /password-strength) rates a password for the strength bar. It is
// public because the reset page uses it too, and it stores and logs nothing.
func handlePasswordStrength(store *webauth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		rating := passpolicy.Rate(r.PostForm.Get("password"), policyContext(store, r.PostForm.Get("name"), r.PostForm.Get("email")))
		writeJSONWeb(w, http.StatusOK, map[string]any{
			"level": rating.Level, "label": rating.Label, "problems": rating.Problems,
		})
	}
}

// handleUsersPolicyPost (POST /users/policy) sets the minimum password length.
func handleUsersPolicyPost(store *webauth.Store, repl *authSync, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, _ := userFromContext(r)
		n, err := strconv.Atoi(strings.TrimSpace(r.FormValue("min_length")))
		if err != nil || n < passpolicy.FloorMinLength || n > passpolicy.CeilingMinLength {
			data := usersData(store, actor.Name)
			data.Error = fmt.Sprintf("the minimum length must be a number from %d to %d", passpolicy.FloorMinLength, passpolicy.CeilingMinLength)
			renderUsers(w, http.StatusBadRequest, data)
			return
		}
		if err := repl.change(func(d *webauth.Store) error {
			d.MinPasswordLength = n
			return nil
		}); err != nil {
			data := usersData(store, actor.Name)
			data.Error = "save: " + err.Error()
			renderUsers(w, http.StatusInternalServerError, data)
			return
		}
		auditAll(ref.Load(), actor.Name, "password.policy", fmt.Sprintf("minimum web-UI password length set to %d", n))
		doneRedirect(w, r, fmt.Sprintf("Minimum password length set to %d.", n))
	}
}

// passwordBarScriptHTML adds a fixed-width strength bar after every input marked data-pwbar. The
// optional data-pwbar-name and data-pwbar-email name other fields of the same form that are
// sent along, so the server can reject a password that contains them.
const passwordBarScriptHTML = `<script>(function(){
var colors=['#c0392b','#d9731a','#c9a700','#6aa84f','#1e9e5a'];
function init(inp){
var box=document.createElement('span');
box.style.cssText='display:inline-flex;align-items:center;gap:.4rem;margin-left:.5rem;vertical-align:middle';
var bar=document.createElement('span');
bar.style.cssText='display:inline-flex;gap:2px;width:7.5rem';
var segs=[];
for(var i=0;i<5;i++){var s=document.createElement('i');s.style.cssText='flex:1;height:.6rem;background:#8883;border-radius:1px';bar.appendChild(s);segs.push(s);}
var label=document.createElement('span');
label.style.cssText='display:inline-block;width:5rem;font-size:.85em';
box.appendChild(bar);box.appendChild(label);
inp.insertAdjacentElement('afterend',box);
function draw(res){
for(var i=0;i<5;i++){segs[i].style.background=(res&&i<=res.level)?colors[res.level]:'#8883';}
label.textContent=res?res.label:'';
box.title=res?(res.problems.length?'Still missing: it '+res.problems.join(', '):'Meets the password policy'):'';
}
var timer,seq=0;
function field(attr){var n=inp.getAttribute(attr);return(n&&inp.form&&inp.form.elements[n])?inp.form.elements[n].value:'';}
function ask(){
var my=++seq;
if(!inp.value){draw(null);return;}
var body=new URLSearchParams();
body.set('password',inp.value);body.set('name',field('data-pwbar-name'));body.set('email',field('data-pwbar-email'));
fetch('/password-strength',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
.then(function(r){return r.json();}).then(function(res){if(my===seq)draw(res);}).catch(function(){});
}
inp.addEventListener('input',function(){clearTimeout(timer);timer=setTimeout(ask,250);});
}
document.querySelectorAll('input[data-pwbar]').forEach(init);
})();</script>`
