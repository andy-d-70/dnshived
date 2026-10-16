// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"dnshived/internal/webauth"
)

const (
	resetLinkTTL     = 30 * time.Minute
	resetLimitWindow = 15 * time.Minute
	resetLimitCount  = 3
)

// resetLimiter caps reset requests per client address and per user.
type resetLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

var resetRequests = &resetLimiter{hits: map[string][]time.Time{}}

func (l *resetLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if now.Sub(t) < resetLimitWindow {
			kept = append(kept, t)
		}
	}
	if len(kept) >= resetLimitCount {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

// resetBaseURL is the public URL, else the mgmt VIP on this listener's port.
func resetBaseURL(store *webauth.Store, cfg *WebConfig, r *http.Request) string {
	if _, public := store.MailSettings(); public != "" {
		return public
	}
	scheme := "http"
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		scheme = "https"
	}
	host := r.Host
	if cfg.VIPHost != "" {
		_, port, err := net.SplitHostPort(cfg.ListenAddr)
		if err != nil {
			port = cfg.ListenAddr
		}
		host = net.JoinHostPort(cfg.VIPHost, port)
	}
	return scheme + "://" + host
}

type resetPageData struct {
	Token  string
	Error  string
	Notice string
	Done   bool
}

var forgotTmpl = template.Must(template.New("forgot").Parse(`<!doctype html>
<title>dnshived-web — forgot password</title>
` + styleHTML + `
<h1>Forgot password</h1>
<div style="max-width:28rem">
{{if .Notice}}<p class="ok">{{.Notice}}</p><p><a href="/login">&larr; log in</a></p>{{else}}
<p class="dim">Enter your user name or email address. If the account has an email address, a reset link valid for 30 minutes is sent to it.</p>
<form method="post" action="/forgot">
<p><label>User name or email<br><input name="login" autocomplete="username" required autofocus style="width:100%"></label></p>
<p><button type="submit">Send reset link</button> <a href="/login" style="margin-left:1rem">cancel</a></p>
</form>{{end}}
</div>
`))

var resetTmpl = template.Must(template.New("reset").Parse(`<!doctype html>
<title>dnshived-web — set new password</title>
` + styleHTML + `
<h1>Set a new password</h1>
<div style="max-width:28rem">
{{if .Error}}<p class="crit">{{.Error}}</p>{{end}}
{{if .Token}}
<form method="post" action="/reset">
<input type="hidden" name="token" value="{{.Token}}">
<p><label>New password<br><input type="password" name="new_password" autocomplete="new-password" required autofocus style="width:100%"></label></p>
<p><label>Confirm new password<br><input type="password" name="confirm_password" autocomplete="new-password" required style="width:100%"></label></p>
<p><button type="submit" class="btn-success">Set password</button></p>
</form>
{{else}}<p><a href="/forgot">Request a new link</a> · <a href="/login">log in</a></p>{{end}}
</div>
`))

const forgotAnswer = "If that account exists and has an email address, a reset link is on its way. Check your inbox (and spam folder)."

func handleForgotGet(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, forgotTmpl, resetPageData{}, "forgot")
}

// handleForgotPost answers the same way whether or not the account exists;
// the lookup and the mail run in the background so timing tells nothing.
func handleForgotPost(store *webauth.Store, repl *authSync, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		login := strings.TrimSpace(r.FormValue("login"))
		client := clientAddr(r)
		base := resetBaseURL(store, ref.Load(), r)
		if login != "" && resetRequests.allow("client:"+client, time.Now()) {
			go requestReset(store, repl, ref, login, client, base)
		}
		renderTemplate(w, forgotTmpl, resetPageData{Notice: forgotAnswer}, "forgot")
	}
}

func requestReset(store *webauth.Store, repl *authSync, ref *configRef, login, client, base string) {
	u, ok := store.LookupLogin(login)
	smtpCfg, _ := store.MailSettings()
	if !ok || u.Disabled || u.Email == "" || smtpCfg.Host == "" {
		log.Printf("[RESET] reset requested for %q from %s — no mail sent (unknown, disabled, no email or no mail settings)", login, client)
		return
	}
	if !resetRequests.allow("user:"+u.Name, time.Now()) {
		log.Printf("[RESET] reset for %s from %s refused — too many requests", u.Name, client)
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		log.Printf("[RESET] token: %v", err)
		return
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	expires := time.Now().Add(resetLinkTTL)
	err := repl.change(func(d *webauth.Store) error {
		webauth.PruneResets(d, time.Now())
		kept := d.Resets[:0]
		for _, rt := range d.Resets {
			if rt.User != u.Name {
				kept = append(kept, rt)
			}
		}
		d.Resets = append(kept, webauth.ResetToken{User: u.Name, Hash: webauth.HashToken(token), Expires: expires.UTC().Format(time.RFC3339)})
		return nil
	})
	if err != nil {
		log.Printf("[RESET] store reset link for %s: %v", u.Name, err)
		return
	}
	link := base + "/reset?token=" + url.QueryEscape(token)
	body := fmt.Sprintf("A password reset was requested for the dnshived web UI user %s (from %s).\n\n"+
		"Set a new password here (valid until %s):\n%s\n\n"+
		"If you did not ask for this, ignore this email — your password stays unchanged.",
		u.Name, client, expires.Local().Format("2006-01-02 15:04 MST"), link)
	if err := sendMail(smtpCfg, u.Email, "dnshived password reset", body+"\n\n— dnshived"); err != nil {
		log.Printf("[RESET] mail to %s (%s): %v", u.Name, u.Email, err)
		auditAll(ref.Load(), "system", "password.reset_mail_failed", "reset mail for "+u.Name+" failed: "+err.Error())
		return
	}
	auditAll(ref.Load(), "system", "password.reset_requested", "reset link mailed to "+u.Name+" (requested from "+client+")")
}

func handleResetGet(store *webauth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if _, ok := store.ResetUser(token, time.Now()); !ok {
			w.WriteHeader(http.StatusBadRequest)
			renderTemplate(w, resetTmpl, resetPageData{Error: "This reset link is invalid, already used or expired."}, "reset")
			return
		}
		renderTemplate(w, resetTmpl, resetPageData{Token: token}, "reset")
	}
}

var errResetInvalid = errors.New("This reset link is invalid, already used or expired.")

func handleResetPost(store *webauth.Store, repl *authSync, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.FormValue("token")
		newPw, confirm := r.FormValue("new_password"), r.FormValue("confirm_password")
		fail := func(msg string, keepToken bool) {
			data := resetPageData{Error: msg}
			if keepToken {
				data.Token = token
			}
			w.WriteHeader(http.StatusBadRequest)
			renderTemplate(w, resetTmpl, data, "reset")
		}
		name, ok := store.ResetUser(token, time.Now())
		if !ok {
			fail(errResetInvalid.Error(), false)
			return
		}
		if newPw != confirm {
			fail("New password and confirmation do not match.", true)
			return
		}
		if len(newPw) < minPasswordLength {
			fail(fmt.Sprintf("The new password must have at least %d characters.", minPasswordLength), true)
			return
		}
		hash, err := webauth.HashPassword(newPw)
		if err != nil {
			fail("hash password: "+err.Error(), true)
			return
		}
		hashedToken := webauth.HashToken(token)
		err = repl.change(func(d *webauth.Store) error {
			now := time.Now()
			var kept []webauth.ResetToken
			found := false
			for _, rt := range d.Resets {
				if rt.Hash == hashedToken && rt.User == name {
					if exp, err := time.Parse(time.RFC3339, rt.Expires); err == nil && now.Before(exp) {
						found = true
					}
					continue
				}
				kept = append(kept, rt)
			}
			if !found {
				return errResetInvalid
			}
			for i := range d.Users {
				if d.Users[i].Name == name && !d.Users[i].Disabled {
					d.Users[i].PasswordHash = hash
					d.Users[i].SessionEpoch++
					d.Resets = kept
					webauth.PruneResets(d, now)
					return nil
				}
			}
			return errResetInvalid
		})
		if err != nil {
			fail(err.Error(), false)
			return
		}
		auditAll(ref.Load(), name, "password.reset", "password of "+name+" set through an emailed reset link (from "+clientAddr(r)+")")
		notifyUser(store, name, "Your dnshived password was reset",
			"The web-UI password of user "+name+" was just set through a reset link. If that was not you, tell an admin at once.")
		http.Redirect(w, r, "/login?msg=reset", http.StatusSeeOther)
	}
}
