// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"dnshived/internal/webauth"
)

const (
	sessionCookieName = "dnshived_session"
	sessionIdle       = 30 * time.Minute
	sessionMax        = 12 * time.Hour
	// sessionRefresh bounds how often a sliding session cookie is re-issued.
	sessionRefresh = time.Minute
)

// sessionClaims is the signed content of a session cookie. The cookie
// carries no secret: it names the user and is valid only while the user's
// session epoch is unchanged.
type sessionClaims struct {
	User   string `json:"u"`
	Epoch  int64  `json:"e"`
	Issued int64  `json:"i"`
	Seen   int64  `json:"s"`
}

func signSession(key []byte, c sessionClaims) string {
	payload, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(mac.Sum(nil))
}

func parseSession(key []byte, value string, now time.Time) (sessionClaims, bool) {
	if len(key) == 0 {
		return sessionClaims{}, false
	}
	payloadPart, sigPart, ok := strings.Cut(value, ".")
	if !ok {
		return sessionClaims{}, false
	}
	enc := base64.RawURLEncoding
	payload, err1 := enc.DecodeString(payloadPart)
	sig, err2 := enc.DecodeString(sigPart)
	if err1 != nil || err2 != nil {
		return sessionClaims{}, false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return sessionClaims{}, false
	}
	var c sessionClaims
	if json.Unmarshal(payload, &c) != nil || c.User == "" {
		return sessionClaims{}, false
	}
	issued, seen := time.Unix(c.Issued, 0), time.Unix(c.Seen, 0)
	if now.Sub(issued) > sessionMax || now.Sub(seen) > sessionIdle || seen.After(now.Add(time.Minute)) {
		return sessionClaims{}, false
	}
	return c, true
}

// sessionUser resolves a session cookie to the current user record.
func sessionUser(store *webauth.Store, value string, now time.Time) (webauth.User, sessionClaims, bool) {
	c, ok := parseSession(store.SessionKeyBytes(), value, now)
	if !ok {
		return webauth.User{}, c, false
	}
	u, found := store.Lookup(c.User)
	if !found || u.Disabled || u.SessionEpoch != c.Epoch {
		return webauth.User{}, c, false
	}
	return u, c, true
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: value, Path: "/",
		MaxAge: int(sessionMax.Seconds()), HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
}

// authenticate accepts a session cookie, or HTTP Basic credentials sent
// unprompted by scripts; a browser without a session goes to /login.
func authenticate(store *webauth.Store, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		if ck, err := r.Cookie(sessionCookieName); err == nil {
			if user, claims, ok := sessionUser(store, ck.Value, now); ok {
				if now.Sub(time.Unix(claims.Seen, 0)) > sessionRefresh {
					claims.Seen = now.Unix()
					setSessionCookie(w, r, signSession(store.SessionKeyBytes(), claims))
				}
				next(w, r.WithContext(context.WithValue(r.Context(), userContextKey{}, user)))
				return
			}
		}
		if _, _, ok := r.BasicAuth(); ok {
			basicAuth(store, next)(w, r)
			return
		}
		loginRequired(w, r)
	}
}

func loginRequired(w http.ResponseWriter, r *http.Request) {
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && !strings.HasPrefix(r.URL.Path, "/api/") {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	http.Error(w, "login required", http.StatusUnauthorized)
}

type loginData struct {
	Next    string
	User    string
	Error   string
	Notice  string
	CanMail bool
}

var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<title>dnshived-web — log in</title>
` + styleHTML + `
<h1>dnshived</h1>
<div style="max-width:24rem">
{{if .Notice}}<p class="ok">{{.Notice}}</p>{{end}}
{{if .Error}}<p class="crit">{{.Error}}</p>{{end}}
<form method="post" action="/login">
<input type="hidden" name="next" value="{{.Next}}">
<p><label>User name<br><input name="username" value="{{.User}}" autocomplete="username" autofocus required style="width:100%"></label></p>
<p><label>Password<br><input type="password" name="password" autocomplete="current-password" required style="width:100%"></label></p>
<p><button type="submit" class="btn-success">Log in</button></p>
</form>
{{if .CanMail}}<p class="dim"><a href="/forgot">Forgot password?</a></p>{{else}}<p class="dim" title="Password reset by email needs mail settings (Cluster config → Mail). Without them, an admin resets the password on the Users page, or on a core: dnshived-web -reset-user &lt;name&gt;.">Forgot password? Ask an admin.</p>{{end}}
</div>
`))

func safeNext(next string) string {
	if isSafeReturnPath(next) && !strings.HasPrefix(next, "/login") && !strings.HasPrefix(next, "/logout") {
		return next
	}
	return "/"
}

func mailConfigured(store *webauth.Store) bool {
	smtp, _ := store.MailSettings()
	return smtp.Host != "" && smtp.From != ""
}

func handleLoginGet(store *webauth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next := safeNext(r.URL.Query().Get("next"))
		if ck, err := r.Cookie(sessionCookieName); err == nil {
			if _, _, ok := sessionUser(store, ck.Value, time.Now()); ok {
				http.Redirect(w, r, next, http.StatusSeeOther)
				return
			}
		}
		data := loginData{Next: next, CanMail: mailConfigured(store)}
		switch r.URL.Query().Get("msg") {
		case "logout":
			data.Notice = "Logged out."
		case "reset":
			data.Notice = "Password changed — log in with the new password."
		case "expired":
			data.Notice = "Your session ended — log in again."
		}
		renderTemplate(w, loginTmpl, data, "login")
	}
}

func handleLoginPost(store *webauth.Store, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next := safeNext(r.FormValue("next"))
		name := strings.TrimSpace(r.FormValue("username"))
		data := loginData{Next: next, User: name, CanMail: mailConfigured(store)}
		client := clientAddr(r)
		user, res := verifyWithCache(store.Verify, name, r.FormValue("password"), client)
		switch res {
		case verifyLimited:
			if wait := loginLimiter.retryAfter(client, time.Now()); wait > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
			}
			w.WriteHeader(http.StatusTooManyRequests)
			data.Error = "Too many failed logins from this address — try again later."
			renderTemplate(w, loginTmpl, data, "login")
			return
		case verifyBad:
			log.Printf("[AUTH] failed login for %q from %s", name, client)
			auditAll(ref.Load(), name, "login.failed", "failed web-UI login from "+client)
			w.WriteHeader(http.StatusUnauthorized)
			data.Error = "Wrong user name or password."
			renderTemplate(w, loginTmpl, data, "login")
			return
		}
		now := time.Now()
		setSessionCookie(w, r, signSession(store.SessionKeyBytes(), sessionClaims{
			User: user.Name, Epoch: user.SessionEpoch, Issued: now.Unix(), Seen: now.Unix(),
		}))
		log.Printf("[AUTH] %s logged in from %s", user.Name, client)
		http.Redirect(w, r, next, http.StatusSeeOther)
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w, r)
	http.Redirect(w, r, "/login?msg=logout", http.StatusSeeOther)
}

// auditAll records one event on every core, in the background.
func auditAll(cfg *WebConfig, actor, action, summary string) {
	nodes := append([]NodeConfig(nil), cfg.Nodes...)
	go func() {
		for _, n := range nodes {
			if err := pushAudit(n, actor, action, summary); err != nil {
				log.Printf("[AUDIT] %s on %s: %v", action, n.Name, err)
			}
		}
	}()
}
