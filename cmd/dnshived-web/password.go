// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"dnshived/internal/passpolicy"
	"dnshived/internal/webauth"
)

// passwordData feeds passwordTmpl.
type passwordData struct {
	Username string
	Error    string
	Success  bool
	Weak     bool
	Next     string
}

var passwordTmpl = template.Must(template.New("password").Parse(`<!doctype html>
<title>dnshived-web — change password</title>
` + styleHTML + `
` + navHTML + `
<h1>Change password</h1>

{{if .Success}}<p><strong>Password changed</strong> on every core. All your sessions have ended — <a href="/login">log in again</a> with the new password.</p>
{{else}}
{{if .Error}}<p><strong>{{.Error}}</strong></p>{{end}}
{{if .Weak}}<p class="warn">Your password does not meet the current password policy (minimum length, an uppercase letter, a digit and a special character, no simple patterns). It still works, but please change it.</p><p><a href="{{.Next}}">Continue without changing</a></p>{{end}}
<p>Logged in as {{.Username}}.</p>
<form method="post" action="/password">
<label>Current password: <input type="password" name="current_password" autocomplete="current-password"></label><br>
<input type="hidden" name="name" value="{{.Username}}">
<label>New password: <input type="password" name="new_password" autocomplete="new-password" data-pwbar data-pwbar-name="name"></label><br>
<label>Confirm new password: <input type="password" name="confirm_password" autocomplete="new-password"></label><br>
<button type="submit">Change password</button>
</form>
` + passwordBarScriptHTML + `
{{end}}
`))

func handlePasswordForm(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, _ := userFromContext(r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := passwordTmpl.Execute(w, passwordData{Username: user.Name, Weak: r.URL.Query().Get("weak") == "1", Next: safeNext(r.URL.Query().Get("next"))}); err != nil {
			log.Printf("[PASSWORD] render form: %v", err)
		}
	}
}

func renderPasswordError(w http.ResponseWriter, username, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	passwordTmpl.Execute(w, passwordData{Username: username, Error: msg})
}

// changePasswordFormHandler (POST /password) is the self-service
// counterpart to cmd/dnshived-web's console-only -reset-user flag.
func changePasswordFormHandler(ref *configRef, store *webauth.Store, repl *authSync) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		user, ok := userFromContext(r)
		if !ok {
			renderPasswordError(w, "", "not authenticated")
			return
		}

		current := r.FormValue("current_password")
		newPw := r.FormValue("new_password")
		confirm := r.FormValue("confirm_password")
		if current == "" || newPw == "" || confirm == "" {
			renderPasswordError(w, user.Name, "current password, new password, and confirmation are all required")
			return
		}
		if newPw != confirm {
			renderPasswordError(w, user.Name, "new password and confirmation do not match")
			return
		}
		if problems := passpolicy.Check(newPw, policyContext(store, user.Name, user.Email)); len(problems) > 0 {
			renderPasswordError(w, user.Name, tooWeakMessage(problems))
			return
		}
		if _, ok := store.Verify(user.Name, current); !ok {
			renderPasswordError(w, user.Name, "current password is incorrect")
			return
		}

		hash, err := webauth.HashPassword(newPw)
		if err != nil {
			renderPasswordError(w, user.Name, "hash new password: "+err.Error())
			return
		}
		if err := setPasswordHash(repl, user.Name, hash); err != nil {
			renderPasswordError(w, user.Name, "save new password: "+err.Error())
			return
		}
		auditAll(cfg, user.Name, "password.change", "changed web-UI password for "+user.Name)
		notifyUser(store, user.Name, "Your dnshived password was changed",
			"The web-UI password of user "+user.Name+" was changed. If that was not you, ask an admin to reset it and check the audit log.")

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := passwordTmpl.Execute(w, passwordData{Username: user.Name, Success: true}); err != nil {
			log.Printf("[PASSWORD] render success: %v", err)
		}
	}
}

// setPasswordHash stores a new hash and ends the user's sessions everywhere.
func setPasswordHash(repl *authSync, name, hash string) error {
	return repl.change(func(d *webauth.Store) error {
		for i := range d.Users {
			if d.Users[i].Name == name {
				d.Users[i].PasswordHash = hash
				d.Users[i].SessionEpoch++
				return nil
			}
		}
		return fmt.Errorf("user %q not found", name)
	})
}

// applyPasswordChangeHandler (POST /internal/password/change) receives a
// password change from a sibling still running an older version.
func applyPasswordChangeHandler(ref *configRef, repl *authSync) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := ref.Load()
		if !checkSharedToken(cfg, r) {
			writeJSONWeb(w, http.StatusUnauthorized, map[string]string{"error": "invalid or missing token"})
			return
		}
		var req struct {
			Name         string `json:"name"`
			PasswordHash string `json:"password_hash"`
			Role         string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.PasswordHash == "" || req.Role == "" {
			writeJSONWeb(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if !webauth.ValidPasswordHash(req.PasswordHash) {
			log.Printf("[PASSWORD] refused a password hash for %q from %s: outside the allowed sizes", req.Name, clientAddr(r))
			writeJSONWeb(w, http.StatusBadRequest, map[string]string{"error": "invalid password hash"})
			return
		}
		if err := setPasswordHash(repl, req.Name, req.PasswordHash); err != nil {
			writeJSONWeb(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSONWeb(w, http.StatusOK, map[string]bool{"ok": true})
	}
}
