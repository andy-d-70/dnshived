// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"dnshived/internal/webauth"
)

// passwordData feeds passwordTmpl.
type passwordData struct {
	Username string
	Error    string
	Success  bool
}

var passwordTmpl = template.Must(template.New("password").Parse(`<!doctype html>
<title>dnshived-web — change password</title>
` + styleHTML + `
<h1>Change password</h1>
` + navHTML + `
{{if .Success}}<p><strong>Password changed</strong> on every core. All your sessions have ended — <a href="/login">log in again</a> with the new password.</p>
{{else}}
{{if .Error}}<p><strong>{{.Error}}</strong></p>{{end}}
<p>Logged in as {{.Username}}.</p>
<form method="post" action="/password">
<label>Current password: <input type="password" name="current_password" autocomplete="current-password"></label><br>
<label>New password: <input type="password" name="new_password" autocomplete="new-password"></label><br>
<label>Confirm new password: <input type="password" name="confirm_password" autocomplete="new-password"></label><br>
<button type="submit">Change password</button>
</form>
{{end}}
`))

func handlePasswordForm(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, _ := userFromContext(r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := passwordTmpl.Execute(w, passwordData{Username: user.Name}); err != nil {
			log.Printf("[PASSWORD] render form: %v", err)
		}
	}
}

func renderPasswordError(w http.ResponseWriter, username, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	passwordTmpl.Execute(w, passwordData{Username: username, Error: msg})
}

// minPasswordLength applies to every password set through the web UI.
const minPasswordLength = 10

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
		if len(newPw) < minPasswordLength {
			renderPasswordError(w, user.Name, fmt.Sprintf("the new password must have at least %d characters", minPasswordLength))
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
		if err := setPasswordHash(repl, req.Name, req.PasswordHash); err != nil {
			writeJSONWeb(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSONWeb(w, http.StatusOK, map[string]bool{"ok": true})
	}
}
