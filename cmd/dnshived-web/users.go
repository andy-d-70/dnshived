// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"dnshived/internal/passpolicy"
	"dnshived/internal/webauth"
)

var userNamePattern = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

type userRow struct {
	webauth.User
	Self bool
}

type usersPageData struct {
	MinLength int
	Users     []userRow
	Roles     []string
	Error     string
	Notice    string
	Edit      *userRow
	Policy    bool
	New       struct{ Name, Email, Role string }
}

var usersTmpl = template.Must(template.New("users").Parse(`<!doctype html>
<title>dnshived-web — users</title>
` + styleHTML + `
` + navHTML + `
<h1>Security</h1>
{{if .Policy}}` + securityTabs("/users/policy") + `{{else}}` + securityTabs("/users") + `{{end}}
<p class="dim">Web-UI logins. Changes apply at once on every core (no commit needed).
<strong>admin</strong>: everything. <strong>scopeadmin</strong>: everything served to clients — scopes, DHCP/DNS settings,
templates, local domains — but no cluster settings, nodes, users, tokens, backups or daemon restarts.
<strong>readonly</strong>: view only.</p>
{{if .Notice}}<p class="ok">{{.Notice}}</p>{{end}}
{{if .Error}}<p class="crit">{{.Error}}</p>{{end}}

{{if .Edit}}
<h2>Edit {{.Edit.Name}}</h2>
<form method="post" action="/users/{{.Edit.Name}}">
<input type="hidden" name="name" value="{{.Edit.Name}}">
<table border="1" cellpadding="4">
<tr><td>Role</td><td>{{if .Edit.Self}}{{.Edit.Role}} <span class="dim">(you cannot change your own role)</span><input type="hidden" name="role" value="{{.Edit.Role}}">{{else}}<select name="role" class="js-combo">{{$r := .Edit.Role}}{{range .Roles}}<option value="{{.}}" {{if eq . $r}}selected{{end}}>{{.}}</option>{{end}}</select>{{end}}</td></tr>
<tr><td>Email</td><td><input name="email" value="{{.Edit.Email}}" size="30" placeholder="for password reset"></td></tr>
<tr><td>Disabled</td><td>{{if .Edit.Self}}<span class="dim">you cannot disable yourself</span>{{else}}<label><input type="checkbox" name="disabled" {{if .Edit.Disabled}}checked{{end}}> cannot log in</label>{{end}}</td></tr>
<tr><td>New password</td><td><input type="password" name="new_password" autocomplete="new-password" size="24" placeholder="blank = unchanged" data-pwbar data-pwbar-name="name" data-pwbar-email="email"> confirm <input type="password" name="confirm_password" autocomplete="new-password" size="24"></td></tr>
</table>
<p><button type="submit" class="btn-success">Save</button> <a href="/users" style="margin-left:1rem">cancel</a></p>
</form>
{{if not .Edit.Self}}
<form method="post" action="/users/{{.Edit.Name}}/signout" style="display:inline" onsubmit="return confirm('End every session of {{.Edit.Name}} on every core?')"><button type="submit">Sign out everywhere</button></form>
<form method="post" action="/users/{{.Edit.Name}}/delete" style="display:inline;margin-left:1.5rem" onsubmit="return confirm('Delete user {{.Edit.Name}} on every core? This cannot be undone.')"><button type="submit" class="btn-danger">Delete user</button></form>
{{end}}
{{else}}
{{if .Policy}}
<div class="card probe-card">
<h3>Password policy</h3>
<form method="post" action="/users/policy">
<p>Minimum length <input type="number" name="min_length" min="8" max="64" value="{{.MinLength}}" style="width:5rem"> characters (8 to 64).
Also required: an uppercase letter, a digit, a special character, five different characters, no simple sequence or repeated block, and not the user name, mail address or host name.
Existing passwords keep working until they are changed. <button type="submit">Save</button></p>
</form>
</div>
{{else}}
<div class="table-wrap"><table class="list-table" border="1" cellpadding="4" data-stack>
<colgroup><col style="width:22%"><col style="width:14%"><col style="width:34%"><col style="width:16%"><col style="width:3.5rem"></colgroup>
<tr><th>User</th><th>Role</th><th>Mail</th><th>Status</th><th></th></tr>
{{range .Users}}{{$n := .Name}}<tr><td style="white-space:nowrap">{{.Name}}{{if .Self}} <span class="dim">(you)</span>{{end}}</td><td><span class="chip">{{.Role}}</span></td><td>{{if .Email}}{{.Email}}{{else}}<span class="dim" title="No email address: this user cannot reset a forgotten password by email.">—</span>{{end}}</td><td>{{if .Disabled}}<span class="chip warn">○ disabled</span>{{else}}<span class="chip ok">✔ active</span>{{end}}</td>
<td style="width:3rem;text-align:center"><details class="row-menu"><summary aria-haspopup="menu" title="actions for {{.Name}}">&#9776;</summary>
<div class="row-menu-list" role="menu">
<a role="menuitem" href="/users/{{.Name}}">Edit</a>
{{if not .Self}}<form method="post" action="/users/{{$n}}/signout" onsubmit="return confirm('End every session of {{$n}} on every core?')"><button type="submit" role="menuitem">Sign out everywhere</button></form>
<form method="post" action="/users/{{$n}}/delete" onsubmit="return confirm('Delete user {{$n}} on every core? This cannot be undone.')"><button type="submit" role="menuitem" class="danger">Delete&hellip;</button></form>{{end}}
</div></details></td></tr>
{{end}}
</table></div>

<div class="card probe-card">
<h3>Add user</h3>
<form method="post" action="/users/new">
<div class="fieldset">
<label>User name<input name="name" value="{{.New.Name}}" required pattern="[A-Za-z0-9._@\-]{1,64}" title="letters, digits, . _ @ -"></label>
<span class="fl">Role<span class="rseg">{{$r := .New.Role}}{{range .Roles}}<label><input type="radio" name="role" value="{{.}}" {{if eq . $r}}checked{{end}}><span>{{.}}</span></label>{{end}}</span></span>
<label>Email<input name="email" value="{{.New.Email}}" size="26" placeholder="optional, for password reset"></label>
<label>Password<input type="password" name="new_password" autocomplete="new-password" required size="22" data-pwbar data-pwbar-name="name" data-pwbar-email="email"></label>
<label>Confirm<input type="password" name="confirm_password" autocomplete="new-password" required size="22"></label>
<button type="submit" class="btn-success">Add user</button>
</div>
</form>
</div>
{{end}}
{{end}}
` + passwordBarScriptHTML + rowMenuScriptHTML + `
`))

func usersData(store *webauth.Store, self string) usersPageData {
	data := usersPageData{Roles: webauth.Roles, MinLength: passpolicy.ClampMin(store.PasswordMinLength())}
	data.New.Role = webauth.RoleReadonly
	for _, u := range store.List() {
		data.Users = append(data.Users, userRow{User: u, Self: u.Name == self})
	}
	return data
}

func renderUsers(w http.ResponseWriter, status int, data usersPageData) {
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	renderTemplate(w, usersTmpl, data, "users")
}

func handleUsersGet(store *webauth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, _ := userFromContext(r)
		if !actor.HasPermission(webauth.PermEditConfig) {
			http.Redirect(w, r, "/security", http.StatusSeeOther)
			return
		}
		data := usersData(store, actor.Name)
		data.Notice = r.URL.Query().Get("done")
		renderUsers(w, http.StatusOK, data)
	}
}

func handleUsersPolicyGet(store *webauth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, _ := userFromContext(r)
		data := usersData(store, actor.Name)
		data.Policy = true
		data.Notice = r.URL.Query().Get("done")
		renderUsers(w, http.StatusOK, data)
	}
}

func handleUserEditGet(store *webauth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, _ := userFromContext(r)
		u, ok := store.Lookup(r.PathValue("name"))
		if !ok {
			http.Error(w, "no such user", http.StatusNotFound)
			return
		}
		data := usersData(store, actor.Name)
		data.Edit = &userRow{User: u, Self: u.Name == actor.Name}
		renderUsers(w, http.StatusOK, data)
	}
}

func checkNewPassword(store *webauth.Store, name, email, pw, confirm string) error {
	if pw != confirm {
		return errors.New("password and confirmation do not match")
	}
	if problems := passpolicy.Check(pw, policyContext(store, name, email)); len(problems) > 0 {
		return errors.New(tooWeakMessage(problems))
	}
	return nil
}

func normalizeEmail(email string) (string, error) {
	email = strings.TrimSpace(email)
	if email != "" && !validAddress(email) {
		return "", fmt.Errorf("invalid email address %q", email)
	}
	return email, nil
}

func doneRedirect(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/users?done="+url.QueryEscape(msg), http.StatusSeeOther)
}

func handleUserCreate(store *webauth.Store, repl *authSync, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, _ := userFromContext(r)
		data := usersData(store, actor.Name)
		name := strings.TrimSpace(r.FormValue("name"))
		role := r.FormValue("role")
		data.New.Name, data.New.Role, data.New.Email = name, role, r.FormValue("email")
		fail := func(err error) {
			data.Error = err.Error()
			renderUsers(w, http.StatusBadRequest, data)
		}
		if !userNamePattern.MatchString(name) {
			fail(errors.New("user name: 1-64 letters, digits, . _ @ -"))
			return
		}
		if !webauth.ValidRole(role) {
			fail(fmt.Errorf("unknown role %q", role))
			return
		}
		email, err := normalizeEmail(r.FormValue("email"))
		if err != nil {
			fail(err)
			return
		}
		if err := checkNewPassword(store, name, email, r.FormValue("new_password"), r.FormValue("confirm_password")); err != nil {
			fail(err)
			return
		}
		hash, err := webauth.HashPassword(r.FormValue("new_password"))
		if err != nil {
			fail(err)
			return
		}
		err = repl.change(func(d *webauth.Store) error {
			for _, u := range d.Users {
				if u.Name == name {
					return fmt.Errorf("user %q already exists", name)
				}
			}
			d.Users = append(d.Users, webauth.User{Name: name, PasswordHash: hash, Role: role, Email: email})
			return nil
		})
		if err != nil {
			fail(err)
			return
		}
		auditAll(ref.Load(), actor.Name, "user.create", fmt.Sprintf("created web-UI user %s (role %s)", name, role))
		doneRedirect(w, r, "User "+name+" added.")
	}
}

func handleUserUpdate(store *webauth.Store, repl *authSync, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, _ := userFromContext(r)
		name := r.PathValue("name")
		before, ok := store.Lookup(name)
		if !ok {
			http.Error(w, "no such user", http.StatusNotFound)
			return
		}
		self := name == actor.Name
		role := r.FormValue("role")
		disabled := r.FormValue("disabled") == "on"
		if self {
			role, disabled = before.Role, before.Disabled
		}
		fail := func(err error) {
			data := usersData(store, actor.Name)
			data.Edit = &userRow{User: before, Self: self}
			data.Error = err.Error()
			renderUsers(w, http.StatusBadRequest, data)
		}
		if !webauth.ValidRole(role) {
			fail(fmt.Errorf("unknown role %q", role))
			return
		}
		email, err := normalizeEmail(r.FormValue("email"))
		if err != nil {
			fail(err)
			return
		}
		var hash string
		if pw := r.FormValue("new_password"); pw != "" {
			if err := checkNewPassword(store, name, email, pw, r.FormValue("confirm_password")); err != nil {
				fail(err)
				return
			}
			if hash, err = webauth.HashPassword(pw); err != nil {
				fail(err)
				return
			}
		}
		err = repl.change(func(d *webauth.Store) error {
			for i := range d.Users {
				u := &d.Users[i]
				if u.Name != name {
					continue
				}
				losesAdmin := u.Role == webauth.RoleAdmin && !u.Disabled && (role != webauth.RoleAdmin || disabled)
				if losesAdmin && webauth.ActiveAdmins(d) <= 1 {
					return errors.New("this is the last active admin — make another user admin first")
				}
				if u.Role != role || (disabled && !u.Disabled) || hash != "" {
					u.SessionEpoch++
				}
				u.Role, u.Disabled, u.Email = role, disabled, email
				if hash != "" {
					u.PasswordHash = hash
				}
				return nil
			}
			return fmt.Errorf("user %q not found", name)
		})
		if err != nil {
			fail(err)
			return
		}
		var changes []string
		if before.Role != role {
			changes = append(changes, "role "+before.Role+" → "+role)
		}
		if before.Disabled != disabled {
			changes = append(changes, map[bool]string{true: "disabled", false: "enabled"}[disabled])
		}
		if before.Email != email {
			changes = append(changes, "email changed")
		}
		if hash != "" {
			changes = append(changes, "password set by "+actor.Name)
		}
		if len(changes) == 0 {
			doneRedirect(w, r, "No change for "+name+".")
			return
		}
		summary := strings.Join(changes, ", ")
		auditAll(ref.Load(), actor.Name, "user.update", "web-UI user "+name+": "+summary)
		if before.Role != role || before.Disabled != disabled || hash != "" {
			notifyUser(store, name, "Your dnshived account was changed",
				"An admin ("+actor.Name+") changed your dnshived web-UI account "+name+": "+summary+".")
		}
		doneRedirect(w, r, "User "+name+" saved ("+summary+").")
	}
}

func handleUserSignout(store *webauth.Store, repl *authSync, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, _ := userFromContext(r)
		name := r.PathValue("name")
		err := repl.change(func(d *webauth.Store) error {
			for i := range d.Users {
				if d.Users[i].Name == name {
					d.Users[i].SessionEpoch++
					return nil
				}
			}
			return fmt.Errorf("user %q not found", name)
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		auditAll(ref.Load(), actor.Name, "user.signout", "ended every session of web-UI user "+name)
		doneRedirect(w, r, "Every session of "+name+" has ended.")
	}
}

func handleUserDelete(store *webauth.Store, repl *authSync, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, _ := userFromContext(r)
		name := r.PathValue("name")
		if name == actor.Name {
			http.Error(w, "you cannot delete yourself", http.StatusBadRequest)
			return
		}
		err := repl.change(func(d *webauth.Store) error {
			var kept []webauth.User
			found := false
			for _, u := range d.Users {
				if u.Name != name {
					kept = append(kept, u)
					continue
				}
				found = true
				if u.Role == webauth.RoleAdmin && !u.Disabled && webauth.ActiveAdmins(d) <= 1 {
					return errors.New("this is the last active admin")
				}
			}
			if !found {
				return fmt.Errorf("user %q not found", name)
			}
			var resets []webauth.ResetToken
			for _, rt := range d.Resets {
				if rt.User != name {
					resets = append(resets, rt)
				}
			}
			d.Users, d.Resets = kept, resets
			return nil
		})
		if err != nil {
			data := usersData(store, actor.Name)
			data.Error = err.Error()
			renderUsers(w, http.StatusBadRequest, data)
			return
		}
		auditAll(ref.Load(), actor.Name, "user.delete", "deleted web-UI user "+name)
		doneRedirect(w, r, "User "+name+" deleted.")
	}
}
