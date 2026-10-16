// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"dnshived/internal/webauth"
)

const (
	smtpDialTimeout = 10 * time.Second
	smtpIOTimeout   = 30 * time.Second
)

func smtpPort(s webauth.SMTPSettings) int {
	if s.Port > 0 {
		return s.Port
	}
	switch s.Security {
	case "tls":
		return 465
	case "none":
		return 25
	}
	return 587
}

func smtpTLSConfig(s webauth.SMTPSettings) (*tls.Config, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if strings.TrimSpace(s.CAPEM) != "" && !pool.AppendCertsFromPEM([]byte(s.CAPEM)) {
		return nil, errors.New("the custom CA field contains no PEM certificate")
	}
	return &tls.Config{ServerName: s.Host, RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// dialSMTP connects, secures the connection as configured and logs in.
func dialSMTP(s webauth.SMTPSettings) (*smtp.Client, error) {
	if s.Host == "" {
		return nil, errors.New("no SMTP server configured")
	}
	tlsCfg, err := smtpTLSConfig(s)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(s.Host, strconv.Itoa(smtpPort(s)))
	dialer := &net.Dialer{Timeout: smtpDialTimeout}
	var conn net.Conn
	if s.Security == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}
	conn.SetDeadline(time.Now().Add(smtpIOTimeout))
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SMTP greeting from %s: %w", addr, err)
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "localhost"
	}
	if err := c.Hello(host); err != nil {
		c.Close()
		return nil, fmt.Errorf("EHLO: %w", err)
	}
	if s.Security != "tls" && s.Security != "none" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			c.Close()
			return nil, errors.New("the server does not offer STARTTLS — choose TLS or none")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			c.Close()
			return nil, fmt.Errorf("STARTTLS: %w", err)
		}
	}
	if s.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			c.Close()
			return nil, fmt.Errorf("login as %s: %w", s.Username, err)
		}
	}
	return c, nil
}

// testSMTP checks connection, TLS and login without sending anything.
func testSMTP(s webauth.SMTPSettings) error {
	c, err := dialSMTP(s)
	if err != nil {
		return err
	}
	return c.Quit()
}

func validAddress(a string) bool {
	p, err := mail.ParseAddress(a)
	return err == nil && p.Address == a && !strings.ContainsAny(a, "\r\n")
}

func sendMail(s webauth.SMTPSettings, to, subject, body string) error {
	if !validAddress(s.From) {
		return fmt.Errorf("invalid sender address %q", s.From)
	}
	if !validAddress(to) {
		return fmt.Errorf("invalid recipient address %q", to)
	}
	c, err := dialSMTP(s)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Mail(s.From); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO %s: %w", to, err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	id := make([]byte, 12)
	rand.Read(id)
	host := s.Host
	if at := strings.LastIndex(s.From, "@"); at >= 0 {
		host = s.From[at+1:]
	}
	msg := "From: dnshived <" + s.From + ">\r\n" +
		"To: <" + to + ">\r\n" +
		"Subject: " + subject + "\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"Message-ID: <" + hex.EncodeToString(id) + "@" + host + ">\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n\r\n" +
		strings.ReplaceAll(body, "\n", "\r\n") + "\r\n"
	if _, err := w.Write([]byte(msg)); err != nil {
		return fmt.Errorf("write message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("message refused: %w", err)
	}
	return c.Quit()
}

// notifyUser mails a security notice to name's address, in the background;
// a user without an address or a cluster without mail settings gets none.
func notifyUser(store *webauth.Store, name, subject, body string) {
	u, ok := store.Lookup(name)
	smtpCfg, _ := store.MailSettings()
	if !ok || u.Email == "" || smtpCfg.Host == "" || smtpCfg.From == "" {
		return
	}
	go func() {
		if err := sendMail(smtpCfg, u.Email, subject, body+"\n\n— dnshived"); err != nil {
			log.Printf("[MAIL] notification to %s (%s): %v", name, u.Email, err)
		}
	}()
}

type mailPageData struct {
	SMTP        webauth.SMTPSettings
	HasPassword bool
	PublicURL   string
	TestTo      string
	Error       string
	Notice      string
}

var mailTmpl = template.Must(template.New("mail").Parse(`<!doctype html>
<title>dnshived-web — mail</title>
` + styleHTML + `
<h1>Mail</h1>
` + navHTML + `
<p class="dim">Outgoing mail for password-reset links and security notifications. These settings apply at once on every core
(no commit needed). <a href="/config">&larr; cluster config</a></p>
{{if .Notice}}<p class="ok">{{.Notice}}</p>{{end}}
{{if .Error}}<p class="crit">{{.Error}}</p>{{end}}
<form method="post" action="/config/mail">
<table border="1" cellpadding="4">
<tr><td>SMTP server</td><td><input name="host" value="{{.SMTP.Host}}" placeholder="mail.example.org" size="30"></td></tr>
<tr><td>Port</td><td><input name="port" value="{{if .SMTP.Port}}{{.SMTP.Port}}{{end}}" placeholder="587 / 465 / 25" size="8"></td></tr>
<tr><td>Security <span class="info-ico" title="STARTTLS: plain connection upgraded to TLS (usually port 587). TLS: encrypted from the start (usually 465). None: unencrypted — a login is then refused, so the password is never sent in clear.">ⓘ</span></td><td><select name="security" class="js-combo">
<option value="starttls" {{if or (eq .SMTP.Security "starttls") (eq .SMTP.Security "")}}selected{{end}}>STARTTLS</option>
<option value="tls" {{if eq .SMTP.Security "tls"}}selected{{end}}>TLS</option>
<option value="none" {{if eq .SMTP.Security "none"}}selected{{end}}>none</option>
</select></td></tr>
<tr><td>Login (optional)</td><td><input name="username" value="{{.SMTP.Username}}" autocomplete="off" size="30"></td></tr>
<tr><td>Password</td><td><input type="password" name="password" value="" autocomplete="new-password" size="30" placeholder="{{if .HasPassword}}unchanged{{else}}none set{{end}}" title="Never sent to the browser. Leave blank to keep it."> <label><input type="checkbox" name="clear_password"> remove</label></td></tr>
<tr><td>Sender address</td><td><input name="from" value="{{.SMTP.From}}" placeholder="dnshived@example.org" size="30"></td></tr>
<tr><td>Custom CA (optional) <span class="info-ico" title="PEM certificate(s) trusted in addition to the system CAs, for a mail server with an internal certificate. The server name must still match the certificate.">ⓘ</span></td><td><textarea name="ca_pem" rows="4" cols="60" placeholder="-----BEGIN CERTIFICATE-----">{{.SMTP.CAPEM}}</textarea></td></tr>
<tr><td>Public URL <span class="info-ico" title="The address used in password-reset links, e.g. https://dnshived.example.org:8443. Blank: the management VIP.">ⓘ</span></td><td><input name="public_url" value="{{.PublicURL}}" placeholder="https://&lt;mgmt VIP&gt;:8443" size="40"></td></tr>
</table>
<p><button type="submit" name="action" value="save" class="btn-success">Save</button>
<button type="submit" name="action" value="test" title="Connects, secures the connection and logs in with the values in this form, without saving or sending anything.">Test settings</button>
<label style="margin-left:1.5rem">Test email to <input name="test_to" value="{{.TestTo}}" placeholder="you@example.org" size="24"></label>
<button type="submit" name="action" value="send" title="Sends one test email with the values in this form, without saving them.">Send test email</button></p>
</form>
`))

func mailPage(store *webauth.Store) mailPageData {
	smtpCfg, publicURL := store.MailSettings()
	data := mailPageData{SMTP: smtpCfg, HasPassword: smtpCfg.Password != "", PublicURL: publicURL}
	data.SMTP.Password = ""
	return data
}

func handleMailGet(store *webauth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, mailTmpl, mailPage(store), "mail")
	}
}

// mailSettingsFromForm builds the settings in the form; a blank password
// keeps the stored one.
func mailSettingsFromForm(r *http.Request, stored webauth.SMTPSettings) (webauth.SMTPSettings, string, error) {
	s := webauth.SMTPSettings{
		Host:     strings.TrimSpace(r.FormValue("host")),
		Security: r.FormValue("security"),
		Username: strings.TrimSpace(r.FormValue("username")),
		Password: stored.Password,
		From:     strings.TrimSpace(r.FormValue("from")),
		CAPEM:    strings.TrimSpace(r.FormValue("ca_pem")),
	}
	if s.Host != stored.Host || s.Username != stored.Username {
		s.Password = ""
	}
	if pw := r.FormValue("password"); pw != "" {
		s.Password = pw
	}
	if r.FormValue("clear_password") == "on" {
		s.Password = ""
	}
	if s.Security != "starttls" && s.Security != "tls" && s.Security != "none" {
		return s, "", fmt.Errorf("unknown security mode %q", s.Security)
	}
	if p := strings.TrimSpace(r.FormValue("port")); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return s, "", fmt.Errorf("invalid port %q", p)
		}
		s.Port = n
	}
	if s.Host != "" && strings.ContainsAny(s.Host, " /:\r\n") {
		return s, "", fmt.Errorf("invalid SMTP server %q (host name or address, port separately)", s.Host)
	}
	if s.From != "" && !validAddress(s.From) {
		return s, "", fmt.Errorf("invalid sender address %q", s.From)
	}
	if s.Host != "" && s.From == "" {
		return s, "", errors.New("a sender address is required")
	}
	if s.Username != "" && s.Password == "" {
		return s, "", errors.New("enter the password (it is kept only while server and login stay the same)")
	}
	if s.Security == "none" && s.Username != "" {
		return s, "", errors.New("a login needs STARTTLS or TLS — the password would be sent unencrypted")
	}
	publicURL := strings.TrimRight(strings.TrimSpace(r.FormValue("public_url")), "/")
	if publicURL != "" {
		u, err := url.Parse(publicURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return s, "", fmt.Errorf("invalid public URL %q (e.g. https://dnshived.example.org:8443)", publicURL)
		}
	}
	return s, publicURL, nil
}

func handleMailPost(store *webauth.Store, repl *authSync, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stored, _ := store.MailSettings()
		user, _ := userFromContext(r)
		s, publicURL, err := mailSettingsFromForm(r, stored)
		data := mailPage(store)
		data.SMTP, data.PublicURL, data.TestTo = s, publicURL, strings.TrimSpace(r.FormValue("test_to"))
		data.HasPassword, data.SMTP.Password = s.Password != "", ""
		if err != nil {
			data.Error = err.Error()
			w.WriteHeader(http.StatusBadRequest)
			renderTemplate(w, mailTmpl, data, "mail")
			return
		}
		switch r.FormValue("action") {
		case "test":
			if err := testSMTP(s); err != nil {
				data.Error = "Test failed: " + err.Error()
			} else {
				data.Notice = "Connection, TLS and login work (nothing was saved or sent)."
			}
		case "send":
			if err := sendMail(s, data.TestTo, "dnshived test email",
				"This is a test email from the dnshived web UI, sent by "+user.Name+"."); err != nil {
				data.Error = "Sending failed: " + err.Error()
			} else {
				data.Notice = "Test email sent to " + data.TestTo + " (settings not saved)."
			}
		default:
			err := repl.change(func(d *webauth.Store) error {
				if s.Host == "" {
					d.SMTP = nil
				} else {
					saved := s
					d.SMTP = &saved
				}
				d.PublicURL = publicURL
				return nil
			})
			if err != nil {
				data.Error = "Save failed: " + err.Error()
				break
			}
			auditAll(ref.Load(), user.Name, "mail.settings", fmt.Sprintf("mail settings saved (server %q, security %s, public URL %q)", s.Host, s.Security, publicURL))
			data.Notice = "Saved — active on every core."
		}
		renderTemplate(w, mailTmpl, data, "mail")
	}
}
