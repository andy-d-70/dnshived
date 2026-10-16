// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"dnshived/internal/webauth"
)

func mailForm(v url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/config/mail", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ParseForm()
	return r
}

func TestMailSettingsFromForm_StoredPasswordOnlyForSameServer(t *testing.T) {
	stored := webauth.SMTPSettings{Host: "mail.example.org", Username: "dnshived", Password: "s3cret", From: "a@example.org"}
	base := url.Values{"host": {"mail.example.org"}, "security": {"starttls"}, "username": {"dnshived"}, "from": {"a@example.org"}}

	s, _, err := mailSettingsFromForm(mailForm(base), stored)
	if err != nil || s.Password != "s3cret" {
		t.Errorf("same server: password %q, err %v", s.Password, err)
	}
	moved := url.Values{"host": {"attacker.example"}, "security": {"starttls"}, "username": {"dnshived"}, "from": {"a@example.org"}}
	if _, _, err := mailSettingsFromForm(mailForm(moved), stored); err == nil {
		t.Error("the stored password was reused for a different server")
	}
	moved.Set("password", "typed-again")
	if s, _, err := mailSettingsFromForm(mailForm(moved), stored); err != nil || s.Password != "typed-again" {
		t.Errorf("re-entered password: %q %v", s.Password, err)
	}
}

func TestMailSettingsFromForm_Validation(t *testing.T) {
	ok := url.Values{"host": {"mail.example.org"}, "security": {"tls"}, "from": {"a@example.org"}}
	if _, _, err := mailSettingsFromForm(mailForm(ok), webauth.SMTPSettings{}); err != nil {
		t.Fatalf("valid form refused: %v", err)
	}
	bad := []url.Values{
		{"host": {"mail.example.org"}, "security": {"rot13"}, "from": {"a@example.org"}},
		{"host": {"mail.example.org:25"}, "security": {"tls"}, "from": {"a@example.org"}},
		{"host": {"mail.example.org"}, "security": {"tls"}, "from": {"a@example.org"}, "port": {"70000"}},
		{"host": {"mail.example.org"}, "security": {"tls"}, "from": {"not an address"}},
		{"host": {"mail.example.org"}, "security": {"tls"}},
		{"host": {"mail.example.org"}, "security": {"none"}, "from": {"a@example.org"}, "username": {"u"}, "password": {"p"}},
		{"host": {"mail.example.org"}, "security": {"tls"}, "from": {"a@example.org"}, "public_url": {"ftp://x"}},
		{"host": {"mail.example.org"}, "security": {"tls"}, "from": {"a@example.org"}, "public_url": {"https://x/?a=1"}},
	}
	for i, v := range bad {
		if _, _, err := mailSettingsFromForm(mailForm(v), webauth.SMTPSettings{}); err == nil {
			t.Errorf("case %d accepted: %v", i, v)
		}
	}
}

func TestValidAddress_RejectsHeaderInjection(t *testing.T) {
	for _, a := range []string{"a@b.c\r\nBcc: x@y.z", "Name <a@b.c>", "", "a@b.c\n"} {
		if validAddress(a) {
			t.Errorf("validAddress(%q) = true", a)
		}
	}
	if !validAddress("ops@example.org") {
		t.Error("plain address refused")
	}
}

func TestMailGet_NeverShowsPassword(t *testing.T) {
	store := &webauth.Store{SMTP: &webauth.SMTPSettings{Host: "mail.example.org", Password: "s3cret-value", From: "a@example.org"}}
	w := httptest.NewRecorder()
	handleMailGet(store)(w, httptest.NewRequest(http.MethodGet, "/config/mail", nil))
	if strings.Contains(w.Body.String(), "s3cret-value") {
		t.Error("SMTP password sent to the browser")
	}
	if !strings.Contains(w.Body.String(), `placeholder="unchanged"`) {
		t.Error("page does not say a password is stored")
	}
}
