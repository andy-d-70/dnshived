// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"dnshived/internal/webauth"
)

// fakeSMTP accepts plain SMTP sessions and hands every message body to got.
func fakeSMTP(t *testing.T) (host string, port int, got chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				rd := bufio.NewReader(c)
				say := func(s string) { c.Write([]byte(s + "\r\n")) }
				say("220 fake ESMTP")
				var data strings.Builder
				inData := false
				for {
					line, err := rd.ReadString('\n')
					if err != nil {
						return
					}
					if inData {
						if line == ".\r\n" {
							inData = false
							got <- data.String()
							say("250 queued")
							continue
						}
						data.WriteString(line)
						continue
					}
					switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
					case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
						say("250 fake")
					case strings.HasPrefix(cmd, "DATA"):
						inData = true
						say("354 go")
					case strings.HasPrefix(cmd, "QUIT"):
						say("221 bye")
						return
					default:
						say("250 ok")
					}
				}
			}(c)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ = strconv.Atoi(p)
	return h, port, got
}

func TestPasswordReset_EndToEnd(t *testing.T) {
	host, port, mails := fakeSMTP(t)
	store, repl, ref := usersFixture(t)
	hash, _ := webauth.HashPassword("old-password-1")
	store.Users = []webauth.User{{Name: "ops", Role: webauth.RoleScopeAdmin, Email: "ops@example.org", PasswordHash: hash}}
	store.SMTP = &webauth.SMTPSettings{Host: host, Port: port, Security: "none", From: "dnshived@example.org"}
	store.PublicURL = "https://dnshived.example.org:8443"
	resetRequests = &resetLimiter{hits: map[string][]time.Time{}}

	form := url.Values{"login": {"OPS@example.org"}}
	r := httptest.NewRequest(http.MethodPost, "/forgot", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleForgotPost(store, repl, ref)(w, r)
	if !strings.Contains(w.Body.String(), "If that account exists") {
		t.Fatalf("forgot answer: %s", w.Body.String())
	}

	var mail string
	select {
	case mail = <-mails:
	case <-time.After(5 * time.Second):
		t.Fatal("no reset mail sent")
	}
	m := regexp.MustCompile(`https://dnshived\.example\.org:8443/reset\?token=([A-Za-z0-9_-]+)`).FindStringSubmatch(mail)
	if m == nil {
		t.Fatalf("no reset link in mail:\n%s", mail)
	}
	token := m[1]
	if strings.Contains(string(mustMarshal(t, store)), token) {
		t.Error("the plain reset token is stored; only its hash may be")
	}

	g := httptest.NewRecorder()
	handleResetGet(store)(g, httptest.NewRequest(http.MethodGet, "/reset?token="+token, nil))
	if g.Code != http.StatusOK || !strings.Contains(g.Body.String(), `name="token"`) {
		t.Fatalf("reset form: %d", g.Code)
	}

	set := func(pw string) *httptest.ResponseRecorder {
		f := url.Values{"token": {token}, "new_password": {pw}, "confirm_password": {pw}}
		r := httptest.NewRequest(http.MethodPost, "/reset", strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleResetPost(store, repl, ref)(w, r)
		return w
	}
	if w := set("short"); w.Code != http.StatusBadRequest {
		t.Errorf("short password accepted: %d", w.Code)
	}
	if w := set("brand-new-pass-1"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login?msg=reset" {
		t.Fatalf("reset refused: %d %s", w.Code, w.Body.String())
	}
	u, _ := store.Lookup("ops")
	if !webauth.VerifyPassword("brand-new-pass-1", u.PasswordHash) || u.SessionEpoch != 1 {
		t.Errorf("password not set or sessions not ended: %+v", u)
	}
	if w := set("another-pass-12"); w.Code != http.StatusBadRequest {
		t.Error("a reset link worked twice")
	}
}

func TestForgot_UnknownUserSameAnswerNoMail(t *testing.T) {
	host, port, mails := fakeSMTP(t)
	store, repl, ref := usersFixture(t, webauth.User{Name: "nomail", Role: webauth.RoleReadonly})
	store.SMTP = &webauth.SMTPSettings{Host: host, Port: port, Security: "none", From: "dnshived@example.org"}
	resetRequests = &resetLimiter{hits: map[string][]time.Time{}}
	for _, login := range []string{"ghost", "nomail"} {
		r := httptest.NewRequest(http.MethodPost, "/forgot", strings.NewReader("login="+login))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleForgotPost(store, repl, ref)(w, r)
		if !strings.Contains(w.Body.String(), forgotAnswer) {
			t.Errorf("%s: different answer", login)
		}
	}
	select {
	case m := <-mails:
		t.Errorf("mail sent for an unknown/no-email user:\n%s", m)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestResetLimiter(t *testing.T) {
	l := &resetLimiter{hits: map[string][]time.Time{}}
	now := time.Now()
	for i := 0; i < resetLimitCount; i++ {
		if !l.allow("k", now) {
			t.Fatalf("request %d refused", i)
		}
	}
	if l.allow("k", now) {
		t.Error("limit not enforced")
	}
	if !l.allow("k", now.Add(resetLimitWindow+time.Second)) {
		t.Error("limit never expires")
	}
}

func mustMarshal(t *testing.T, s *webauth.Store) []byte {
	t.Helper()
	b, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
