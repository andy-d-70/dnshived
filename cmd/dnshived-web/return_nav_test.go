package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsSafeReturnPath(t *testing.T) {
	for _, ok := range []string{"/", "/scopes", "/scopes/core3-test", "/scopes?page=2", "/probes/x/y"} {
		if !isSafeReturnPath(ok) {
			t.Errorf("isSafeReturnPath(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "scopes", "//evil.example", "/\\evil", "http://evil", "/a\nb", `/a"b`, "/a<b>"} {
		if isSafeReturnPath(bad) {
			t.Errorf("isSafeReturnPath(%q) = true, want false (open redirect / injection)", bad)
		}
	}
}

func browserGet(path string) *http.Request {
	r := httptest.NewRequest("GET", path, nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	return r
}

func TestRememberReturnPage_SetsCookieForPagesNotPendingFlow(t *testing.T) {
	rec := httptest.NewRecorder()
	rememberReturnPage(rec, browserGet("/scopes/core3-test"))
	if len(rec.Result().Cookies()) != 1 {
		t.Fatalf("cookies = %v, want the return cookie set", rec.Result().Cookies())
	}
	for _, skip := range []string{"/pending", "/pending/commit", "/audit", "/logs/dnsmasq/core-1/core-dhcp"} {
		rec := httptest.NewRecorder()
		rememberReturnPage(rec, browserGet(skip))
		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s set a return cookie, want none", skip)
		}
	}
	// A background fetch (Accept */*) or a POST never becomes the target.
	r := httptest.NewRequest("GET", "/scopes", nil)
	rec = httptest.NewRecorder()
	rememberReturnPage(rec, r)
	if len(rec.Result().Cookies()) != 0 {
		t.Error("non-browser GET set a return cookie")
	}
	post := browserGet("/scopes")
	post.Method = "POST"
	rec = httptest.NewRecorder()
	rememberReturnPage(rec, post)
	if len(rec.Result().Cookies()) != 0 {
		t.Error("POST set a return cookie")
	}
}

func TestReturnTarget_RoundTripAndFallbacks(t *testing.T) {
	// Round trip through the real cookie writer.
	rec := httptest.NewRecorder()
	rememberReturnPage(rec, browserGet("/scopes/core3-test"))
	r := httptest.NewRequest("POST", "/pending/commit", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	link, text := returnTarget(r)
	if link != "/scopes/core3-test" || text != "back to scope core3-test" {
		t.Errorf("returnTarget = (%q, %q), want the scope page", link, text)
	}
	// No cookie → overview.
	link, text = returnTarget(httptest.NewRequest("POST", "/pending/commit", nil))
	if link != "/" || text != "back to overview" {
		t.Errorf("no cookie: (%q, %q), want overview", link, text)
	}
	// Tampered cookie pointing off-site → overview.
	bad := httptest.NewRequest("POST", "/pending/commit", nil)
	bad.AddCookie(&http.Cookie{Name: returnCookieName, Value: "%2F%2Fevil.example"})
	if link, _ := returnTarget(bad); link != "/" {
		t.Errorf("tampered cookie: link = %q, want /", link)
	}
}

func TestWithOverviewLink(t *testing.T) {
	if got := withOverviewLink("/", "back to overview"); got != "back to overview" {
		t.Errorf("overview target must not be doubled, got %q", got)
	}
	got := withOverviewLink("/scopes", "back to scopes")
	if !strings.Contains(got, `<a href="/">back to overview`) || !strings.HasPrefix(got, "back to scopes</a>") {
		t.Errorf("got %q, want the scope link closed and a second overview anchor opened", got)
	}
}

// Disabling a scope from the Scopes list returns to the list, not the
// scope page; without a remembered page the handler's own link is used.
func TestReturnTargetOr_PrefersRememberedPage(t *testing.T) {
	rec := httptest.NewRecorder()
	rememberReturnPage(rec, browserGet("/scopes"))
	r := httptest.NewRequest("POST", "/scopes/office/toggle-disabled", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	if link, text := returnTargetOr(r, "/scopes/office", "back to scope"); link != "/scopes" || text != "back to scopes" {
		t.Errorf("returnTargetOr = (%q, %q), want the scopes list", link, text)
	}
	bare := httptest.NewRequest("POST", "/scopes/office/toggle-disabled", nil)
	if link, text := returnTargetOr(bare, "/scopes/office", "back to scope"); link != "/scopes/office" || text != "back to scope" {
		t.Errorf("no cookie: (%q, %q), want the handler's own link", link, text)
	}
}
