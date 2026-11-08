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

func TestBackTarget_FollowsTheRealCookieSequence(t *testing.T) {
	jar := map[string]*http.Cookie{}
	// visit plays one browser navigation: the handler reads the request's cookies,
	// then the middleware's response cookies replace them, as a browser would.
	visit := func(path string) (string, string) {
		req := browserGet(path)
		for _, c := range jar {
			req.AddCookie(c)
		}
		link, text := backTarget(req, "/logs", "back to logs")
		rec := httptest.NewRecorder()
		rememberReturnPage(rec, req)
		for _, c := range rec.Result().Cookies() {
			jar[c.Name] = c
		}
		return link, text
	}
	if link, _ := visit("/"); link != "/logs" {
		t.Errorf("the first page has no way back, want the fallback, got %q", link)
	}
	if link, text := visit("/daemons"); link != "/" || text != "back to overview" {
		t.Errorf("first visit of daemons from the overview = (%q, %q), want the overview", link, text)
	}
	if link, _ := visit("/daemons"); link != "/" {
		t.Errorf("a reload must keep the way back, got %q", link)
	}
	if link, _ := visit("/daemons"); link != "/" {
		t.Errorf("a second reload must keep the way back, got %q", link)
	}
	visit("/logs")
	if link, text := visit("/daemons"); link != "/logs" || text != "back to logs" {
		t.Errorf("daemons from the logs = (%q, %q), want the logs", link, text)
	}
	visit("/config")
	if link, text := visit("/daemons"); link != "/config" || text != "back to cluster settings" {
		t.Errorf("daemons from the cluster settings = (%q, %q)", link, text)
	}
	// An unsafe value is never followed.
	bad := browserGet("/daemons")
	bad.AddCookie(&http.Cookie{Name: returnCookieName, Value: "%2F%2Fevil.example"})
	if link, _ := backTarget(bad, "/logs", "back to logs"); link != "/logs" {
		t.Errorf("an unsafe page must fall back, got %q", link)
	}
}

func TestBackLinks_ViewPagesUseTheCameFromTarget(t *testing.T) {
	var buf strings.Builder
	data := daemonsPageData{BackHref: "/", BackText: "back to overview"}
	if err := daemonsTmpl.Execute(&buf, data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `<a href="/">&larr; back to overview</a>`) {
		t.Error("the Daemons page must show the came-from link")
	}
	if strings.Contains(buf.String(), `href="/config">`) {
		t.Error("the Daemons page must not link to the cluster settings as a fixed back target")
	}
}
