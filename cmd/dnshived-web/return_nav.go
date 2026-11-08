package main

import (
	"net/http"
	"net/url"
	"strings"
)

const returnCookieName = "dnshived_return"

// prevCookieName holds the page the operator was on before the current one,
// the target of every "back" link on a view page.
const prevCookieName = "dnshived_prev"

var returnSkipPrefixes = []string{
	"/pending", "/audit", "/logs/dnsmasq", "/logs/daemon", "/backup/download",
	"/config/export", "/backup/list", "/static", "/favicon", "/api/", "/healthz",
}

func isSafeReturnPath(p string) bool {
	if p == "" || p[0] != '/' || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return false
	}
	for _, c := range p {
		if c < 0x20 || c == 0x7f || c == '\\' || c == '"' || c == '<' || c == '>' {
			return false
		}
	}
	return true
}

func readReturnCookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	p, err := url.QueryUnescape(c.Value)
	if err != nil || !isSafeReturnPath(p) {
		return ""
	}
	return p
}

func setReturnCookie(w http.ResponseWriter, r *http.Request, name, page string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    url.QueryEscape(page),
		Path:     "/",
		MaxAge:   24 * 60 * 60,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

// rememberReturnPage records r as the operator's last page, when it is a
// full-page browser navigation to a page worth returning to. The page that was
// current before moves to the previous-page cookie; a reload or an automatic
// refresh of the same address changes neither.
func rememberReturnPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || !strings.Contains(r.Header.Get("Accept"), "text/html") {
		return
	}
	p := r.URL.RequestURI()
	if !isSafeReturnPath(p) {
		return
	}
	for _, skip := range returnSkipPrefixes {
		if strings.HasPrefix(r.URL.Path, skip) {
			return
		}
	}
	cur := readReturnCookie(r, returnCookieName)
	if cur == p {
		return
	}
	if cur != "" {
		setReturnCookie(w, r, prevCookieName, cur)
	}
	setReturnCookie(w, r, returnCookieName, p)
}

// backTarget resolves the link of a "back" button on a view page: the page the
// operator came from, or the caller's own link when there is none. While a page
// renders, the cookies still describe the state before this request: the
// current-page cookie holds the page that was open before this one, unless this
// request is a reload or a refresh of the same page, in which case that page is in
// the previous-page cookie.
func backTarget(r *http.Request, link, text string) (string, string) {
	pathOf := func(p string) string {
		if i := strings.IndexAny(p, "?#"); i >= 0 {
			return p[:i]
		}
		return p
	}
	p := readReturnCookie(r, returnCookieName)
	if p == "" || pathOf(p) == r.URL.Path {
		p = readReturnCookie(r, prevCookieName)
	}
	if p == "" || pathOf(p) == r.URL.Path {
		return link, text
	}
	return p, "back to " + returnPageLabel(p)
}

// returnPageLabel names a return target in operator terms.
func returnPageLabel(p string) string {
	path := p
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	switch {
	case path == "/" || path == "":
		return "overview"
	case strings.HasPrefix(path, "/scopes/wizard"):
		return "add-scope wizard"
	case strings.HasPrefix(path, "/scopes/"):
		return "scope " + strings.TrimPrefix(path, "/scopes/")
	case path == "/scopes":
		return "scopes"
	case strings.HasPrefix(path, "/config/scopes"):
		return "scope table"
	case strings.HasPrefix(path, "/config/dns"):
		return "DHCP & DNS"
	case path == "/config/mail" || strings.HasPrefix(path, "/security") || strings.HasPrefix(path, "/users"):
		return "security"
	case strings.HasPrefix(path, "/config"):
		return "cluster settings"
	case strings.HasPrefix(path, "/daemons"):
		return "daemons"
	case strings.HasPrefix(path, "/logs"):
		return "logs"
	case strings.HasPrefix(path, "/backup"):
		return "maintenance"
	case strings.HasPrefix(path, "/probes/"):
		return "probe detail"
	case strings.HasPrefix(path, "/probes"):
		return "probes"
	case strings.HasPrefix(path, "/templates"):
		return "templates"
	}
	return strings.TrimPrefix(path, "/")
}

// returnTarget resolves where a result page's primary link should lead:
// the remembered last page when there is a valid one, else Overview.
func returnTarget(r *http.Request) (link, text string) {
	c, err := r.Cookie(returnCookieName)
	if err != nil {
		return "/", "back to overview"
	}
	p, err := url.QueryUnescape(c.Value)
	if err != nil || !isSafeReturnPath(p) {
		return "/", "back to overview"
	}
	return p, "back to " + returnPageLabel(p)
}

// returnTargetOr is returnTarget with the caller's own link as the fallback
// when no page is remembered.
func returnTargetOr(r *http.Request, link, text string) (string, string) {
	if c, err := r.Cookie(returnCookieName); err != nil || c.Value == "" {
		return link, text
	}
	return returnTarget(r)
}

// withOverviewLink appends a second "back to overview" anchor to a result
// page's primary link text.
func withOverviewLink(link, text string) string {
	if link == "/" {
		return text
	}
	return text + `</a> &nbsp;|&nbsp; <a href="/">back to overview`
}
