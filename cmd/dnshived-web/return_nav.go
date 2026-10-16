package main

import (
	"net/http"
	"net/url"
	"strings"
)

const returnCookieName = "dnshived_return"

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

// rememberReturnPage records r as the operator's last page, when it is a
// full-page browser navigation to a page worth returning to.
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
	http.SetCookie(w, &http.Cookie{
		Name:     returnCookieName,
		Value:    url.QueryEscape(p),
		Path:     "/",
		MaxAge:   24 * 60 * 60,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
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
	case strings.HasPrefix(path, "/config"):
		return "cluster config"
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
