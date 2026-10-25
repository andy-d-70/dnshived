// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"dnshived/internal/loglevel"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"dnshived/internal/bootstrap"
	"dnshived/internal/discovery"
	"dnshived/internal/sysinfo"
)

// defaultBootstrapDataDir mirrors cluster.json.example's own default
// data_dir.
const defaultBootstrapDataDir = "/var/lib/dnshived"

const defaultBootstrapOTPPath = "/run/dnshived-bootstrap/otp"

// defaultControlPort is the cluster control API's own port convention
// (9443).
const defaultControlPort = "9443"

// bootstrapUnits are the units DetectExisting checks for ActiveState as
// evidence this node was already configured.
var bootstrapUnits = []string{
	"dnshived-web.service",
}

// bootstrapPaths derives the full set of locations
// bootstrap.DetectExisting checks from cfgPath.
func bootstrapPaths(cfgPath, dataDir string) bootstrap.Paths {
	dir := filepath.Dir(cfgPath)
	return bootstrap.Paths{
		ClusterConfigPath: cfgPath,
		ProbeConfigPath:   filepath.Join(dir, "probe.json"),
		WebUsersPath:      filepath.Join(dir, "webui-users.json"),
		DataDir:           dataDir,
		Units:             bootstrapUnits,
	}
}

// bootstrapStatusResponse is GET /api/v1/bootstrap/status's body.
type bootstrapStatusResponse struct {
	Configured bool     `json:"configured"`
	Hostname   string   `json:"hostname"`
	Version    string   `json:"version"`
	OS         string   `json:"os,omitempty"`
	Interfaces []string `json:"interfaces,omitempty"`
	// MgmtInterface carries the address this request arrived on, i.e. the
	// interface the cluster reaches this node through.
	MgmtInterface string `json:"mgmt_interface,omitempty"`
}

// bootstrapStatusHandler serves this node's unconfigured status.
func bootstrapStatusHandler(hostname, ver string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ifaces, _ := discovery.UnconfiguredInterfaces()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bootstrapStatusResponse{
			Configured:    false,
			Hostname:      hostname,
			Version:       ver,
			OS:            sysinfo.Collect().OS,
			Interfaces:    ifaces,
			MgmtInterface: interfaceForLocalAddr(r),
		})
	}
}

// bootstrapProbeInterfaceRequest is POST /api/v1/bootstrap/probe-
// interface's body.
type bootstrapProbeInterfaceRequest struct {
	Interface  string `json:"interface"`
	DurationMS int    `json:"duration_ms"`
}

// bootstrapProbeInterfaceMaxDuration caps how long a single burst can run.
const bootstrapProbeInterfaceMaxDuration = 15 * time.Second

// bootstrapProbeInterfaceHandler (POST /api/v1/bootstrap/probe-interface)
// runs one interface's own burst SYNCHRONOUSLY.
func bootstrapProbeInterfaceHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req bootstrapProbeInterfaceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Interface == "" {
			http.Error(w, "interface is required", http.StatusBadRequest)
			return
		}
		dur := time.Duration(req.DurationMS) * time.Millisecond
		if dur <= 0 || dur > bootstrapProbeInterfaceMaxDuration {
			dur = bootstrapProbeInterfaceMaxDuration
		}
		known, _ := discovery.UnconfiguredInterfaces()
		valid := false
		for _, k := range known {
			if k == req.Interface {
				valid = true
				break
			}
		}
		if !valid {
			http.Error(w, "not a recognized unconfigured interface on this node", http.StatusBadRequest)
			return
		}

		hostname, _ := os.Hostname()
		ctx, cancel := context.WithTimeout(r.Context(), dur)
		defer cancel()
		discovery.BroadcastOnInterface(ctx, req.Interface, hostname)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}
}

// bootstrapSessionCookie names the cookie that marks a browser as having
// already entered the correct join code.
const bootstrapSessionCookie = "dnshived_bootstrap_session"

// bootstrapSession holds this bootstrap-mode process's single active
// session token, minted once a correct join code is submitted.
type bootstrapSession struct {
	mu    sync.Mutex
	token string // empty until a correct code has been submitted once
}

// issue mints and stores a fresh random session token, invalidating any
// previous one — only one operator session is meaningful at a time.
func (s *bootstrapSession) issue() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	s.mu.Lock()
	s.token = token
	s.mu.Unlock()
	return token, nil
}

func (s *bootstrapSession) valid(token string) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) == 1
}

// bootstrapSessionMiddleware gates next behind a valid session cookie.
func bootstrapSessionMiddleware(sess *bootstrapSession, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(bootstrapSessionCookie)
		if err != nil || !sess.valid(cookie.Value) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// bootstrapLoginData feeds bootstrapLoginTmpl — Error is only set to
// re-render the same page with a message after a wrong code, never on the
// initial GET.
type bootstrapLoginData struct {
	Error string
}

var bootstrapLoginTmpl = template.Must(template.New("bootstrap-login").Parse(`<!doctype html>
<title>dnshived — enter join code</title>
` + bootstrapStyleHTML + `
<div class="card">
<h1>Enter this node's join code</h1>
<p class="hint">Read it off this node's own console or journal (<code>journalctl -u dnshived</code>) — proof of physical access before anything here is trusted.</p>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<form method="post" action="/login">
<label>Join code: <input type="password" name="code" autofocus></label>
<button type="submit">Continue</button>
</form>
</div>
`))

// bootstrapLoginHandler serves the join-code form (GET) and validates a
// submission (POST).
func bootstrapLoginHandler(otp string, sess *bootstrapSession) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			code := r.FormValue("code")
			if subtle.ConstantTimeCompare([]byte(code), []byte(otp)) == 1 {
				token, err := sess.issue()
				if err != nil {
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
				http.SetCookie(w, &http.Cookie{
					Name:     bootstrapSessionCookie,
					Value:    token,
					Path:     "/",
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
				})
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			bootstrapLoginTmpl.Execute(w, bootstrapLoginData{Error: "Wrong join code — try again."})
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		bootstrapLoginTmpl.Execute(w, bootstrapLoginData{})
	}
}

// newBootstrapMux builds the complete bootstrap-mode route table.
func newBootstrapMux(hostname, otp, cfgPath string, state *builderState, sess *bootstrapSession) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/bootstrap/status", bootstrapStatusHandler(hostname, version))
	mux.HandleFunc("POST /api/v1/bootstrap/probe-interface", bootstrapProbeInterfaceHandler())
	mux.HandleFunc("POST /api/v1/bootstrap/adopt", bootstrapAdoptHandler(otp, cfgPath))
	mux.HandleFunc("GET /login", bootstrapLoginHandler(otp, sess))
	mux.HandleFunc("POST /login", bootstrapLoginHandler(otp, sess))
	controlPort := defaultControlPort
	mux.HandleFunc("GET /", bootstrapSessionMiddleware(sess, bootstrapSetupHandler(hostname, controlPort, state)))
	mux.HandleFunc("POST /setup/role", bootstrapSessionMiddleware(sess, bootstrapSetRoleHandler(hostname, controlPort, state)))
	mux.HandleFunc("POST /setup/network", bootstrapSessionMiddleware(sess, bootstrapSetNetworkHandler(hostname, controlPort, state)))
	mux.HandleFunc("POST /setup/mgmt-vip", bootstrapSessionMiddleware(sess, bootstrapSetMgmtVIPHandler(hostname, controlPort, state)))
	mux.HandleFunc("POST /setup/tls", bootstrapSessionMiddleware(sess, bootstrapSetTLSHandler(hostname, controlPort, state)))
	mux.HandleFunc("POST /setup/nodes", bootstrapSessionMiddleware(sess, bootstrapAddNodeHandler(hostname, controlPort, state)))
	mux.HandleFunc("POST /setup/commit", bootstrapSessionMiddleware(sess, bootstrapCommitHandler(cfgPath, state)))
	return mux
}

// runBootstrapMode is entered when cfgPath doesn't exist.
func runBootstrapMode(cfgPath, addr, tlsAddr, dataDir, otpPath string) {
	paths := bootstrapPaths(cfgPath, dataDir)
	findings := bootstrap.DetectExisting(paths)
	if !findings.Fresh() {
		loglevel.Warnf("[BOOTSTRAP:REFUSE] %s is missing, but this node isn't fresh — refusing to auto-bootstrap", cfgPath)
		loglevel.Warnf("[BOOTSTRAP:REFUSE] found: %s", findings.String())
		loglevel.Warnf("[BOOTSTRAP:REFUSE] resolve this by hand before retrying — this is not a self-service action")
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(otpPath), 0o750); err != nil {
		log.Fatalf("[BOOTSTRAP:INIT] create %s: %v", filepath.Dir(otpPath), err)
	}
	otp, err := bootstrap.LoadOrCreateOTP(otpPath)
	if err != nil {
		log.Fatalf("[BOOTSTRAP:INIT] otp: %v", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	loglevel.Infof("[BOOTSTRAP:READY] this node is not yet configured (no %s)", cfgPath)
	loglevel.Infof("[BOOTSTRAP:READY] hostname: %s", hostname)
	loglevel.Infof("[BOOTSTRAP:READY] join code: %s (the same code for a core role and for a probe role)", otp)
	loglevel.Infof("[BOOTSTRAP:READY] open http://%s/ (or https://%s/, self-signed) and enter the join code above to continue", addr, tlsAddr)

	loglevel.Infof("[DISCOVERY] broadcasting as unclaimed on port %d every 5s", discovery.Port)
	go discovery.Broadcast(context.Background(), hostname, version, discovery.PortFromAddr(addr, 80))

	mux := newBootstrapMux(hostname, otp, cfgPath, &builderState{}, &bootstrapSession{})

	certPEM, keyPEM, err := genSelfSignedCert([]string{"localhost", "127.0.0.1", hostname})
	if err != nil {
		log.Fatalf("[BOOTSTRAP:INIT] generate self-signed certificate: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("[BOOTSTRAP:INIT] parse generated certificate: %v", err)
	}
	tlsSrv := &http.Server{Addr: tlsAddr, Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	go func() {
		if err := tlsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			loglevel.Warnf("[BOOTSTRAP:INIT] https listener on %s: %v", tlsAddr, err)
		}
	}()

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[BOOTSTRAP:INIT] listen on %s: %v", addr, err)
	}
}

func interfaceForLocalAddr(r *http.Request) string {
	la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return ""
	}
	host, _, err := net.SplitHostPort(la.String())
	if err != nil {
		return ""
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() {
		return ""
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.Equal(ip) {
				return iface.Name
			}
		}
	}
	return ""
}
