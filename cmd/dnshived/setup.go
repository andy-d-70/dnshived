// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/discovery"
)

// setupRoles are the node-role choices the cluster-setup wizard offers.
var setupRoles = []string{config.RoleCore1, config.RoleCore2, config.RoleCore3, "probe"}

// isValidSetupRole reports whether role is one of setupRoles.
func isValidSetupRole(role string) bool {
	for _, r := range setupRoles {
		if r == role {
			return true
		}
	}
	return false
}

// builderState holds the cluster-setup wizard's accumulated choices for
// this bootstrap-mode process.
type builderState struct {
	mu       sync.Mutex
	role     string
	selfAddr string
	nodes    []clusterNode // other nodes added via /setup/nodes — see cluster_setup.go

	// mgmtVIP/mgmtVRRPID/mgmtIface: the optional cluster-wide management VIP
	// (see cluster_setup.go's buildClusterConfig).
	mgmtVIP    string
	mgmtVRRPID int
	mgmtIface  string

	// tlsCertPEM/tlsKeyPEM: operator-pasted TLS material for the web UI,
	// PEM-encoded.
	tlsCertPEM string
	tlsKeyPEM  string

	// platformMgmt/platformWorkers: the cluster-wide Platform fields
	// (internal/config.Cluster.Platform).
	platformMgmt    string
	platformWorkers []string
}

func (b *builderState) setRole(role string) error {
	if !isValidSetupRole(role) {
		return &setupError{msg: "invalid role: " + role}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.role = role
	return nil
}

func (b *builderState) getRole() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.role
}

// setSelfAddr records this node's own reachable address.
func (b *builderState) setSelfAddr(addr string) error {
	if addr == "" {
		return &setupError{msg: "address is required"}
	}
	if _, port, err := net.SplitHostPort(addr); err != nil {
		return &setupError{msg: "address must be host:port, e.g. 192.0.2.22:9443: " + err.Error()}
	} else if port == "" {
		return &setupError{msg: "address must include a port, e.g. 192.0.2.22:9443"}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.selfAddr = addr
	return nil
}

func (b *builderState) getSelfAddr() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.selfAddr
}

// detectInterfaceFunc resolves a local IP to the network interface that
// owns it.
var detectInterfaceFunc = detectInterfaceForIP

func detectInterfaceForIP(ip string) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.String() == ip {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no local interface owns %s", ip)
}

// detectOutboundAddrFunc resolves this node's own default outbound
// address.
var detectOutboundAddrFunc = detectDefaultOutboundAddr

// detectDefaultOutboundAddr returns a real "host:port" DEFAULT for this
// node's own control_addr.
func detectDefaultOutboundAddr(controlPort string) (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, controlPort), nil
}

// selfAddrFromRequest derives this node's own reachable address directly
// from the live HTTP connection the operator is using right now to reach
// this wizard.
func selfAddrFromRequest(r *http.Request, controlPort string) (string, error) {
	if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if host, _, err := net.SplitHostPort(addr.String()); err == nil && host != "" {
			return net.JoinHostPort(host, controlPort), nil
		}
	}
	return detectOutboundAddrFunc(controlPort)
}

// discoveredInterfacesFunc resolves the set of local interfaces with no
// IPv4 address of their own.
var discoveredInterfacesFunc = discovery.UnconfiguredInterfaces

// setPlatform validates and records the cluster-wide Platform fields.
func (b *builderState) setPlatform(mgmt string, workers []string) error {
	mgmt = strings.TrimSpace(mgmt)
	if mgmt == "" {
		return &setupError{msg: "management interface is required"}
	}
	var cleaned []string
	seen := make(map[string]bool, len(workers))
	for _, w := range workers {
		w = strings.TrimSpace(w)
		if w == "" || seen[w] {
			continue
		}
		if w == mgmt {
			return &setupError{msg: "the management interface (" + mgmt + ") can't also be a worker trunk — it's already protected/reserved"}
		}
		seen[w] = true
		cleaned = append(cleaned, w)
	}
	b.mu.Lock()
	b.platformMgmt, b.platformWorkers = mgmt, cleaned
	b.mu.Unlock()
	return nil
}

func (b *builderState) getPlatform() (mgmt string, workers []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.platformMgmt, append([]string{}, b.platformWorkers...)
}

// setMgmtVIP validates and records the optional cluster-wide management
// VIP.
func (b *builderState) setMgmtVIP(vip string, vrrpID int) error {
	if vip == "" {
		b.mu.Lock()
		b.mgmtVIP, b.mgmtVRRPID, b.mgmtIface = "", 0, ""
		b.mu.Unlock()
		return nil
	}
	if _, _, err := net.ParseCIDR(vip); err != nil {
		return &setupError{msg: "management VIP must be an address with a prefix, e.g. 192.0.2.230/24: " + err.Error()}
	}
	if vrrpID < 1 || vrrpID > 255 {
		return &setupError{msg: "VRRP ID must be between 1 and 255"}
	}

	self := b.getSelfAddr()
	if self == "" {
		return &setupError{msg: "set this node's own address first"}
	}
	iface, err := detectInterfaceFunc(hostOnly(self))
	if err != nil {
		return &setupError{msg: "couldn't determine which local interface serves " + hostOnly(self) + " — the management VIP needs a real interface, not a guess: " + err.Error()}
	}

	b.mu.Lock()
	b.mgmtVIP, b.mgmtVRRPID, b.mgmtIface = vip, vrrpID, iface
	b.mu.Unlock()
	return nil
}

func (b *builderState) getMgmtVIP() (vip string, vrrpID int, iface string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.mgmtVIP, b.mgmtVRRPID, b.mgmtIface
}

// setTLS validates and records operator-pasted TLS material for the web
// UI.
func (b *builderState) setTLS(certPEM, keyPEM string) error {
	certPEM = strings.TrimSpace(certPEM)
	keyPEM = strings.TrimSpace(keyPEM)
	if certPEM == "" && keyPEM == "" {
		b.mu.Lock()
		b.tlsCertPEM, b.tlsKeyPEM = "", ""
		b.mu.Unlock()
		return nil
	}
	if certPEM == "" || keyPEM == "" {
		return &setupError{msg: "provide both the certificate and the private key, or leave both blank to use a generated self-signed one"}
	}
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return &setupError{msg: "certificate/key don't form a valid pair: " + err.Error()}
	}

	b.mu.Lock()
	b.tlsCertPEM, b.tlsKeyPEM = certPEM, keyPEM
	b.mu.Unlock()
	return nil
}

func (b *builderState) getTLS() (certPEM, keyPEM string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tlsCertPEM, b.tlsKeyPEM
}

// setupError is a minimal error type for setup validation failures —
// doesn't need fmt.Errorf's formatting machinery for a single fixed
// message.
type setupError struct{ msg string }

func (e *setupError) Error() string { return e.msg }

// bootstrapSetupData feeds bootstrapSetupTmpl.
const (
	stepRole    = 1
	stepNetwork = 2
	stepMgmtVIP = 3
	stepTLS     = 4
	stepNodes   = 5
	stepReview  = 6
)

// parseStepParam reads the "step" query param a step's own Save/Skip/Back
// link redirects to.
func parseStepParam(raw string) int {
	n, err := strconv.Atoi(raw)
	if err != nil || n < stepRole || n > stepReview {
		return stepRole
	}
	return n
}

// networkCandidate is one row on the wizard's Network step.
type networkCandidate struct {
	Name    string
	Label   string
	Checked bool
}

type bootstrapSetupData struct {
	Hostname          string
	CurrentStep       int
	CurrentRole       string
	CurrentAddr       string
	CurrentMgmt       string
	NetworkCandidates []networkCandidate
	CurrentMgmtVIP    string
	CurrentMgmtVRRPID string
	CurrentTLSCert    string
	TLSKeySet         bool
	Roles             []string
	Nodes             []clusterNode
	ReadyToCommit     bool
	Error             string
}

// newBootstrapSetupData builds bootstrapSetupData from the builder state's
// current values.
func newBootstrapSetupData(hostname, controlPort string, state *builderState) bootstrapSetupData {
	vip, vrrpID, _ := state.getMgmtVIP()
	vrrpIDStr := ""
	if vip != "" {
		vrrpIDStr = strconv.Itoa(vrrpID)
	}
	certPEM, keyPEM := state.getTLS()

	addr := state.getSelfAddr()
	if addr == "" {
		if detected, err := detectOutboundAddrFunc(controlPort); err == nil {
			addr = detected
		}
	}

	mgmt, workers := state.getPlatform()
	mgmtDefault := mgmt
	if mgmtDefault == "" && addr != "" {
		if iface, err := detectInterfaceFunc(hostOnly(addr)); err == nil {
			mgmtDefault = iface
		}
	}

	savedSet := make(map[string]bool, len(workers))
	for _, w := range workers {
		savedSet[w] = true
	}
	var candidateNames []string
	candidateNames = append(candidateNames, workers...)
	if discovered, err := discoveredInterfacesFunc(); err == nil {
		for _, d := range discovered {
			if d == mgmtDefault || savedSet[d] {
				continue
			}
			candidateNames = append(candidateNames, d)
		}
	}
	candidates := make([]networkCandidate, 0, len(candidateNames))
	for i, name := range candidateNames {
		candidates = append(candidates, networkCandidate{
			Name:    name,
			Label:   fmt.Sprintf("Trunk %d", i+1),
			Checked: savedSet[name] || len(workers) == 0,
		})
	}

	return bootstrapSetupData{
		Hostname:          hostname,
		CurrentStep:       stepRole,
		CurrentRole:       state.getRole(),
		CurrentAddr:       addr,
		CurrentMgmt:       mgmtDefault,
		NetworkCandidates: candidates,
		CurrentMgmtVIP:    vip,
		CurrentMgmtVRRPID: vrrpIDStr,
		CurrentTLSCert:    certPEM,
		TLSKeySet:         keyPEM != "",
		Roles:             setupRoles,
		Nodes:             state.getNodes(),
		ReadyToCommit:     hasAtLeastOneCoreNode(state.allNodes()),
	}
}

// bootstrapSetupTmpl is the cluster-setup wizard's real page.
const bootstrapStyleHTML = `<style>
:root{--bg:#f2f4f7;--panel:#fff;--border:#dde1e7;--text:#1b1f24;--muted:#68707b;--accent:#2563eb;--head:#eaedf2}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1.5rem;max-width:760px;background:var(--bg);color:var(--text);
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
font-size:14px;line-height:1.55}
h1{font-size:1.35rem;margin:0 0 .25rem;font-weight:650}
h2{font-size:1.05rem;font-weight:600;margin:0 0 .6rem}
p{color:var(--text)}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.steps{display:flex;flex-wrap:wrap;gap:.15rem;background:var(--panel);border:1px solid var(--border);
border-radius:8px;padding:.35rem .5rem;box-shadow:0 1px 2px rgba(0,0,0,.06);font-size:.85rem;margin:1rem 0 1.4rem}
.steps a{padding:.3rem .6rem;border-radius:6px;color:var(--text);font-weight:600}
.steps a:hover{background:var(--bg);text-decoration:none}
.steps a.current{background:var(--accent);color:#fff}
.card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:1.25rem 1.4rem;
box-shadow:0 1px 2px rgba(0,0,0,.06)}
.step-label{color:var(--muted);font-size:.8rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;margin:0 0 .3rem}
.hint{color:var(--muted);font-size:.88rem;margin:0 0 1rem}
form label{display:block;margin:0 0 .9rem;font-weight:500}
form input[type=text],form input[type=password],form textarea,form select{
display:block;width:100%;margin-top:.3rem;padding:.5rem .6rem;border:1px solid var(--border);
border-radius:6px;font:inherit;background:#fff;color:var(--text)}
form textarea{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.82rem}
form input[type=radio],form input[type=checkbox]{margin-right:.4rem}
button{background:var(--accent);color:#fff;border:0;border-radius:6px;padding:.55rem 1.1rem;
font:inherit;font-weight:600;cursor:pointer}
button:hover{filter:brightness(1.08)}
.error{background:#fdeceb;border:1px solid #f3b9b3;color:#c0392b;border-radius:6px;
padding:.6rem .8rem;margin:0 0 1rem;font-weight:600}
.nav-links{margin-top:1rem;font-size:.88rem}
ul{padding-left:1.2rem}
li{margin:.2rem 0}
</style>`

var bootstrapSetupTmpl = template.Must(template.New("bootstrap-setup").Parse(`<!doctype html>
<title>dnshived — cluster setup</title>
` + bootstrapStyleHTML + `
<h1>{{.Hostname}}</h1>
<nav class="steps">
<a href="/?step=1"{{if eq .CurrentStep 1}} class="current"{{end}}>1. Role</a>
<a href="/?step=2"{{if eq .CurrentStep 2}} class="current"{{end}}>2. Network</a>
<a href="/?step=3"{{if eq .CurrentStep 3}} class="current"{{end}}>3. Management VIP</a>
<a href="/?step=4"{{if eq .CurrentStep 4}} class="current"{{end}}>4. TLS</a>
<a href="/?step=5"{{if eq .CurrentStep 5}} class="current"{{end}}>5. Other nodes</a>
<a href="/?step=6"{{if eq .CurrentStep 6}} class="current"{{end}}>6. Review</a>
</nav>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<div class="card">

{{if eq .CurrentStep 1}}
<p class="step-label">Step 1 of 6</p>
<h2>This node's role</h2>
<form method="post" action="/setup/role">
{{range .Roles}}
<label><input type="radio" name="role" value="{{.}}" required{{if eq . $.CurrentRole}} checked{{end}}> {{.}}</label><br>
{{end}}
<button type="submit">Next</button>
</form>
{{end}}

{{if eq .CurrentStep 2}}
<p class="step-label">Step 2 of 6</p>
<h2>Network (Platform)</h2>
<p class="hint">The management interface (the one this node is already reachable on — it answered the request that loaded this page) is pre-filled below — override it if this box actually manages the cluster through a different NIC. Worker trunks are the physical interfaces that will carry tagged VLANs for scopes (DHCP/DNS-served networks); interfaces with no IPv4 address of their own were auto-detected as candidates and are pre-checked, deselectable. Each one gets a stable, purely positional "Trunk N" identity (1-based, in the order checked/listed here) — the same identity every other node in this cluster will use to refer to the same logical trunk, even if its real interface name differs per node/OS.</p>
<form method="post" action="/setup/network">
<label>Management interface: <input type="text" name="mgmt" value="{{.CurrentMgmt}}" placeholder="eth0" required></label><br>
<p>Worker trunks (optional — needed only once you add scopes):</p>
{{range .NetworkCandidates}}
<label><input type="checkbox" name="workers" value="{{.Name}}"{{if .Checked}} checked{{end}}> {{.Label}} — {{.Name}}</label><br>
{{end}}
{{if not .NetworkCandidates}}<p>No unconfigured interfaces were detected on this box — that's fine, a cluster with zero worker trunks (and zero scopes) is a real, supported starting point. Add trunks later by re-visiting this step once real hardware is wired up.</p>{{end}}
<button type="submit">Save and continue</button>
</form>
<p class="nav-links"><a href="/?step=1">Back</a> · <a href="/?step=3">Skip</a></p>
{{end}}

{{if eq .CurrentStep 3}}
<p class="step-label">Step 3 of 6</p>
<h2>Management VIP (optional)</h2>
<p class="hint">A floating address shared by the whole cluster for reaching the web UI, regardless of which node currently holds it. Leave blank and continue to skip this entirely.</p>
<form method="post" action="/setup/mgmt-vip">
<label>Management VIP (e.g. 192.0.2.230/24): <input type="text" name="mgmt_vip" value="{{.CurrentMgmtVIP}}" placeholder="192.0.2.230/24"></label><br>
<label>VRRP ID (only used if a management VIP is set, default 60): <input type="text" name="vrrp_id" value="{{.CurrentMgmtVRRPID}}" placeholder="60"></label><br>
<button type="submit">Save and continue</button>
</form>
<p class="nav-links"><a href="/?step=2">Back</a> · <a href="/?step=4">Skip</a></p>
{{end}}

{{if eq .CurrentStep 4}}
<p class="step-label">Step 4 of 6</p>
<h2>TLS for the web UI (optional)</h2>
<p class="hint">A self-signed certificate is generated automatically at cluster creation if you leave this blank — covering every recorded node, the management VIP if set, and localhost. Paste your own certificate and key here instead if you have a real one.{{if .TLSKeySet}} <strong>A certificate/key pair is currently saved.</strong> Leave both fields blank and save to go back to the generated one.{{end}}</p>
<form method="post" action="/setup/tls">
<label>Certificate (PEM):<br><textarea name="tls_cert" rows="8" cols="72" placeholder="-----BEGIN CERTIFICATE-----">{{.CurrentTLSCert}}</textarea></label><br>
<label>Private key (PEM) — re-paste it every time you change the certificate, it is never echoed back:<br><textarea name="tls_key" rows="8" cols="72" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></label><br>
<button type="submit">Save and continue</button>
</form>
<p class="nav-links"><a href="/?step=3">Back</a> · <a href="/?step=5">Skip</a></p>
{{end}}

{{if eq .CurrentStep 5}}
<p class="step-label">Step 5 of 6</p>
<h2>Other nodes in this cluster (optional)</h2>
{{if .Nodes}}<ul>
{{range .Nodes}}<li>{{.Role}} at {{.Addr}}{{if .TrunkParent}} (trunk: {{.TrunkParent}}){{end}}{{template "detected" .}}</li>{{end}}
</ul>{{else}}<p>None recorded yet — a single-node cluster is a real, supported starting point; onboard peers and a probe host later too, whenever you're ready.</p>{{end}}
<form method="post" action="/setup/nodes">
<label>Address: <input type="text" name="addr" placeholder="192.0.2.23:9443" required></label><br>
<label>Role:
<select name="role" required>
{{range .Roles}}<option value="{{.}}">{{.}}</option>{{end}}
</select>
</label><br>
<label>Join code (read from that node's own console): <input type="password" name="otp" required></label><br>
<label>Trunk interface (probe role only, e.g. ens19): <input type="text" name="trunk_parent"></label><br>
<label title="Before a core node is added, this node listens on its trunks while the new node broadcasts on each of its interfaces. A trunk where nothing is heard is refused unless this is ticked; the new node then keeps this cluster's interface name for it."><input type="checkbox" name="allow_undetected"> Add anyway, even if the interface check cannot detect every trunk</label><br>
<button type="submit">Add node</button>
</form>
<p class="nav-links"><a href="/?step=4">Back</a> · <a href="/?step=6">Continue to review</a></p>
{{end}}

{{if eq .CurrentStep 6}}
<p class="step-label">Step 6 of 6</p>
<h2>Review before creating the cluster</h2>
<ul>
<li>Role: <strong>{{if .CurrentRole}}{{.CurrentRole}}{{else}}(not set){{end}}</strong></li>
<li>Address: <strong>{{if .CurrentAddr}}{{.CurrentAddr}}{{else}}(not set){{end}}</strong> <span class="hint">(detected automatically from this node's own connection)</span></li>
<li>Management interface: <strong>{{if .CurrentMgmt}}{{.CurrentMgmt}}{{else}}(not set){{end}}</strong></li>
<li>Worker trunks: {{if .NetworkCandidates}}<ul>{{range .NetworkCandidates}}{{if .Checked}}<li>{{.Label}} — {{.Name}}</li>{{end}}{{end}}</ul>{{else}}none — add scopes later once trunks are wired up{{end}}</li>
<li>Management VIP: {{if .CurrentMgmtVIP}}<strong>{{.CurrentMgmtVIP}}</strong> (VRRP ID {{.CurrentMgmtVRRPID}}){{else}}none{{end}}</li>
<li>TLS for the web UI: {{if .CurrentTLSCert}}an operator-provided certificate{{else}}a generated self-signed certificate{{end}}</li>
<li>Other nodes: {{if .Nodes}}<ul>{{range .Nodes}}<li>{{.Role}} at {{.Addr}}{{if .TrunkParent}} (trunk: {{.TrunkParent}}){{end}}{{template "detected" .}}</li>{{end}}</ul>{{else}}none — onboard peers and a probe host later{{end}}</li>
</ul>
<p>A single core node is a real, fully-supported starting point — optimal is 3 (core-1/core-2/core-3), but one does the job.</p>
{{if .ReadyToCommit}}
<form method="post" action="/setup/commit">
<button type="submit">Create cluster</button>
</form>
{{else}}
<p>This node's own role must be a core role (core-1, core-2, or core-3) — not "probe" — before the cluster can be created. <a href="/?step=1">Go back and choose one</a>.</p>
{{end}}
<p class="nav-links"><a href="/?step=5">Back</a></p>
{{end}}
</div>
{{define "detected"}}{{if ne .Role "probe"}} — mgmt: {{if .Mgmt}}{{.Mgmt}}{{else}}unknown{{end}}{{end}}{{if .Detected}} — interfaces: {{range $i, $d := .Detected}}{{if $i}}, {{end}}{{$d.Canonical}} → {{if $d.Local}}{{$d.Local}}{{else}}<strong class="crit">NOT DETECTED</strong>{{end}}{{end}}{{end}}{{end}}`))

// bootstrapSetupHandler serves the cluster-setup wizard's current step —
// only reachable through bootstrapSessionMiddleware.
func bootstrapSetupHandler(hostname, controlPort string, state *builderState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := newBootstrapSetupData(hostname, controlPort, state)
		data.CurrentStep = parseStepParam(r.URL.Query().Get("step"))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := bootstrapSetupTmpl.Execute(w, data); err != nil {
			log.Printf("[BOOTSTRAP:ERROR] render setup page: %v", err)
		}
	}
}

// renderSetupStepError redisplays the setup page on step with err shown
// inline.
func renderSetupStepError(w http.ResponseWriter, hostname, controlPort string, state *builderState, step int, err error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	data := newBootstrapSetupData(hostname, controlPort, state)
	data.CurrentStep = step
	data.Error = err.Error()
	bootstrapSetupTmpl.Execute(w, data)
}

// bootstrapSetRoleHandler handles step 1's POST.
func bootstrapSetRoleHandler(hostname, controlPort string, state *builderState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := state.setRole(r.FormValue("role")); err != nil {
			renderSetupStepError(w, hostname, controlPort, state, stepRole, err)
			return
		}
		if addr, err := selfAddrFromRequest(r, controlPort); err == nil {
			state.setSelfAddr(addr)
		}
		http.Redirect(w, r, "/?step=2", http.StatusSeeOther)
	}
}

func bootstrapSetNetworkHandler(hostname, controlPort string, state *builderState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			renderSetupStepError(w, hostname, controlPort, state, stepNetwork, &setupError{msg: "malformed form: " + err.Error()})
			return
		}
		if err := state.setPlatform(r.FormValue("mgmt"), r.Form["workers"]); err != nil {
			renderSetupStepError(w, hostname, controlPort, state, stepNetwork, err)
			return
		}
		http.Redirect(w, r, "/?step=3", http.StatusSeeOther)
	}
}

// bootstrapSetMgmtVIPHandler handles step 3's POST: the optional
// management VIP and VRRP ID.
func bootstrapSetMgmtVIPHandler(hostname, controlPort string, state *builderState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vip := strings.TrimSpace(r.FormValue("mgmt_vip"))
		vrrpID := 0
		if vip != "" {
			vrrpIDStr := strings.TrimSpace(r.FormValue("vrrp_id"))
			if vrrpIDStr == "" {
				vrrpIDStr = "60"
			}
			var err error
			vrrpID, err = strconv.Atoi(vrrpIDStr)
			if err != nil {
				renderSetupStepError(w, hostname, controlPort, state, stepMgmtVIP, &setupError{msg: "VRRP ID must be a number"})
				return
			}
		}
		if err := state.setMgmtVIP(vip, vrrpID); err != nil {
			renderSetupStepError(w, hostname, controlPort, state, stepMgmtVIP, err)
			return
		}
		http.Redirect(w, r, "/?step=4", http.StatusSeeOther)
	}
}

// bootstrapSetTLSHandler handles step 4's POST.
func bootstrapSetTLSHandler(hostname, controlPort string, state *builderState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := state.setTLS(r.FormValue("tls_cert"), r.FormValue("tls_key")); err != nil {
			renderSetupStepError(w, hostname, controlPort, state, stepTLS, err)
			return
		}
		http.Redirect(w, r, "/?step=5", http.StatusSeeOther)
	}
}

// maxCandidateInterfacesForInspect bounds the wizard's own trunk-
// correlation timeout (see bootstrapAddNodeHandler below).
const maxCandidateInterfacesForInspect = 12

func bootstrapAddNodeHandler(hostname, controlPort string, state *builderState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role := r.FormValue("role")
		addr := normalizeNodeAddr(r.FormValue("addr"), role, controlPort)
		otp := r.FormValue("otp")
		trunkParent := r.FormValue("trunk_parent")

		// Real physical-layer trunk correlation for core roles, BEFORE this node
		// is ever trusted.
		var override map[string]string
		var detected []trunkDetection
		var mgmt string
		if role != "probe" {
			_, workers := state.getPlatform()
			if len(workers) == 0 && addr != "" {
				if status, err := bootstrapStatusFromCandidate(coreBootstrapContactAddr(addr)); err == nil {
					mgmt = status.MgmtInterface
				}
			}
			if len(workers) > 0 && addr != "" {
				ctx, cancel := context.WithTimeout(r.Context(), inspectBurstDuration()*time.Duration(maxCandidateInterfacesForInspect)+10*time.Second)
				mapping, status, err := correlateCandidateInterfaces(ctx, workers, coreBootstrapContactAddr(addr))
				cancel()
				if err != nil {
					renderSetupStepError(w, hostname, controlPort, state, stepNodes,
						&setupError{msg: "could not reach candidate to correlate its interfaces: " + err.Error()})
					return
				}
				mgmt = status.MgmtInterface
				var missing []string
				for _, canonical := range workers {
					local := mapping[canonical]
					detected = append(detected, trunkDetection{Canonical: canonical, Local: local})
					if local == "" {
						missing = append(missing, canonical)
						continue
					}
					if local != canonical {
						if override == nil {
							override = make(map[string]string)
						}
						override[canonical] = local
					}
				}
				if len(missing) > 0 && r.FormValue("allow_undetected") == "" {
					renderSetupStepError(w, hostname, controlPort, state, stepNodes,
						&setupError{msg: "the interface check heard no interface of " + addr + " on trunk(s) " + strings.Join(missing, ", ") +
							" — check that node's cabling/bridges, or tick \"Add anyway\" to keep the cluster's interface name for those trunks"})
					return
				}
			}
		}

		if err := state.addNodeDetected(addr, role, otp, trunkParent, override, detected, mgmt); err != nil {
			renderSetupStepError(w, hostname, controlPort, state, stepNodes, err)
			return
		}
		http.Redirect(w, r, "/?step=5", http.StatusSeeOther)
	}
}
