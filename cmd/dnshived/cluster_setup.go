// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"crypto/rand"
	"dnshived/internal/loglevel"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"dnshived/internal/bootstrap"
	"dnshived/internal/config"
	"dnshived/internal/helper"
	"dnshived/internal/webauth"
)

// clusterNode is one node the builder session has recorded.
type clusterNode struct {
	Addr        string
	Role        string
	OTP         string
	TrunkParent string
	Self        bool

	// WorkerOverride is this node's own real local interface name per
	// canonical trunk (keyed by the founder's own platformWorkers entries).
	WorkerOverride map[string]string

	// Detected is the interface check's result per trunk, for display.
	Detected []trunkDetection

	// Mgmt is the interface the candidate reported being reached on.
	Mgmt string
}

// trunkDetection is one trunk's interface check result; Local is "" when
// nothing was heard on it.
type trunkDetection struct {
	Canonical string
	Local     string
}

// addNode validates and records another node.
func (b *builderState) addNode(addr, role, otp, trunkParent string) error {
	return b.addNodeWithOverride(addr, role, otp, trunkParent, nil)
}

// addNodeWithOverride is addNode plus an already-computed WorkerOverride
// mapping for a core-role node.
func (b *builderState) addNodeWithOverride(addr, role, otp, trunkParent string, workerOverride map[string]string) error {
	return b.addNodeDetected(addr, role, otp, trunkParent, workerOverride, nil, "")
}

func (b *builderState) addNodeDetected(addr, role, otp, trunkParent string, workerOverride map[string]string, detected []trunkDetection, mgmt string) error {
	if addr == "" {
		return &setupError{msg: "address is required"}
	}
	if !isValidSetupRole(role) {
		return &setupError{msg: "invalid role: " + role}
	}
	if otp == "" {
		return &setupError{msg: "join code is required"}
	}
	if role == "probe" && trunkParent == "" {
		return &setupError{msg: "trunk interface is required for the probe role"}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if addr == b.selfAddr {
		return &setupError{msg: "that's this node's own address"}
	}
	for _, n := range b.nodes {
		if n.Addr == addr {
			return &setupError{msg: "a node with that address is already recorded"}
		}
		if n.Role == role {
			return &setupError{msg: "role " + role + " is already assigned to another recorded node"}
		}
	}
	if role == b.role {
		return &setupError{msg: "role " + role + " is already this node's own role"}
	}

	b.nodes = append(b.nodes, clusterNode{
		Addr: addr, Role: role, OTP: otp, TrunkParent: trunkParent,
		WorkerOverride: workerOverride, Detected: detected, Mgmt: mgmt,
	})
	return nil
}

func (b *builderState) getNodes() []clusterNode {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]clusterNode, len(b.nodes))
	copy(out, b.nodes)
	return out
}

// allNodes returns every recorded node including this one, self first —
// the single source of truth the commit step builds every node's
// cluster.json from.
func (b *builderState) allNodes() []clusterNode {
	b.mu.Lock()
	self := clusterNode{Addr: b.selfAddr, Role: b.role, Self: true}
	nodes := make([]clusterNode, len(b.nodes))
	copy(nodes, b.nodes)
	b.mu.Unlock()
	return append([]clusterNode{self}, nodes...)
}

// coreRolesComplete reports whether exactly one of each of the three
// cluster.json-bearing roles (core-1, core-2, core-3) is present across
// all recorded nodes.
func coreRolesComplete(nodes []clusterNode) bool {
	have := map[string]bool{}
	for _, n := range nodes {
		have[n.Role] = true
	}
	return have[config.RoleCore1] && have[config.RoleCore2] && have[config.RoleCore3]
}

// hasAtLeastOneCoreNode is the real gate for a commit.
func hasAtLeastOneCoreNode(nodes []clusterNode) bool {
	return len(coreNodes(nodes)) >= 1
}

// randomHex returns n random bytes, hex-encoded.
func randomHex(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

type generatedSecrets struct {
	ClusterID       string
	PSK             string
	AdminToken      string
	ProbeToken      string
	ProbeAdminToken string
	ReadonlyToken   string
	WebUIPassword   string
}

func generateClusterSecrets() (generatedSecrets, error) {
	clusterID, err := randomHex(4)
	if err != nil {
		return generatedSecrets{}, err
	}
	psk, err := randomHex(32)
	if err != nil {
		return generatedSecrets{}, err
	}
	adminToken, err := randomHex(32)
	if err != nil {
		return generatedSecrets{}, err
	}
	probeToken, err := randomHex(32)
	if err != nil {
		return generatedSecrets{}, err
	}
	probeAdminToken, err := randomHex(32)
	if err != nil {
		return generatedSecrets{}, err
	}
	readonlyToken, err := randomHex(32)
	if err != nil {
		return generatedSecrets{}, err
	}
	webUIPassword, err := bootstrap.GenerateOTP()
	if err != nil {
		return generatedSecrets{}, err
	}
	return generatedSecrets{
		ClusterID:       "cluster-" + clusterID,
		PSK:             psk,
		AdminToken:      adminToken,
		ProbeToken:      probeToken,
		ProbeAdminToken: probeAdminToken,
		ReadonlyToken:   readonlyToken,
		WebUIPassword:   webUIPassword,
	}, nil
}

// webUIUsername is fixed, not operator-chosen.
const webUIUsername = "admin"

// buildWebUICredentials constructs webui-users.json's content.
func buildWebUICredentials(password string) (*webauth.Store, error) {
	hash, err := webauth.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hash web-ui password: %w", err)
	}
	return &webauth.Store{
		Users: []webauth.User{
			{Name: webUIUsername, PasswordHash: hash, Role: "admin"},
		},
	}, nil
}

// webConfigNode/generatedWebConfig locally mirror cmd/dnshived-web's own
// WebConfig/NodeConfig JSON shape.
type webConfigNode struct {
	Name       string `json:"name"`
	Addr       string `json:"addr"`
	TLS        bool   `json:"tls"`
	AdminToken string `json:"admin_token"`
}

type generatedWebConfig struct {
	ListenAddr string          `json:"listen_addr"`
	HTTPAddr   string          `json:"http_addr,omitempty"`
	TLSCert    string          `json:"tls_cert,omitempty"`
	TLSKey     string          `json:"tls_key,omitempty"`
	UsersFile  string          `json:"users_file"`
	Nodes      []webConfigNode `json:"nodes"`
	VIPHost    string          `json:"vip_host,omitempty"`
	// SelfAdminToken mirrors cmd/dnshived-web's own WebConfig.
	SelfAdminToken string `json:"self_admin_token,omitempty"`
	// ProbeHosts mirrors cmd/dnshived-web's own WebConfig.ProbeHosts.
	ProbeHosts []webConfigNode `json:"probe_hosts,omitempty"`
}

// webUIListenAddr/webUIUsersFile are dnshived-web's own defaults
// (packaging/systemd/dnshived-web.service's ExecStart already points at
// webUIUsersFile).
const (
	webUIListenAddr    = "0.0.0.0:8080"
	webUITLSListenAddr = "0.0.0.0:8443"
	webUIUsersFile     = "/etc/dnshived/webui-users.json"
	webUITLSCertFile   = "/etc/dnshived/webui-tls-cert.pem"
	webUITLSKeyFile    = "/etc/dnshived/webui-tls-key.pem"
)

const (
	coreTLSCertFile = "/etc/dnshived/tls/cert.pem"
	coreTLSKeyFile  = "/etc/dnshived/tls/key.pem"
)

// buildWebConfig constructs web.json's content.
func buildWebConfig(allNodes []clusterNode, adminToken, probeAdminToken, vipHost string, tlsEnabled bool) generatedWebConfig {
	core := coreNodes(allNodes)
	nodes := make([]webConfigNode, 0, len(core))
	for _, n := range core {
		nodes = append(nodes, webConfigNode{Name: n.Role, Addr: n.Addr, TLS: true, AdminToken: adminToken})
	}

	probes := probeOnlyNodes(allNodes)
	probeHosts := make([]webConfigNode, 0, len(probes))
	for _, n := range probes {
		probeHosts = append(probeHosts, webConfigNode{Name: "probe", Addr: n.Addr, TLS: false, AdminToken: probeAdminToken})
	}

	cfg := generatedWebConfig{
		ListenAddr:     webUIListenAddr,
		UsersFile:      webUIUsersFile,
		Nodes:          nodes,
		VIPHost:        vipHost,
		ProbeHosts:     probeHosts,
		SelfAdminToken: adminToken,
	}
	if tlsEnabled {
		cfg.ListenAddr = webUITLSListenAddr
		cfg.HTTPAddr = webUIListenAddr
		cfg.TLSCert = webUITLSCertFile
		cfg.TLSKey = webUITLSKeyFile
	}
	return cfg
}

// startWebUI best-effort starts dnshived-web on this node via the helper.
func startWebUI() error {
	return bootstrapUnitFunc("enable-now", "dnshived-web.service")
}

// bootstrapUnitFunc runs one allowlisted helper unit action for founding
// and adopt.
var bootstrapUnitFunc = func(action, unit string) error {
	return helper.NewClient(defaultHelperSocket).ManageUnit(action, unit)
}

// writeAndStartWebUI writes webui-users.json/web.json/the TLS cert+key
// (whichever are non-empty) and starts dnshived-web.
func writeAndStartWebUI(webUsersJSON, webConfigJSON, tlsCertPEM, tlsKeyPEM []byte) {
	if len(webUsersJSON) > 0 {
		if err := os.WriteFile(webUIUsersFile, webUsersJSON, 0o600); err != nil {
			loglevel.Warnf("[BOOTSTRAP:WEBUI] write %s: %v", webUIUsersFile, err)
		}
		chownDnshived(webUIUsersFile)
	}
	if len(webConfigJSON) > 0 {
		if err := os.WriteFile("/etc/dnshived/web.json", webConfigJSON, 0o640); err != nil {
			loglevel.Warnf("[BOOTSTRAP:WEBUI] write web.json: %v", err)
		}
		chownDnshived("/etc/dnshived/web.json")
	}
	if len(tlsCertPEM) > 0 && len(tlsKeyPEM) > 0 {
		if err := os.WriteFile(webUITLSCertFile, tlsCertPEM, 0o644); err != nil {
			loglevel.Warnf("[BOOTSTRAP:WEBUI] write %s: %v", webUITLSCertFile, err)
		}
		chownDnshived(webUITLSCertFile)
		if err := os.WriteFile(webUITLSKeyFile, tlsKeyPEM, 0o600); err != nil {
			loglevel.Warnf("[BOOTSTRAP:WEBUI] write %s: %v", webUITLSKeyFile, err)
		}
		chownDnshived(webUITLSKeyFile)
	}
	if len(webUsersJSON) > 0 && len(webConfigJSON) > 0 {
		if err := startWebUI(); err != nil {
			loglevel.Warnf("[BOOTSTRAP:WEBUI] start dnshived-web: %v", err)
		} else {
			loglevel.Infof("[BOOTSTRAP:WEBUI] dnshived-web started")
		}
	}
}

// chownDnshived hands path's ownership to the "dnshived" system user/
// group.
func chownDnshived(path string) {
	u, err := user.Lookup("dnshived")
	if err != nil {
		loglevel.Warnf("[BOOTSTRAP:WEBUI] chown %s: lookup dnshived user: %v", path, err)
		return
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		loglevel.Warnf("[BOOTSTRAP:WEBUI] chown %s: parse dnshived uid/gid: %v / %v", path, err1, err2)
		return
	}
	if err := os.Chown(path, uid, gid); err != nil {
		loglevel.Warnf("[BOOTSTRAP:WEBUI] chown %s to dnshived: %v", path, err)
	}
}

// probeConfigNode/generatedProbeConfig locally mirror cmd/dnshived-
// probe's own ProbeConfig/ClusterNode JSON shape.
type probeConfigNode struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
	TLS  bool   `json:"tls"`
}

type generatedProbeConfig struct {
	ListenAddr        string            `json:"listen_addr"`
	TrunkParent       string            `json:"trunk_parent"`
	TrunkParents      []string          `json:"trunk_parents,omitempty"`
	ClusterToken      string            `json:"cluster_token"`
	ClusterNodes      []probeConfigNode `json:"cluster_nodes"`
	APITokens         []config.APIToken `json:"api_tokens,omitempty"`
	LocalOctet        int               `json:"local_octet,omitempty"`
	ProbeHelperSocket string            `json:"probe_helper_socket,omitempty"`
	KnownVLANsPath    string            `json:"known_vlans_path,omitempty"`
	ClusterCertPEM    string            `json:"cluster_cert_pem,omitempty"`
}

// probeListenAddr matches cmd/dnshived-probe's default listen address.
const probeListenAddr = "0.0.0.0:9444"

const (
	defaultProbeHelperSocket = "/run/dnshived/probe-helper.sock"
	defaultKnownVLANsPath    = "/var/lib/dnshived-probe/known-vlans.json"
)

// defaultHelperSocket mirrors cmd/dnshived-helper's own "-socket" flag
// default exactly (main.go).
const defaultHelperSocket = "/run/dnshived/helper.sock"

// buildProbeConfig constructs a probe host's complete probe.json.
func buildProbeConfig(secrets generatedSecrets, allNodes []clusterNode, probeNode clusterNode, mgmt mgmtSetup) (generatedProbeConfig, error) {
	core := coreNodes(allNodes)
	if len(core) == 0 {
		return generatedProbeConfig{}, fmt.Errorf("no core node to point the probe at")
	}
	// The probe must speak whatever the core API actually serves, so read
	// it from the core config founding writes rather than assuming.
	coreCfg, err := buildClusterConfig(secrets, core[0], allNodes, mgmt)
	if err != nil {
		return generatedProbeConfig{}, fmt.Errorf("derive core TLS: %w", err)
	}
	tls := coreCfg.TLSEnabled()
	nodes := make([]probeConfigNode, 0, len(core))
	for _, n := range core {
		nodes = append(nodes, probeConfigNode{Name: n.Role, Addr: n.Addr, TLS: tls})
	}
	return generatedProbeConfig{
		ListenAddr:   probeListenAddr,
		TrunkParent:  probeNode.TrunkParent,
		TrunkParents: mgmt.PlatformWorkers,
		ClusterToken: secrets.ProbeToken,
		ClusterNodes: nodes,
		APITokens: []config.APIToken{
			{Name: "probe-admin", Token: secrets.ProbeAdminToken, Role: "admin"},
			{Name: "monitoring", Token: secrets.ReadonlyToken, Role: "readonly"},
		},
		LocalOctet:        deriveProbeLocalOctet(probeNode.Addr),
		ProbeHelperSocket: defaultProbeHelperSocket,
		KnownVLANsPath:    defaultKnownVLANsPath,
	}, nil
}

func pushProbeAdopt(addr, otp string, probeJSON []byte) error {
	plain, err := json.Marshal(struct {
		Config json.RawMessage `json:"config"`
	}{Config: probeJSON})
	if err != nil {
		return err
	}

	target, err := probeAdoptTarget(addr)
	if err != nil {
		return err
	}
	return postSealedAdopt("http://"+target+"/api/v1/bootstrap/adopt", otp, bootstrap.PurposeProbeAdopt, plain)
}

// probeAdoptTarget derives pushProbeAdopt's real destination.
func probeAdoptTarget(addr string) (string, error) {
	_, probePort, err := net.SplitHostPort(probeListenAddr)
	if err != nil {
		return "", fmt.Errorf("internal error: probeListenAddr %q has no port: %w", probeListenAddr, err)
	}
	return net.JoinHostPort(hostOnly(addr), probePort), nil
}

// buildClusterConfig constructs one node's complete cluster.json content
// from the cluster-wide secrets and the full node list.
func coreNodes(nodes []clusterNode) []clusterNode {
	var out []clusterNode
	for _, n := range nodes {
		if n.Role != "probe" {
			out = append(out, n)
		}
	}
	return out
}

// probeOnlyNodes is coreNodes' complement.
func probeOnlyNodes(nodes []clusterNode) []clusterNode {
	var out []clusterNode
	for _, n := range nodes {
		if n.Role == "probe" {
			out = append(out, n)
		}
	}
	return out
}

type mgmtSetup struct {
	VIP    string
	VRRPID int
	Iface  string

	PlatformMgmt    string
	PlatformWorkers []string
}

func buildClusterConfig(secrets generatedSecrets, self clusterNode, allNodes []clusterNode, mgmt mgmtSetup) (*config.Cluster, error) {
	nodeID, err := randomHex(6)
	if err != nil {
		return nil, err
	}

	var peers []string
	var trustedHosts []string
	nodeIPSuffixes := make(map[string]string)
	for _, n := range coreNodes(allNodes) {
		if suffix := lastIPv4Octet(n.Addr); suffix != "" {
			nodeIPSuffixes[n.Role] = suffix
		}
		if n.Addr != self.Addr {
			peers = append(peers, n.Addr)
		}
		trustedHosts = append(trustedHosts, hostOnly(n.Addr))
	}

	cc := &config.Cluster{
		SchemaVersion: 2,
		ClusterID:     secrets.ClusterID,
		NodeID:        self.Role + "-" + nodeID,
		Role:          self.Role,
		ControlAddr:   self.Addr,
		DataDir:       defaultBootstrapDataDir,
		PSK:           secrets.PSK,
		Peers:         peers,
		TrustedHosts:  trustedHosts,
		HelperSocket:  defaultHelperSocket,
		TLSCert:       coreTLSCertFile,
		TLSKey:        coreTLSKeyFile,
		APITokens: []config.APIToken{
			{Name: "bootstrap-admin", Token: secrets.AdminToken, Role: "admin"},
			{Name: "bootstrap-probe", Token: secrets.ProbeToken, Role: "probe"},
			{Name: "bootstrap-probe-admin", Token: secrets.ProbeAdminToken, Role: "probe-admin"},
			{Name: "monitoring", Token: secrets.ReadonlyToken, Role: "readonly"},
		},
		Scopes: map[string]config.ScopeConfig{},
	}
	// Suggestions for a new /24 scope; every scope can override them.
	cc.ScopeDefaults = &config.ScopeDefaults{
		Upstream:        []string{"1.1.1.1", "8.8.8.8"},
		VIPSuffix:       "254",
		GatewaySuffix:   "1",
		DHCPStartSuffix: "200",
		DHCPEndSuffix:   "250",
	}
	if len(nodeIPSuffixes) > 0 {
		cc.ScopeDefaults.NodeIPSuffixes = nodeIPSuffixes
	}
	mgmtIface := mgmt.PlatformMgmt
	if mgmtIface == "" {
		mgmtIface = mgmt.Iface
	}
	if mgmtIface != "" {
		cc.Platform = &config.Platform{Mgmt: mgmtIface, Workers: mgmt.PlatformWorkers}
		// WorkerOverrides is built once here, from every recorded node's own
		// (already broadcast-correlated, never hand-typed) WorkerOverride.
		var overrides map[string]map[string]string
		for _, n := range allNodes {
			if len(n.WorkerOverride) == 0 {
				continue
			}
			if overrides == nil {
				overrides = make(map[string]map[string]string)
			}
			overrides[n.Role] = n.WorkerOverride
		}
		cc.Platform.WorkerOverrides = overrides
		var mgmtOverrides map[string]string
		for _, n := range coreNodes(allNodes) {
			if n.Mgmt == "" || n.Mgmt == mgmtIface {
				continue
			}
			if mgmtOverrides == nil {
				mgmtOverrides = make(map[string]string)
			}
			mgmtOverrides[n.Role] = n.Mgmt
		}
		cc.Platform.MgmtOverrides = mgmtOverrides
	}
	if mgmt.VIP != "" {
		cc.MgmtVIP = &config.MgmtVIPConfig{VIP: mgmt.VIP, VRRPID: mgmt.VRRPID}
	}
	return cc, nil
}

// pushResult is one node's outcome from a commit attempt, shown on the
// result page.
type pushResult struct {
	Addr    string
	Role    string
	Self    bool
	OK      bool
	Message string
}

// pushConfigTimeout bounds a single adopt push.
const pushConfigTimeout = 30 * time.Second

// adoptPayload bundles everything a core-node push delivers in one commit.
type adoptPayload struct {
	ClusterJSON    []byte
	WebUsersJSON   []byte
	WebConfigJSON  []byte
	TLSCertPEM     []byte
	TLSKeyPEM      []byte
	CoreTLSCertPEM []byte
	CoreTLSKeyPEM  []byte
}

// pushAdoptConfig POSTs the generated cluster.json to a remote node's
// bootstrap adopt endpoint, presenting the join code the operator entered
// for it.
func pushAdoptConfig(addr, otp string, payload adoptPayload) error {
	plain, err := json.Marshal(bootstrapAdoptRequest{
		ClusterJSON:    payload.ClusterJSON,
		WebUsersJSON:   payload.WebUsersJSON,
		WebConfigJSON:  payload.WebConfigJSON,
		TLSCertPEM:     payload.TLSCertPEM,
		TLSKeyPEM:      payload.TLSKeyPEM,
		CoreTLSCertPEM: payload.CoreTLSCertPEM,
		CoreTLSKeyPEM:  payload.CoreTLSKeyPEM,
	})
	if err != nil {
		return err
	}
	return postSealedAdopt("http://"+coreBootstrapContactAddr(addr)+"/api/v1/bootstrap/adopt", otp, bootstrap.PurposeCoreAdopt, plain)
}

func postSealedAdopt(url, otp, purpose string, plain []byte) error {
	sealed, err := bootstrap.Seal(otp, purpose, plain)
	if err != nil {
		return err
	}
	body, err := json.Marshal(sealed)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: pushConfigTimeout}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("%s: %s (or the node runs a dnshived older than 0.9.8.6, which cannot read an encrypted push; upgrade it first)", resp.Status, strings.TrimSpace(string(msg)))
		}
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// bootstrapCommitTmpl shows the outcome of a create-cluster attempt.
var bootstrapCommitTmpl = template.Must(template.New("bootstrap-commit").Parse(`<!doctype html>
<title>dnshived — cluster creation result</title>
` + bootstrapStyleHTML + `
<div class="card">
<h1>Cluster creation result</h1>
<ul>
{{range .Results}}
<li>{{.Role}} ({{.Addr}}){{if .Self}} — this node{{end}}: {{if .OK}}OK{{else}}FAILED — {{.Message}}{{end}}</li>
{{end}}
</ul>
{{if .AllOK}}
<p><strong>All nodes accepted their configuration.</strong> This node is restarting into the real daemon now — this page will stop responding shortly.</p>
{{if .StandaloneNote}}
<p class="hint">This cluster has fewer than the usual 3 core nodes — it will serve standalone. Onboard the remaining core-1/core-2/core-3 role(s), and a probe host, whenever you're ready; nothing here needs to wait for them.</p>
{{end}}
{{if .WebUILink}}
<h2>Log in to the cluster</h2>
<p>Web UI: <a href="{{.WebUILink}}">{{.WebUILink}}</a></p>
<p>Username: <strong>{{.WebUIUsername}}</strong><br>Password: <strong>{{.WebUIPassword}}</strong></p>
<p class="hint">This password is shown only once — write it down now, then click the link above when ready. Change it afterward with <code>dnshived-web -reset-user</code> if you want a different one.</p>
{{end}}
{{if .ReadonlyToken}}
<h2>Read-only monitoring token</h2>
<p><strong>{{.ReadonlyToken}}</strong></p>
<p class="hint">For read-only tools like <code>dnshived-top</code> — deliberately a separate, lower-privilege credential from the admin login above (never write access, cannot restart anything). Shown only once, save it now — every node's own <code>cluster.json</code> keeps it under <code>api_tokens</code> ("monitoring") if you need to retrieve it later.</p>
{{end}}
{{else}}
<p class="error">One or more nodes failed. This is not automatically retried — nodes that failed still have no real config; nodes that succeeded have already restarted as real cluster members. Resolve the failure and push to the remaining node(s) by hand, or restart this wizard.</p>
{{end}}
</div>
`))

type bootstrapCommitData struct {
	Results        []pushResult
	AllOK          bool
	StandaloneNote bool
	WebUILink      string
	WebUIUsername  string
	WebUIPassword  string
	ReadonlyToken  string
}

// bootstrapCommitHandler is the "create cluster" action.
func bootstrapCommitHandler(cfgPath string, state *builderState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nodes := state.allNodes()
		if !hasAtLeastOneCoreNode(nodes) {
			http.Error(w, "need at least one core node (core-1, core-2, or core-3) recorded before creating the cluster", http.StatusBadRequest)
			return
		}
		if nodes[0].Addr == "" {
			http.Error(w, "set this node's own address before creating the cluster", http.StatusBadRequest)
			return
		}

		secrets, err := generateClusterSecrets()
		if err != nil {
			http.Error(w, "generate secrets: "+err.Error(), http.StatusInternalServerError)
			return
		}

		webUsers, err := buildWebUICredentials(secrets.WebUIPassword)
		if err != nil {
			http.Error(w, "build web-ui credentials: "+err.Error(), http.StatusInternalServerError)
			return
		}
		webUsersRaw, err := json.MarshalIndent(webUsers, "", "  ")
		if err != nil {
			http.Error(w, "marshal web-ui credentials: "+err.Error(), http.StatusInternalServerError)
			return
		}

		vip, vrrpID, iface := state.getMgmtVIP()
		platformMgmt, platformWorkers := state.getPlatform()
		mgmt := mgmtSetup{VIP: vip, VRRPID: vrrpID, Iface: iface, PlatformMgmt: platformMgmt, PlatformWorkers: platformWorkers}
		vipHost := ""
		if vip != "" {
			if vipIP, _, err := net.ParseCIDR(vip); err == nil {
				vipHost = vipIP.String()
			}
		}

		tlsCertPEM, tlsKeyPEM := state.getTLS()
		if tlsCertPEM == "" {
			sans := []string{"localhost", "127.0.0.1"}
			for _, n := range coreNodes(nodes) {
				sans = append(sans, hostOnly(n.Addr))
			}
			if vipHost != "" {
				sans = append(sans, vipHost)
			}
			cert, key, err := genSelfSignedCert(sans)
			if err != nil {
				http.Error(w, "generate self-signed certificate: "+err.Error(), http.StatusInternalServerError)
				return
			}
			tlsCertPEM, tlsKeyPEM = string(cert), string(key)
		}

		webConfigRaw, err := json.MarshalIndent(buildWebConfig(nodes, secrets.AdminToken, secrets.ProbeAdminToken, vipHost, true), "", "  ")
		if err != nil {
			http.Error(w, "marshal web config: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var results []pushResult
		selfSucceeded := false
		var webUILink string

		for _, n := range coreNodes(nodes) {
			cc, err := buildClusterConfig(secrets, n, nodes, mgmt)
			if err != nil {
				results = append(results, pushResult{Addr: n.Addr, Role: n.Role, Self: n.Self, OK: false, Message: "build config: " + err.Error()})
				continue
			}
			raw, err := json.MarshalIndent(cc, "", "  ")
			if err != nil {
				results = append(results, pushResult{Addr: n.Addr, Role: n.Role, Self: n.Self, OK: false, Message: "marshal config: " + err.Error()})
				continue
			}
			payload := adoptPayload{
				ClusterJSON:    raw,
				WebUsersJSON:   webUsersRaw,
				WebConfigJSON:  webConfigRaw,
				TLSCertPEM:     []byte(tlsCertPEM),
				TLSKeyPEM:      []byte(tlsKeyPEM),
				CoreTLSCertPEM: []byte(tlsCertPEM),
				CoreTLSKeyPEM:  []byte(tlsKeyPEM),
			}

			if n.Self {
				if err := writeLocalClusterConfig(cfgPath, payload); err != nil {
					results = append(results, pushResult{Addr: n.Addr, Role: n.Role, Self: true, OK: false, Message: err.Error()})
					continue
				}
				results = append(results, pushResult{Addr: n.Addr, Role: n.Role, Self: true, OK: true})
				selfSucceeded = true
				webUIHost := hostOnly(n.Addr)
				if vipHost != "" {
					webUIHost = vipHost
				}
				webUILink = "https://" + webUIHost + ":" + webUIPort(webUITLSListenAddr)
				continue
			}

			if err := pushAdoptConfig(n.Addr, n.OTP, payload); err != nil {
				results = append(results, pushResult{Addr: n.Addr, Role: n.Role, OK: false, Message: err.Error()})
				continue
			}
			results = append(results, pushResult{Addr: n.Addr, Role: n.Role, OK: true})
		}

		for _, n := range probeOnlyNodes(nodes) {
			pc, err := buildProbeConfig(secrets, nodes, n, mgmt)
			if err != nil {
				results = append(results, pushResult{Addr: n.Addr, Role: n.Role, OK: false, Message: "build config: " + err.Error()})
				continue
			}
			if len(pc.ClusterNodes) > 0 && pc.ClusterNodes[0].TLS {
				pc.ClusterCertPEM = tlsCertPEM
			}
			raw, err := json.MarshalIndent(pc, "", "  ")
			if err != nil {
				results = append(results, pushResult{Addr: n.Addr, Role: n.Role, OK: false, Message: "marshal config: " + err.Error()})
				continue
			}
			if err := pushProbeAdopt(n.Addr, n.OTP, raw); err != nil {
				results = append(results, pushResult{Addr: n.Addr, Role: n.Role, OK: false, Message: err.Error()})
				continue
			}
			results = append(results, pushResult{Addr: n.Addr, Role: n.Role, OK: true})
		}

		allOK := true
		for _, res := range results {
			if !res.OK {
				allOK = false
			}
		}

		data := bootstrapCommitData{Results: results, AllOK: allOK}
		if allOK && !coreRolesComplete(nodes) {
			data.StandaloneNote = true
		}
		if allOK && webUILink != "" {
			data.WebUILink = webUILink
			data.WebUIUsername = webUIUsername
			data.WebUIPassword = secrets.WebUIPassword
			data.ReadonlyToken = secrets.ReadonlyToken
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		bootstrapCommitTmpl.Execute(w, data)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		if selfSucceeded {
			go func() {
				time.Sleep(300 * time.Millisecond)
				reExecFunc()
			}()
		}
	}
}

// hostOnly/webUIPort split a "host:port" address to build the web-UI link
// shown on the result page.
func hostOnly(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}

// normalizeNodeAddr gives an address typed without a port the port the
// node is reached on afterwards: the core API port for cores, the probe
// API port for a probe host.
func normalizeNodeAddr(addr, role, controlPort string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return addr
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	port := controlPort
	if role == "probe" {
		if _, p, err := net.SplitHostPort(probeListenAddr); err == nil {
			port = p
		}
	}
	return net.JoinHostPort(strings.Trim(addr, "[]"), port)
}

// coreBootstrapPort is the core daemon's bootstrap listener; tests point
// it at a test server.
var coreBootstrapPort = "80"

func coreBootstrapContactAddr(addr string) string {
	return net.JoinHostPort(hostOnly(addr), coreBootstrapPort)
}

func webUIPort(listenAddr string) string {
	if i := strings.LastIndex(listenAddr, ":"); i >= 0 {
		return listenAddr[i+1:]
	}
	return listenAddr
}

// writeLocalClusterConfig is the self case of a commit push.
func writeLocalClusterConfig(cfgPath string, payload adoptPayload) error {
	if err := os.WriteFile(cfgPath, payload.ClusterJSON, 0o640); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	if len(payload.CoreTLSCertPEM) > 0 && len(payload.CoreTLSKeyPEM) > 0 {
		var c config.Cluster
		if err := json.Unmarshal(payload.ClusterJSON, &c); err == nil && c.TLSCert != "" && c.TLSKey != "" {
			os.MkdirAll(filepath.Dir(c.TLSCert), 0o755)
			os.MkdirAll(filepath.Dir(c.TLSKey), 0o755)
			if err := os.WriteFile(c.TLSCert, payload.CoreTLSCertPEM, 0o644); err != nil {
				loglevel.Warnf("[BOOTSTRAP:COMMIT] write core TLS cert %s: %v", c.TLSCert, err)
			}
			if err := os.WriteFile(c.TLSKey, payload.CoreTLSKeyPEM, 0o600); err != nil {
				loglevel.Warnf("[BOOTSTRAP:COMMIT] write core TLS key %s: %v", c.TLSKey, err)
			}
		}
	}

	writeAndStartWebUI(payload.WebUsersJSON, payload.WebConfigJSON, payload.TLSCertPEM, payload.TLSKeyPEM)
	reenableHelperAfterAdopt()
	stopProbeDaemonsOnThisHost()
	loglevel.Infof("[BOOTSTRAP:COMMIT] wrote this node's own cluster config — restarting as a configured daemon")
	return nil
}

// reenableHelperAfterAdopt re-enables dnshived-helper.service.
func reenableHelperAfterAdopt() {
	if err := bootstrapUnitFunc("enable", "dnshived-helper.service"); err != nil {
		loglevel.Warnf("[BOOTSTRAP:COMMIT] enable dnshived-helper.service: %v", err)
	}
}

func stopProbeDaemonsOnThisHost() {
	for _, unit := range []string{"dnshived-probe.service", "dnshived-probe-helper.service"} {
		if err := bootstrapUnitFunc("disable-now", unit); err != nil {
			loglevel.Warnf("[BOOTSTRAP:COMMIT] stop/disable %s (mutual exclusion with this node's new core role): %v", unit, err)
		}
	}
}
