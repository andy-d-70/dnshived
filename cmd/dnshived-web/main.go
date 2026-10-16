// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// dnshived-web is the operator web UI for a dnshived cluster.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"dnshived/internal/tlspin"
	"dnshived/internal/webauth"
)

var version = "0.9.7-dev"

func main() {
	cfgPath := flag.String("config", "/etc/dnshived/web.json", "dnshived-web config path")
	showVersion := flag.Bool("version", false, "print version and exit")
	hashPassword := flag.String("hash-password", "", "print a PBKDF2 hash for the given password and exit (for building webui-users.json without hand-rolling the hash format)")
	resetUser := flag.String("reset-user", "", "add this user, or reset their password if they already exist, and exit — the console-based recovery path for a lost web-UI password")
	resetRole := flag.String("role", "admin", "role for -reset-user (admin, scopeadmin or readonly)")
	resetEmail := flag.String("email", "", "email address for -reset-user (kept unchanged when empty)")
	resetPassword := flag.String("password", "", "new password for -reset-user (prompted interactively, without echo, if omitted)")
	usersFileFlag := flag.String("users-file", "", "webui-users.json path for -reset-user (default: read from -config's users_file)")
	flag.Parse()

	if *showVersion {
		fmt.Println("dnshived-web", version)
		os.Exit(0)
	}

	if *hashPassword != "" {
		hash, err := webauth.HashPassword(*hashPassword)
		if err != nil {
			log.Fatalf("hash password: %v", err)
		}
		fmt.Println(hash)
		os.Exit(0)
	}

	if *resetUser != "" {
		runResetUser(*cfgPath, *usersFileFlag, *resetUser, *resetRole, *resetPassword, *resetEmail)
		os.Exit(0)
	}

	cfg, err := loadWebConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	store, err := webauth.Load(cfg.UsersFile)
	if err != nil {
		log.Fatalf("users file: %v", err)
	}
	log.Printf("[INIT] loaded %d web-UI user(s) from %s", len(store.Users), cfg.UsersFile)
	go webauth.PrepareTiming()

	templates, err := LoadTemplates(cfg.TemplatesFile)
	if err != nil {
		log.Fatalf("templates file: %v", err)
	}
	log.Printf("[INIT] loaded %d template(s) from %s", len(templates.Templates), cfg.TemplatesFile)

	log.Printf("[INIT] polling %d cluster node(s)", len(cfg.Nodes))

	ref := newConfigRef(cfg)
	tlspin.SetFile(cfg.TLSCert)

	repl := newAuthSync(store, ref)
	if created, err := store.EnsureSessionKey(repl.selfName()); err != nil {
		log.Fatalf("session key: %v", err)
	} else if created {
		if err := store.Save(cfg.UsersFile); err != nil {
			log.Fatalf("save session key: %v", err)
		}
	}
	repl.run()

	startPendingSummaryTicker(ref)
	startVerifyCacheCleanup()
	watchUsersFile(store, cfg.UsersFile, func() { go repl.pushAll() })
	go refreshSnapshotLoop(ref)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /login", handleLoginGet(store))
	mux.HandleFunc("POST /login", handleLoginPost(store, ref))
	mux.HandleFunc("POST /logout", handleLogout)
	mux.HandleFunc("GET /forgot", handleForgotGet)
	mux.HandleFunc("POST /forgot", handleForgotPost(store, repl, ref))
	mux.HandleFunc("GET /reset", handleResetGet(store))
	mux.HandleFunc("POST /reset", handleResetPost(store, repl, ref))
	mux.HandleFunc("/favicon.ico", handleFavicon)
	mux.HandleFunc("/favicon.svg", handleFavicon)
	mux.HandleFunc("/", requirePermission(store, webauth.PermViewStatus, handleStatus(ref)))
	mux.HandleFunc("/status", requirePermission(store, webauth.PermViewStatus, handleStatus(ref)))
	mux.HandleFunc("/scopes", requirePermission(store, webauth.PermViewStatus, handleScopes(ref)))
	mux.HandleFunc("/scopes/{name}", requirePermission(store, webauth.PermViewStatus, handleScopeDetail(ref, templates)))
	mux.HandleFunc("POST /scopes/{name}/reservations", requirePermission(store, webauth.PermEditScopes, promoteLeaseFormHandler(ref)))
	mux.HandleFunc("POST /scopes/{name}/reservations/delete", requirePermission(store, webauth.PermEditScopes, deleteReservationFormHandler(ref)))
	mux.HandleFunc("POST /scopes/{name}/leases/release", requirePermission(store, webauth.PermEditScopes, releaseLeaseFormHandler(ref)))
	mux.HandleFunc("POST /paths/reset", requirePermission(store, webauth.PermEditConfig, handleReliabilityResetPost(ref)))
	mux.HandleFunc("POST /scopes/{name}/config", requirePermission(store, webauth.PermEditScopes, handleScopeConfigPost(ref)))
	mux.HandleFunc("POST /scopes/{name}/toggle-disabled", requirePermission(store, webauth.PermEditScopes, handleScopeDisableToggle(ref)))
	mux.HandleFunc("POST /scopes/{name}/rebalance", requirePermission(store, webauth.PermEditScopes, handleScopeRebalance(ref)))
	mux.HandleFunc("POST /scopes/rebalance-all", requirePermission(store, webauth.PermEditScopes, handleScopeRebalanceAll(ref)))
	mux.HandleFunc("POST /scopes/{name}/delete", requirePermission(store, webauth.PermEditScopes, handleScopeDelete(ref)))
	mux.HandleFunc("/probes", requirePermission(store, webauth.PermViewStatus, handleProbes(ref)))
	mux.HandleFunc("/probes/{scope}/{worker}", requirePermission(store, webauth.PermViewStatus, handleProbeDetail(ref)))
	mux.HandleFunc("POST /probes/{scope}/{worker}/refresh", requirePermission(store, webauth.PermViewStatus, handleProbeRefresh(ref)))
	mux.HandleFunc("POST /probes/{scope}/toggle-probe", requirePermission(store, webauth.PermEditScopes, handleProbeToggle(ref)))
	mux.HandleFunc("POST /probes/settings", requirePermission(store, webauth.PermEditConfig, handleProbeSettingsPost(ref)))
	mux.HandleFunc("/topology", requirePermission(store, webauth.PermViewStatus, handleTopology(ref)))
	mux.HandleFunc("/daemons", requirePermission(store, webauth.PermViewStatus, handleDaemons(ref)))
	mux.HandleFunc("/daemons/{node}/{unit}/restart/confirm", requirePermission(store, webauth.PermEditConfig, handleDaemonRestartConfirm(ref)))
	mux.HandleFunc("POST /daemons/{node}/{unit}/restart", requirePermission(store, webauth.PermEditConfig, handleDaemonRestart(ref)))
	mux.HandleFunc("/logs", requirePermission(store, webauth.PermViewStatus, handleLogs(ref)))
	mux.HandleFunc("/logs/dnsmasq/{node}/{scope}", requirePermission(store, webauth.PermViewStatus, handleDnsmasqLogView(ref)))
	mux.HandleFunc("/logs/daemon/{node}/{unit}", requirePermission(store, webauth.PermViewStatus, handleDaemonLogView(ref)))
	mux.HandleFunc("/config", requirePermission(store, webauth.PermViewStatus, handleConfigGet(ref)))
	mux.HandleFunc("POST /config", requirePermission(store, webauth.PermEditConfig, handleConfigPost(ref)))
	mux.HandleFunc("/config/scopes", requirePermission(store, webauth.PermViewStatus, handleScopesConfigGet(ref)))
	mux.HandleFunc("POST /config/scopes", requirePermission(store, webauth.PermEditScopes, handleScopesConfigPost(ref)))
	mux.HandleFunc("/config/dns", requirePermission(store, webauth.PermViewStatus, handleDHCPDNSConfigGet(ref, templates)))
	mux.HandleFunc("POST /config/dns", requirePermission(store, webauth.PermEditScopes, handleDNSConfigPost(ref)))
	mux.HandleFunc("POST /config/dhcp", requirePermission(store, webauth.PermEditScopes, handleDHCPConfigPost(ref)))
	mux.HandleFunc("POST /config/domains/new", requirePermission(store, webauth.PermEditScopes, handleLocalDomainAddPost(ref)))
	mux.HandleFunc("POST /config/domains/{name}/save", requirePermission(store, webauth.PermEditScopes, handleLocalDomainSavePost(ref)))
	mux.HandleFunc("POST /config/domains/{name}/delete", requirePermission(store, webauth.PermEditScopes, handleLocalDomainDeletePost(ref)))
	mux.HandleFunc("POST /config/domains/{name}/fork", requirePermission(store, webauth.PermEditScopes, handleLocalDomainForkPost(ref)))
	mux.HandleFunc("POST /config/domains/{name}/unlink", requirePermission(store, webauth.PermEditScopes, handleLocalDomainUnlinkPost(ref)))
	mux.HandleFunc("POST /config/probe-parallel", requirePermission(store, webauth.PermEditConfig, handleProbeParallelPost(ref)))
	mux.HandleFunc("/config/export", requirePermissionOrToken(store, webauth.PermEditConfig, ref, handleConfigExport(ref)))
	mux.HandleFunc("/backup", requirePermission(store, webauth.PermViewStatus, handleBackup(ref)))
	mux.HandleFunc("POST /backup/settings", requirePermission(store, webauth.PermEditConfig, handleBackupSettingsPost(ref)))
	mux.HandleFunc("POST /backup/create", requirePermission(store, webauth.PermEditConfig, handleBackupCreatePost(ref)))
	mux.HandleFunc("GET /backup/download/{node}/{name}", requirePermissionOrToken(store, webauth.PermEditConfig, ref, handleBackupDownload(ref)))
	mux.HandleFunc("GET /backup/list", requirePermissionOrToken(store, webauth.PermViewStatus, ref, handleBackupListAPI(ref)))
	mux.HandleFunc("POST /backup/delete/{node}/{name}", requirePermission(store, webauth.PermEditConfig, handleBackupDeletePost(ref)))
	mux.HandleFunc("POST /backup/delete-group/{name}", requirePermission(store, webauth.PermEditConfig, handleBackupDeleteGroup(ref)))
	mux.HandleFunc("GET /backup/restore", requirePermission(store, webauth.PermEditConfig, handleBackupRestoreGet(ref)))
	mux.HandleFunc("POST /backup/restore", requirePermission(store, webauth.PermEditConfig, handleBackupRestorePost(ref)))
	// Security tab: API tokens.
	mux.HandleFunc("/security", requirePermission(store, webauth.PermViewStatus, handleSecurityGet(ref)))
	mux.HandleFunc("POST /security", requirePermission(store, webauth.PermEditConfig, handleSecurityPost(ref)))
	// Scope general options: scope VIP preference and new-scope defaults.
	mux.HandleFunc("/scopes/options", requirePermission(store, webauth.PermViewStatus, handleScopeDefaultsGet(ref)))
	mux.HandleFunc("POST /scopes/options", requirePermission(store, webauth.PermEditScopes, handleScopeDefaultsPost(ref)))
	mux.HandleFunc("/scopes/wizard", requirePermission(store, webauth.PermViewStatus, handleScopeWizard(ref, templates)))
	mux.HandleFunc("POST /scopes/wizard", requirePermission(store, webauth.PermEditScopes, handleScopeWizard(ref, templates)))
	mux.HandleFunc("/templates/new", requirePermission(store, webauth.PermViewStatus, handleTemplateNew(ref, templates)))
	mux.HandleFunc("POST /templates/new", requirePermission(store, webauth.PermEditScopes, handleTemplateNew(ref, templates)))
	mux.HandleFunc("/templates/{id}/edit", requirePermission(store, webauth.PermViewStatus, handleTemplateEditGet(ref, templates)))
	mux.HandleFunc("POST /templates/{id}/edit", requirePermission(store, webauth.PermEditScopes, handleTemplateEditPost(ref, templates)))
	mux.HandleFunc("POST /templates/{id}/delete", requirePermission(store, webauth.PermEditScopes, handleTemplateDelete(ref, templates)))
	mux.HandleFunc("/optionsets", requirePermission(store, webauth.PermViewStatus, handleOptionSets(templates)))
	mux.HandleFunc("/optionsets/new", requirePermission(store, webauth.PermViewStatus, handleOptionSetNew(ref, templates)))
	mux.HandleFunc("POST /optionsets/new", requirePermission(store, webauth.PermEditScopes, handleOptionSetNew(ref, templates)))
	mux.HandleFunc("/optionsets/{id}/edit", requirePermission(store, webauth.PermViewStatus, handleOptionSetEdit(ref, templates)))
	mux.HandleFunc("POST /optionsets/{id}/edit", requirePermission(store, webauth.PermEditScopes, handleOptionSetEdit(ref, templates)))
	mux.HandleFunc("POST /optionsets/{id}/delete", requirePermission(store, webauth.PermEditScopes, handleOptionSetDelete(ref, templates)))
	mux.HandleFunc("/rollout", requirePermission(store, webauth.PermViewStatus, handleRollout(ref, templates)))
	mux.HandleFunc("POST /rollout", requirePermission(store, webauth.PermEditScopes, handleRollout(ref, templates)))
	mux.HandleFunc("/groups", requirePermission(store, webauth.PermViewStatus, handleScopeGroups(templates)))
	mux.HandleFunc("/groups/new", requirePermission(store, webauth.PermViewStatus, handleScopeGroupNew(ref, templates)))
	mux.HandleFunc("POST /groups/new", requirePermission(store, webauth.PermEditScopes, handleScopeGroupNew(ref, templates)))
	mux.HandleFunc("/groups/{id}/edit", requirePermission(store, webauth.PermViewStatus, handleScopeGroupEdit(ref, templates)))
	mux.HandleFunc("POST /groups/{id}/edit", requirePermission(store, webauth.PermEditScopes, handleScopeGroupEdit(ref, templates)))
	mux.HandleFunc("POST /groups/{id}/delete", requirePermission(store, webauth.PermEditScopes, handleScopeGroupDelete(ref, templates)))
	// /pending: candidate review and commit (pending.go).
	mux.HandleFunc("/pending", requirePermission(store, webauth.PermViewStatus, handlePending(ref)))
	mux.HandleFunc("GET /api/pending-summary", requirePermission(store, webauth.PermViewStatus, handlePendingSummary()))
	mux.HandleFunc("POST /pending/commit", requirePermission(store, webauth.PermEditScopes, handlePendingCommit(*cfgPath, ref)))
	mux.HandleFunc("POST /pending/discard", requirePermission(store, webauth.PermEditScopes, handlePendingDiscard(ref)))
	mux.HandleFunc("POST /pending/discard/scopes/{scope}", requirePermission(store, webauth.PermEditScopes, handlePendingDiscardScope(ref)))
	mux.HandleFunc("POST /pending/nodeop/commit", requirePermission(store, webauth.PermEditConfig, handlePendingNodeOpCommit(*cfgPath, ref)))
	mux.HandleFunc("POST /pending/nodeop/discard", requirePermission(store, webauth.PermEditConfig, handlePendingNodeOpDiscard()))
	mux.HandleFunc("/audit", requirePermission(store, webauth.PermViewAudit, handleAudit(ref)))

	// Self-service password change (password.go).
	mux.HandleFunc("/password", requirePermission(store, webauth.PermViewStatus, handlePasswordForm(ref)))
	mux.HandleFunc("POST /password", requirePermission(store, webauth.PermViewStatus, changePasswordFormHandler(ref, store, repl)))
	mux.HandleFunc("POST /internal/password/change", applyPasswordChangeHandler(ref, repl))

	// Users and mail settings (users.go, mail.go), replicated by authsync.go.
	mux.HandleFunc("GET /users", requirePermission(store, webauth.PermEditConfig, handleUsersGet(store)))
	mux.HandleFunc("POST /users/new", requirePermission(store, webauth.PermEditConfig, handleUserCreate(store, repl, ref)))
	mux.HandleFunc("GET /users/{name}", requirePermission(store, webauth.PermEditConfig, handleUserEditGet(store)))
	mux.HandleFunc("POST /users/{name}", requirePermission(store, webauth.PermEditConfig, handleUserUpdate(store, repl, ref)))
	mux.HandleFunc("POST /users/{name}/signout", requirePermission(store, webauth.PermEditConfig, handleUserSignout(store, repl, ref)))
	mux.HandleFunc("POST /users/{name}/delete", requirePermission(store, webauth.PermEditConfig, handleUserDelete(store, repl, ref)))
	mux.HandleFunc("GET /config/mail", requirePermission(store, webauth.PermEditConfig, handleMailGet(store)))
	mux.HandleFunc("POST /config/mail", requirePermission(store, webauth.PermEditConfig, handleMailPost(store, repl, ref)))
	mux.HandleFunc("POST /internal/auth-doc", repl.handleAuthDocPost)
	mux.HandleFunc("GET /internal/auth-doc/meta", repl.handleAuthDocMeta)
	mux.HandleFunc("GET /internal/auth-doc", repl.handleAuthDocGet)

	mux.HandleFunc("POST /nodes/probe/add", requirePermission(store, webauth.PermEditConfig, addProbeFormHandler(*cfgPath, ref)))
	mux.HandleFunc("POST /nodes/probe/remove", requirePermission(store, webauth.PermEditConfig, removeProbeFormHandler(*cfgPath, ref)))
	mux.HandleFunc("POST /nodes/replace", requirePermission(store, webauth.PermEditConfig, replaceNodeFormHandler(*cfgPath, ref)))
	mux.HandleFunc("POST /nodes/inspect", requirePermission(store, webauth.PermEditConfig, inspectNodeFormHandler(ref)))
	mux.HandleFunc("POST /nodes/offboard", requirePermission(store, webauth.PermEditConfig, offboardNodeFormHandler(ref, *cfgPath)))
	mux.HandleFunc("POST /nodes/rename", requirePermission(store, webauth.PermEditConfig, renameNodeFormHandler(*cfgPath, ref)))
	mux.HandleFunc("POST /internal/nodes/probe/add", applyProbeAddHandler(*cfgPath, ref))
	mux.HandleFunc("POST /internal/nodes/probe/remove", applyProbeRemoveHandler(*cfgPath, ref))
	mux.HandleFunc("POST /internal/nodes/rename", applyRenameHandler(*cfgPath, ref))
	mux.HandleFunc("POST /internal/web/vip-host", applyVIPHostHandler(*cfgPath, ref))
	mux.HandleFunc("POST /internal/nodes/remove", applyNodeRemoveHandler(*cfgPath, ref))
	mux.HandleFunc("POST /internal/nodes/replace", applyNodeReplaceHandler(*cfgPath, ref))

	var handler http.Handler = mux
	scheme := "http"
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		scheme = "https"
	}
	// vip_host is read live from ref on every request: a committed mgmt
	// VIP change updates it without restarting dnshived-web.
	liveVIPHost := func() string { return ref.Load().VIPHost }
	{
		_, port, err := net.SplitHostPort(cfg.ListenAddr)
		if err != nil {
			port = cfg.ListenAddr
		}
		if cfg.VIPHost != "" {
			log.Printf("[INIT] non-VIP requests will redirect to %s://%s", scheme, net.JoinHostPort(cfg.VIPHost, port))
		}
		if len(cfg.ExternalHosts) > 0 {
			log.Printf("[INIT] also serving (never redirecting) reverse-proxy host(s): %s", strings.Join(cfg.ExternalHosts, ", "))
		}
		floating := func(host string) bool {
			var nodeHosts []string
			for _, n := range nodesIncludingSelf(ref.Load()) {
				if h, _, err := net.SplitHostPort(n.Addr); err == nil {
					nodeHosts = append(nodeHosts, h)
				}
			}
			return floatingMgmtAddr(nodeHosts, host)
		}
		handler = vipHostMiddleware(liveVIPHost, cfg.ExternalHosts, scheme, port, mux, floating)
	}
	allowedOrigins := func() []string { return append([]string{ref.Load().VIPHost}, cfg.ExternalHosts...) }
	handler = securityHeaders(sameOriginGuard(allowedOrigins, limitBody(compressResponses(handler))))

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		if cfg.HTTPAddr != "" {
			go func() {
				redirectMux := http.NewServeMux()
				redirectMux.HandleFunc("/", redirectToHTTPS(cfg.ListenAddr, liveVIPHost))
				log.Printf("[http] listening on %s (redirects to https)", cfg.HTTPAddr)
				if err := newServer(cfg.HTTPAddr, securityHeaders(redirectMux)).ListenAndServe(); err != nil {
					log.Printf("[ERROR] http redirect listener on %s: %v", cfg.HTTPAddr, err)
				}
			}()
		}
		// :80/:443 are the bootstrap wizard's ports.
		portRedirect := securityHeaders(redirectToHTTPS(cfg.ListenAddr, liveVIPHost))
		go serveRedirectWithRetry(memberHTTPAddr, "", "", portRedirect)
		go serveRedirectWithRetry(memberHTTPSAddr, cfg.TLSCert, cfg.TLSKey, portRedirect)
		log.Printf("[http] listening on %s (TLS)", cfg.ListenAddr)
		log.Fatal(newServer(cfg.ListenAddr, handler).ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey))
	} else {
		log.Printf("[http] listening on %s", cfg.ListenAddr)
		log.Fatal(newServer(cfg.ListenAddr, handler).ListenAndServe())
	}
}
