// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// memberHTTPAddr/memberHTTPSAddr: the bootstrap wizard's ports, kept as
// redirect-only listeners once the node is a cluster member.
const (
	memberHTTPAddr  = ":80"
	memberHTTPSAddr = ":443"
)

func serveRedirectWithRetry(addr, cert, key string, h http.Handler) {
	log.Printf("[http] %s redirects to the web UI", addr)
	logged := false
	for {
		var err error
		if cert != "" && key != "" {
			err = newServer(addr, h).ListenAndServeTLS(cert, key)
		} else {
			err = newServer(addr, h).ListenAndServe()
		}
		if !logged {
			log.Printf("[http] redirect listener on %s: %v — retrying every 10s", addr, err)
			logged = true
		}
		time.Sleep(10 * time.Second)
	}
}

// redirectToHTTPS returns a handler that 301-redirects every request to
// httpsAddr's port on the same host.
func redirectToHTTPS(httpsAddr string, vipHost func() string) http.HandlerFunc {
	_, port, err := net.SplitHostPort(httpsAddr)
	if err != nil {
		port = httpsAddr // best-effort: ListenAddr was somehow just a bare port
	}
	return func(w http.ResponseWriter, r *http.Request) {
		host := vipHost()
		if host == "" {
			host = r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
		}
		target := "https://" + net.JoinHostPort(host, port) + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	}
}

func vipHostMiddleware(vipHostFn func() string, extraHosts []string, scheme, port string, h http.Handler, isFloating ...func(host string) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vipHost := vipHostFn()
		if vipHost == "" || strings.HasPrefix(r.URL.Path, "/internal/") {
			h.ServeHTTP(w, r)
			return
		}
		host := r.Host
		if hh, _, err := net.SplitHostPort(host); err == nil {
			host = hh
		}
		if strings.EqualFold(host, vipHost) {
			h.ServeHTTP(w, r)
			return
		}
		for _, eh := range extraHosts {
			if strings.EqualFold(host, eh) {
				h.ServeHTTP(w, r)
				return
			}
		}
		for _, f := range isFloating {
			if f(host) {
				h.ServeHTTP(w, r)
				return
			}
		}
		target := scheme + "://" + net.JoinHostPort(vipHost, port) + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

func floatingMgmtAddr(nodeHosts []string, host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	nodes := make(map[string]bool, len(nodeHosts))
	for _, h := range nodeHosts {
		nodes[h] = true
	}
	if nodes[ip.String()] {
		return false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		hasNode, hasHost := false, false
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if nodes[ipNet.IP.String()] {
				hasNode = true
			}
			if ipNet.IP.Equal(ip) {
				hasHost = true
			}
		}
		if hasNode && hasHost {
			return true
		}
	}
	return false
}
