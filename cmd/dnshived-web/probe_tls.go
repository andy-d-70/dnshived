// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"time"

	"dnshived/internal/probepin"
)

const maxCertUploadForm = 256 << 10

// postProbeConfig sends one admin patch to a probe host's POST /api/v1/config.
func postProbeConfig(node NodeConfig, patch map[string]interface{}) error {
	body, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, node.baseURL()+"/api/v1/config", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if node.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+node.AdminToken)
	}
	resp, err := refreshProbeClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxClientBody))
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

// pushProbeHostPlainHTTP switches a probe host's unencrypted API on or off.
// The probe restarts to apply it, so it is only safe over a pinned connection.
func pushProbeHostPlainHTTP(node NodeConfig, enabled bool) error {
	return postProbeConfig(node, map[string]interface{}{"plain_http": enabled})
}

// pushProbeHostCertificate hands a certificate and key to a probe host and
// returns the fingerprint it now serves.
func pushProbeHostCertificate(node NodeConfig, certPEM, keyPEM string) (string, error) {
	body, err := json.Marshal(map[string]string{"cert_pem": certPEM, "key_pem": keyPEM})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, node.baseURL()+"/api/v1/tls", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if node.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+node.AdminToken)
	}
	resp, err := refreshProbeClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxClientBody))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(respBody))
		}
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, e.Error)
	}
	var ok struct {
		Fingerprint string `json:"tls_fingerprint"`
	}
	if err := json.Unmarshal(respBody, &ok); err != nil || !probepin.Valid(ok.Fingerprint) {
		return "", fmt.Errorf("the probe host did not report the new fingerprint")
	}
	return ok.Fingerprint, nil
}

// probeTLSState is what the Probes page shows about one probe host's API.
type probeTLSState struct {
	Name, Addr, Fingerprint string
	Pinned                  bool
	PlainKnown, PlainOpen   bool
	Err                     string
}

// buildProbeTLSStates reads each probe host's plain_http state, over TLS when
// the host is pinned.
func buildProbeTLSStates(hosts []NodeConfig) []probeTLSState {
	out := make([]probeTLSState, 0, len(hosts))
	for _, h := range hosts {
		st := probeTLSState{Name: h.Name, Addr: h.Addr, Fingerprint: h.TLSFingerprint, Pinned: h.TLSFingerprint != "", PlainOpen: true}
		if st.Pinned {
			var s struct {
				PlainHTTP *bool `json:"plain_http"`
			}
			if _, err := doGet(httpClient, h, "/api/v1/status", &s); err != nil {
				st.Err = err.Error()
			} else if s.PlainHTTP != nil {
				st.PlainKnown, st.PlainOpen = true, *s.PlainHTTP
			}
		}
		out = append(out, st)
	}
	return out
}

// closePlainAfterAdopt pins and then closes the plain port of a probe that was
// just adopted, once its TLS API answers with the pinned certificate. The
// result is a line for the adoption report; the probe stays reachable if any
// step fails.
func closePlainAfterAdopt(entry NodeConfig) string {
	if entry.TLSFingerprint == "" {
		return "The probe reported no proven TLS fingerprint, so it stays on plain HTTP: pin it from the Probes page.\n"
	}
	deadline := time.Now().Add(45 * time.Second)
	for {
		err := checkPinnedTLS(entry, entry.TLSFingerprint)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return "The probe's TLS API did not answer with the pinned certificate in time (" + err.Error() + "), so its plain HTTP port is still open: close it from the Probes page.\n"
		}
		time.Sleep(2 * time.Second)
	}
	if err := pushProbeHostPlainHTTP(entry, false); err != nil {
		return "The probe is pinned, but closing its plain HTTP port failed (" + err.Error() + "): close it from the Probes page.\n"
	}
	return "The probe is pinned and its plain HTTP port is being closed.\n"
}

var pinNowTmpl = template.Must(template.New("pin-now").Parse(`<!doctype html>
<title>dnshived-web — pin probe certificate</title>
` + styleHTML + `
` + navHTML + `
<h1>Pin the certificate of {{.Addr}}</h1>

<p>This probe host reports the certificate fingerprint below over its unencrypted port. Anyone who can alter that traffic could
report a different one, so compare it with the fingerprint in the probe host's own log
(<code>journalctl -u dnshived-probe | grep 'TLS API'</code>) before you pin it.</p>
<p><code>{{.Fingerprint}}</code></p>
<form method="post" action="/probes/pin">
<input type="hidden" name="addr" value="{{.Addr}}"><input type="hidden" name="tls_fingerprint" value="{{.Fingerprint}}">
<button type="submit">It matches &mdash; pin it</button> <a href="/probes">cancel</a>
</form>`))

// fetchProbeTLSProof asks a probe host's public tls-info with a fresh nonce
// and reports whether the answer carries a proof, made with the admin token
// this web UI holds, that the fingerprint is the probe's own.
func fetchProbeTLSProof(host NodeConfig) (info probeTLSInfo, proven bool, err error) {
	raw := make([]byte, 16)
	if _, err = rand.Read(raw); err != nil {
		return info, false, err
	}
	nonce := hex.EncodeToString(raw)
	plain := NodeConfig{Name: host.Name, Addr: host.Addr}
	req, err := http.NewRequest(http.MethodGet, plain.baseURL()+"/api/v1/tls-info?nonce="+nonce, nil)
	if err != nil {
		return info, false, err
	}
	resp, err := directHTTPClient.Do(req)
	if err != nil {
		return info, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return info, false, fmt.Errorf("status %d", resp.StatusCode)
	}
	var body struct {
		probeTLSInfo
		Proofs map[string]string `json:"proofs"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		return info, false, fmt.Errorf("parse tls-info: %w", err)
	}
	info = body.probeTLSInfo
	if !probepin.Valid(info.TLSFingerprint) || host.AdminToken == "" {
		return info, false, nil
	}
	for _, p := range body.Proofs {
		if probepin.VerifyTokenProof(host.AdminToken, info.TLSFingerprint, nonce, p) {
			return info, true, nil
		}
	}
	return info, false, nil
}

// newProbeAdminToken makes a random token that passes the token policy.
func newProbeAdminToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// pushProbeRotateToken asks a pinned probe to replace the admin token that
// authenticates this call.
func pushProbeRotateToken(host NodeConfig, newToken string) error {
	body, err := json.Marshal(map[string]string{"new_token": newToken})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, host.baseURL()+"/api/v1/rotate-token", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+host.AdminToken)
	resp, err := refreshProbeClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxClientBody))
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

// replaceProbeHost stores host in place of the entry with the same address.
func replaceProbeHost(cfgPath string, ref *configRef, host NodeConfig) error {
	cfg := ref.Load()
	hosts := append([]NodeConfig{}, cfg.ProbeHosts...)
	found := false
	for i := range hosts {
		if hosts[i].Addr == host.Addr {
			hosts[i], found = host, true
		}
	}
	if !found {
		return fmt.Errorf("no probe host at address %s", host.Addr)
	}
	newCfg := *cfg
	newCfg.ProbeHosts = hosts
	if err := saveWebConfig(cfgPath, &newCfg); err != nil {
		return err
	}
	ref.Store(&newCfg)
	return nil
}

var pinResultTmpl = template.Must(template.New("pin-result").Parse(`<!doctype html>
<title>dnshived-web — probe pinned</title>
` + styleHTML + `
` + navHTML + `
<h1 class="ok">Probe {{.Addr}} is pinned</h1>

<p>Its certificate was proven with the probe's admin token, so nothing had to be compared by hand. The web UI now talks to it over HTTPS only.</p>
{{if .Rotated}}<p class="ok">The probe's admin token was replaced over the pinned connection. The old token was sent in cleartext while the probe was not pinned and no longer works. Other web instances pick the new token up from the probe-host list within a minute; <code>dnshived-top</code> and <code>dnshived-validate</code> need it too if they use the admin token.</p>
{{else}}<p class="warn">The admin token was <b>not</b> replaced: {{.RotateErr}}. The old token travelled in cleartext before this pin, so treat it as known to an observer on the network and replace it as soon as possible.</p>{{end}}
<p><a href="/probes#settings">back to Probes</a></p>`))

// handleProbePinNow serves POST /probes/pin-now. A probe that proves its
// fingerprint with the admin token this web UI holds is pinned at once, and
// its admin token is then replaced over the pinned connection. Any other probe
// gets the manual comparison dialog; pinning is then POST /probes/pin.
func handleProbePinNow(cfgPath string, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		host, ok := probeHostByAddr(ref.Load(), strings.TrimSpace(r.PostForm.Get("addr")))
		if !ok {
			http.Error(w, "unknown probe host", http.StatusNotFound)
			return
		}
		info, proven, err := fetchProbeTLSProof(host)
		if err != nil {
			http.Error(w, "read probe status: "+err.Error(), http.StatusBadGateway)
			return
		}
		if !probepin.Valid(info.TLSFingerprint) {
			http.Error(w, "this probe host reports no TLS fingerprint — upgrade it first", http.StatusConflict)
			return
		}
		user, _ := userFromContext(r)
		if !proven {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = pinNowTmpl.Execute(w, map[string]string{"Addr": host.Addr, "Fingerprint": info.TLSFingerprint})
			return
		}

		host.TLSPort, host.TLSFingerprint = info.TLSPort, info.TLSFingerprint
		if err := checkPinnedTLS(host, host.TLSFingerprint); err != nil {
			http.Error(w, "TLS check with this fingerprint failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		if err := replaceProbeHost(cfgPath, ref, host); err != nil {
			http.Error(w, "save web config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		pushAudit(host, user.Name, "probe.pin", fmt.Sprintf("pinned %s (certificate proven with the admin token)", host.Name))

		rotateErr := ""
		newTok, err := newProbeAdminToken()
		if err == nil {
			err = pushProbeRotateToken(host, newTok)
		}
		if err == nil {
			host.AdminToken = newTok
			err = replaceProbeHost(cfgPath, ref, host)
			if err != nil {
				err = fmt.Errorf("the probe took the new token but saving it here failed (%v): reset it on the probe host", err)
			}
		}
		if err != nil {
			rotateErr = err.Error()
		}
		summary := fmt.Sprintf("admin token of %s replaced over TLS", host.Name)
		if rotateErr != "" {
			summary = fmt.Sprintf("admin token of %s NOT replaced: %s", host.Name, rotateErr)
		}
		pushAudit(host, user.Name, "probe.token_rotate", summary)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = pinResultTmpl.Execute(w, map[string]interface{}{"Addr": host.Addr, "Rotated": rotateErr == "", "RotateErr": rotateErr})
	}
}

// handleProbePlainHTTP serves POST /probes/plain-http. Closing the plain port
// is refused for a probe that is not pinned, because the web UI would lose it.
func handleProbePlainHTTP(ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		cfg := ref.Load()
		host, ok := probeHostByAddr(cfg, strings.TrimSpace(r.PostForm.Get("addr")))
		if !ok {
			http.Error(w, "unknown probe host", http.StatusNotFound)
			return
		}
		enable := r.PostForm.Get("enabled") == "1"
		if !enable && host.TLSFingerprint == "" {
			http.Error(w, "pin this probe's certificate first: closing the plain port of an unpinned probe would cut it off", http.StatusConflict)
			return
		}
		user, _ := userFromContext(r)
		err := pushProbeHostPlainHTTP(host, enable)
		summary := fmt.Sprintf("plain_http -> %v on %s", enable, host.Name)
		if err != nil {
			summary += " FAILED: " + err.Error()
		}
		pushAudit(host, user.Name, "probe.plain_http", summary)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		http.Redirect(w, r, "/probes#settings", http.StatusSeeOther)
	}
}

// handleProbeCertUpload serves POST /probes/tls/upload: the certificate goes
// to the probe over its pinned connection, then the new fingerprint is pinned.
func handleProbeCertUpload(cfgPath string, ref *configRef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxCertUploadForm)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
			return
		}
		cfg := ref.Load()
		host, ok := probeHostByAddr(cfg, strings.TrimSpace(r.PostForm.Get("addr")))
		if !ok {
			http.Error(w, "unknown probe host", http.StatusNotFound)
			return
		}
		if host.TLSFingerprint == "" {
			http.Error(w, "pin this probe's certificate first: the key must not cross an unencrypted connection", http.StatusConflict)
			return
		}
		fp, err := pushProbeHostCertificate(host, r.PostForm.Get("cert_pem"), r.PostForm.Get("key_pem"))
		user, _ := userFromContext(r)
		if err != nil {
			pushAudit(host, user.Name, "probe.tls_upload", fmt.Sprintf("certificate upload to %s FAILED: %v", host.Name, err))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		host.TLSFingerprint = fp
		if err := checkPinnedTLS(host, fp); err != nil {
			http.Error(w, "the probe took the certificate, but the check with its fingerprint failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		hosts := append([]NodeConfig{}, cfg.ProbeHosts...)
		for i := range hosts {
			if hosts[i].Addr == host.Addr {
				hosts[i] = host
			}
		}
		newCfg := *cfg
		newCfg.ProbeHosts = hosts
		if err := saveWebConfig(cfgPath, &newCfg); err != nil {
			http.Error(w, "save web config: "+err.Error(), http.StatusInternalServerError)
			return
		}
		ref.Store(&newCfg)
		pushAudit(host, user.Name, "probe.tls_upload", fmt.Sprintf("certificate of %s replaced, new fingerprint %s", host.Name, fp))
		http.Redirect(w, r, "/probes#settings", http.StatusSeeOther)
	}
}
