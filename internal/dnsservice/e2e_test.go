// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsservice

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dnshived/internal/dnsanswer"
)

func freeUDPPort(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, p, _ := net.SplitHostPort(pc.LocalAddr().String())
	return p
}

func udpQuery(t *testing.T, addr string, name string, typ uint16, tcp bool) (rcode, an int, ok bool) {
	t.Helper()
	netw := "udp"
	if tcp {
		netw = "tcp"
	}
	c, err := net.DialTimeout(netw, addr, time.Second)
	if err != nil {
		return 0, 0, false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(700 * time.Millisecond))
	q := query(name, typ)
	if tcp {
		q = append([]byte{byte(len(q) >> 8), byte(len(q))}, q...)
	}
	if _, err := c.Write(q); err != nil {
		return 0, 0, false
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil || n < 12 {
		return 0, 0, false
	}
	if tcp {
		buf = buf[2:n]
		n -= 2
	}
	return int(buf[3] & 0xF), int(buf[6])<<8 | int(buf[7]), true
}

// TestE2E_RelayServesPublishedTable runs the real relay binary against a table the service publishes. Set
// DNSRELAY_BIN to the built dnshived-dnsrelay to run it.
func TestE2E_RelayServesPublishedTable(t *testing.T) {
	bin := os.Getenv("DNSRELAY_BIN")
	if bin == "" {
		t.Skip("set DNSRELAY_BIN to run")
	}
	dir, err := os.MkdirTemp("", "dnsstore-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	r := openRigMode(t, dir, 0o644)
	port := freeUDPPort(t)
	addr := "127.0.0.1:" + port
	cfg := map[string]any{
		"listen_addr": addr, "upstreams": []string{"127.0.0.1:53"}, "allowed_interfaces": []string{"lo"},
		"table_file": filepath.Join(r.dir, "dnstable.bin"), "timeout": "300ms", "log_file": "",
	}
	b, _ := json.Marshal(cfg)
	cfgPath := filepath.Join(r.dir, "relay.json")
	if err := os.WriteFile(cfgPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"--config", cfgPath}
	name := bin
	if os.Getuid() == 0 {
		name = "setpriv"
		args = append([]string{"--reuid=dnshived", "--regid=dnshived", "--init-groups", bin}, args...)
	}
	cmd := exec.Command(name, args...)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	if code, _ := r.do("POST", "/api/v1/dnsstore/commit", hostBody("00000000000000000000000000000001")); code != 200 {
		t.Fatalf("commit: %d", code)
	}
	wait := func(what string, cond func() bool) {
		t.Helper()
		for i := 0; i < 60; i++ {
			if cond() {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s\nrelay output:\n%s", what, out.String())
	}
	wait("the relay to answer the published host", func() bool {
		rc, an, ok := udpQuery(t, addr, "cam-1.example.lan", dnsanswer.TypeA, false)
		return ok && rc == 0 && an == 1
	})
	wait("the relay to answer over TCP", func() bool {
		rc, an, ok := udpQuery(t, addr, "cam-1.example.lan", dnsanswer.TypeA, true)
		return ok && rc == 0 && an == 1
	})
	if code, _ := r.do("POST", "/api/v1/dnsstore/settings", `{"authoritative":true}`); code != 200 {
		t.Fatalf("cutover: %d", code)
	}
	wait("the relay to answer authoritatively after the cutover", func() bool {
		rc, _, ok := udpQuery(t, addr, "missing.example.lan", dnsanswer.TypeA, false)
		return ok && rc == 3
	})
	if rc, _, ok := udpQuery(t, addr, "missing.example.lan", dnsanswer.TypeA, false); !ok || rc != 3 {
		t.Fatalf("authoritative NXDOMAIN inside our domain: ok=%v rcode=%d", ok, rc)
	}
	if code, _ := r.do("POST", "/api/v1/dnsstore/commit", `{"author":"t","ops":[{"op":"put","kind":"host","host":{"label":"cam-2","domains":["example.lan"],"addrs":[{"ip":"10.0.0.6","ptr":true}]}}]}`); code != 200 {
		t.Fatalf("second commit: %d", code)
	}
	wait("the relay to pick up the second host without a restart", func() bool {
		rc, an, ok := udpQuery(t, addr, "cam-2.example.lan", dnsanswer.TypeA, false)
		return ok && rc == 0 && an == 1
	})
	if code, _ := r.do("POST", "/api/v1/dnsstore/commit", `{"author":"t","ops":[{"op":"del","kind":"host","id":"00000000000000000000000000000001"}]}`); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	wait("the deleted host to disappear", func() bool {
		rc, _, ok := udpQuery(t, addr, "cam-1.example.lan", dnsanswer.TypeA, false)
		return ok && rc == 3
	})
}
