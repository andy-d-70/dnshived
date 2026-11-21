// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsanswer

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func startDnsmasq(t *testing.T, conf string) string {
	t.Helper()
	bin, err := exec.LookPath("dnsmasq")
	if err != nil {
		t.Skip("dnsmasq is not installed")
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	port := addr[strings.LastIndex(addr, ":")+1:]
	_ = pc.Close()
	path := filepath.Join(t.TempDir(), "dnsmasq.conf")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "--keep-in-foreground", "--no-resolv", "--no-hosts", "--no-poll", "--port="+port,
		"--listen-address=127.0.0.1", "--bind-interfaces", "--local-ttl=300", "--pid-file=", "--log-facility=/dev/null", "--conf-file="+path)
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start dnsmasq: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	probe := mkQuery("probe.example.lan", TypeA, false, 0)
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		c, err := net.Dial("udp", "127.0.0.1:"+port)
		if err != nil {
			continue
		}
		_ = c.SetDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = c.Write(probe)
		buf := make([]byte, 512)
		n, err := c.Read(buf)
		_ = c.Close()
		if err == nil && n > 0 {
			return "127.0.0.1:" + port
		}
	}
	t.Fatal("dnsmasq did not start answering")
	return ""
}

func udpAsk(t *testing.T, addr string, q []byte) []byte {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 4096)
	for try := 0; try < 20; try++ {
		_ = c.SetDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := c.Write(q); err != nil {
			t.Fatal(err)
		}
		if n, err := c.Read(buf); err == nil {
			return buf[:n]
		}
	}
	t.Fatal("dnsmasq did not answer")
	return nil
}

func answerSet(r respOut) string {
	var s []string
	for _, a := range r.an {
		s = append(s, fmt.Sprintf("%s %d %s ttl=%d", a.owner, a.typ, a.data, a.ttl))
	}
	sort.Strings(s)
	return strings.Join(s, "; ")
}

func TestDifferential_AgainstDnsmasq(t *testing.T) {
	conf := `local=/example.lan/
host-record=host1.example.lan,10.0.0.1,300
host-record=host1.example.lan,fd00::1,300
host-record=host2.example.lan,10.0.0.2,300
host-record=host2.example.lan,10.0.0.3,300
cname=alias.example.lan,host1.example.lan,300
cname=hop2.example.lan,alias.example.lan,300
cname=ext.example.lan,elsewhere.example.org,300
txt-record=host1.example.lan,"hello world"
srv-host=_svc._tcp.example.lan,host1.example.lan,8080,1,2
mx-host=example.lan,mail.example.lan,10
host-record=mail.example.lan,10.0.0.9,300
ptr-record=7.0.0.10.in-addr.arpa,host1.example.lan
`
	addr := startDnsmasq(t, conf)
	txt := must(RDataTXT("hello world"))
	tb := table(t, lan,
		rrA("host1.example.lan", "10.0.0.1"),
		rr("host1.example.lan", TypeAAAA, 300, must(RDataAAAA("fd00::1"))),
		rrA("host2.example.lan", "10.0.0.2"), rrA("host2.example.lan", "10.0.0.3"),
		rrCNAME("alias.example.lan", "host1.example.lan"), rrCNAME("hop2.example.lan", "alias.example.lan"),
		rrCNAME("ext.example.lan", "elsewhere.example.org"),
		rr("host1.example.lan", TypeTXT, 300, txt),
		rr("_svc._tcp.example.lan", TypeSRV, 300, must(RDataSRV(1, 2, 8080, "host1.example.lan"))),
		rr("example.lan", TypeMX, 300, must(RDataMX(10, "mail.example.lan"))),
		rrA("mail.example.lan", "10.0.0.9"),
		rr("7.0.0.10.in-addr.arpa", TypePTR, 300, must(ToWire("host1.example.lan"))),
	)
	cases := []struct {
		name  string
		qtype uint16
	}{
		{"host1.example.lan", TypeA}, {"host1.example.lan", TypeAAAA}, {"host2.example.lan", TypeA},
		{"host2.example.lan", TypeAAAA}, {"host1.example.lan", TypeTXT}, {"host1.example.lan", TypeMX},
		{"alias.example.lan", TypeA}, {"hop2.example.lan", TypeA}, {"ext.example.lan", TypeA},
		{"alias.example.lan", TypeCNAME}, {"_svc._tcp.example.lan", TypeSRV}, {"example.lan", TypeMX},
		{"7.0.0.10.in-addr.arpa", TypePTR}, {"missing.example.lan", TypeA}, {"missing.example.lan", TypeAAAA},
		{"HOST1.EXAMPLE.LAN", TypeA}, {"_svc._tcp.example.lan", TypeA}, {"mail.example.lan", TypeA},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s/%d", c.name, c.qtype), func(t *testing.T) {
			q := mkQuery(c.name, c.qtype, false, 0)
			want := parseResp(t, udpAsk(t, addr, q))
			out, st := tb.Respond(q, nil, false)
			if st != Answered {
				t.Fatalf("not answered")
			}
			got := parseResp(t, out)
			if got.rcode != want.rcode {
				t.Errorf("rcode: ours %d, dnsmasq %d", got.rcode, want.rcode)
			}
			if a, b := answerSet(got), answerSet(want); a != b {
				t.Errorf("answers differ\n ours:    %s\n dnsmasq: %s", a, b)
			}
			if got.flags&0x0400 != want.flags&0x0400 && len(want.an) > 0 {
				t.Logf("AA differs: ours %#x dnsmasq %#x", got.flags, want.flags)
			}
		})
	}
}
