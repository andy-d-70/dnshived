// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"dnshived/internal/config"
)

func TestRenderMgmtVIPConfig_OnlyTheManagementInstance(t *testing.T) {
	a := &Agent{dataDir: t.TempDir(), role: config.RoleCore1}
	_ = a.RenderMgmtVIPConfig(&config.MgmtVIPConfig{VIP: "192.0.2.100/24", VRRPID: 60}, &config.Platform{Mgmt: "eth0"})
	got, err := os.ReadFile(filepath.Join(a.dataDir, "keepalived-mgmt.conf"))
	if err != nil {
		t.Fatal(err)
	}
	want := `# dnshived managed — management VIP
# DO NOT EDIT — this file is rendered by dnshived and will be overwritten.
vrrp_instance DNSHIVED_MGMT {
    state BACKUP
    interface eth0
    virtual_router_id 60
    priority 100
    advert_int 1
    nopreempt
    virtual_ipaddress {
        192.0.2.100/24
    }
}
`
	if string(got) != want {
		t.Fatalf("the management file changed:\n%s", got)
	}
}
