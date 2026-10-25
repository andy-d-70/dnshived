// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"bytes"
	"dnshived/internal/loglevel"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"dnshived/internal/config"
)

// Static VRRP priorities for the management VIP.
const (
	mgmtVIPPriorityCore3 = 110
	mgmtVIPPriorityCore1 = 100
	mgmtVIPPriorityCore2 = 90
)

type mgmtVIPData struct {
	Interface string
	VRRPID    int
	Priority  int
	VIP       string
}

// mgmtVIPTmpl renders the management-plane VIP's keepalived config.
var mgmtVIPTmpl = template.Must(template.New("keepalived-mgmt").Parse(`# dnshived managed — management VIP
# DO NOT EDIT — this file is rendered by dnshived and will be overwritten.
vrrp_instance DNSHIVED_MGMT {
    state BACKUP
    interface {{.Interface}}
    virtual_router_id {{.VRRPID}}
    priority {{.Priority}}
    advert_int 1
    nopreempt
    virtual_ipaddress {
        {{.VIP}}
    }
}
`))

// mgmtVIPConfPath is where keepalived-mgmt.conf is rendered — factored
// out so the render and decommission paths below always agree on it.
func mgmtVIPConfPath(dataDir string) string {
	return filepath.Join(dataDir, "keepalived-mgmt.conf")
}

func (a *Agent) RenderMgmtVIPConfig(mgmtVIP *config.MgmtVIPConfig, platform *config.Platform) error {
	path := mgmtVIPConfPath(a.dataDir)
	applicable := mgmtVIP != nil && platform != nil && platform.Mgmt != ""
	if !applicable {
		return a.decommissionMgmtVIP(path)
	}

	priority := mgmtVIPPriorityCore2
	switch a.role {
	case config.RoleCore3:
		priority = mgmtVIPPriorityCore3
	case config.RoleCore1:
		priority = mgmtVIPPriorityCore1
	}

	data := mgmtVIPData{
		Interface: platform.ResolveMgmt(a.role),
		VRRPID:    mgmtVIP.VRRPID,
		Priority:  priority,
		VIP:       mgmtVIP.VIP,
	}
	var buf bytes.Buffer
	if err := mgmtVIPTmpl.Execute(&buf, data); err != nil {
		return err
	}
	// Every config save calls this.
	old, readErr := os.ReadFile(path)
	changed := readErr != nil || !bytes.Equal(old, buf.Bytes())
	if changed {
		if err := atomicWriteFile(path, buf.Bytes(), 0o644); err != nil {
			return err
		}
	}
	a.mu.Lock()
	restart := changed || a.mgmtRestartPending
	a.mu.Unlock()
	// A rendered config is useless if nothing is actually running to read it.
	if !restart {
		if err := a.ensureMgmtKeepalivedRunning(); err != nil {
			loglevel.Warnf("[AGENT:WARN] ensure dnshived-keepalived-mgmt running: %v", err)
		}
		return nil
	}
	err := a.reloadMgmtKeepalivedForConfig()
	a.mu.Lock()
	a.mgmtRestartPending = err != nil
	a.mu.Unlock()
	if err != nil {
		loglevel.Warnf("[AGENT:WARN] apply changed management VIP config: %v — retried on the next config save or daemon start", err)
	} else {
		loglevel.Infof("[AGENT:MGMT_VIP] management VIP config changed — dnshived-keepalived-mgmt reloaded")
	}
	return nil
}

// ensureMgmtKeepalivedRunning enables and starts the management-VIP
// keepalived unit, leaving an already-running one alone.
func (a *Agent) ensureMgmtKeepalivedRunning() error {
	unit := "dnshived-keepalived-mgmt.service"
	if a.helperClient != nil {
		return a.helperClient.EnsureMgmtKeepalived()
	}
	return fmt.Errorf("%s: %w", unit, errNoHelper)
}

func (a *Agent) reloadMgmtKeepalivedForConfig() error {
	unit := "dnshived-keepalived-mgmt.service"
	if a.helperClient != nil {
		return a.helperClient.ReloadMgmtKeepalived()
	}
	return fmt.Errorf("%s: %w", unit, errNoHelper)
}

// decommissionMgmtVIP tears down a previously-rendered management VIP that
// is no longer applicable.
func (a *Agent) decommissionMgmtVIP(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	loglevel.Infof("[AGENT:DECOMMISSION] management VIP no longer configured — stopping dnshived-keepalived-mgmt and removing %s", path)
	if err := a.stopMgmtKeepalived(); err != nil {
		loglevel.Warnf("[AGENT:WARN] stop dnshived-keepalived-mgmt unit: %v", err)
	}
	return os.Remove(path)
}

// stopMgmtKeepalived stops and disables the management-VIP keepalived
// unit.
func (a *Agent) stopMgmtKeepalived() error {
	if a.helperClient != nil {
		return a.helperClient.StopMgmtKeepalived()
	}
	return errNoHelper
}
