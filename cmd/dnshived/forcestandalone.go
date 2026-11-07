// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"dnshived/internal/auditlog"
	"dnshived/internal/config"
	"dnshived/internal/ownership"
)

// Replaceable in tests.
var (
	geteuid     = os.Geteuid
	chownConfig = ownership.Dnshived
)

// standaloneConfig returns cfg with this node as the only member and a
// higher membership epoch. The rest of the configuration is kept.
func standaloneConfig(cfg *config.Cluster) *config.Cluster {
	out := *cfg
	out.Peers = nil
	out.MembershipEpoch = cfg.MembershipEpoch + 1
	return &out
}

const forceStandaloneWarning = `
FORCE STANDALONE

This makes THIS node the only member of the cluster "%s":
  - it forgets its %d peer(s): %s
  - its membership epoch goes from %d to %d
  - it will serve every scope by itself and accept configuration changes alone

Do this only when the other cores are gone for good or cannot be reached for a
long time. If they are still running and merely cut off from this node, they
will keep serving too and the same scope can be answered twice.

When the other cores return they see the higher epoch, stop serving and report
that they were removed while away. Re-adopt each of them from this node's web
UI (Cluster Config) to bring them back.

Restart dnshived afterwards for the change to take effect.
`

// runForceStandalone is the console command: it asks for confirmation by
// the cluster id, rewrites cluster.json and writes a local audit line.
func runForceStandalone(cfgPath string, in io.Reader, out io.Writer) error {
	if geteuid() != 0 {
		return errors.New("run this command as root (sudo dnshived --force-standalone)")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", cfgPath, err)
	}
	fmt.Fprintf(out, forceStandaloneWarning, cfg.ClusterID, len(cfg.Peers), strings.Join(cfg.Peers, ", "), cfg.MembershipEpoch, cfg.MembershipEpoch+1)
	fmt.Fprintf(out, "\nType the cluster id (%s) to continue: ", cfg.ClusterID)
	answer, _ := bufio.NewReader(in).ReadString('\n')
	if strings.TrimSpace(answer) != cfg.ClusterID {
		return errors.New("not confirmed, nothing changed")
	}
	next := standaloneConfig(cfg)
	if err := config.Save(cfgPath, next); err != nil {
		return fmt.Errorf("save %s: %w", cfgPath, err)
	}
	if err := chownConfig(cfgPath); err != nil {
		return fmt.Errorf("hand %s back to the dnshived account (the daemon cannot read it otherwise): %w", cfgPath, err)
	}
	logger := auditlog.New(filepath.Join(dataDir(next), "audit.log"))
	summary := fmt.Sprintf("forced standalone from the console: peers %v removed, membership epoch %d -> %d", cfg.Peers, cfg.MembershipEpoch, next.MembershipEpoch)
	if err := logger.Append("root", cfg.NodeID, "cluster.force_standalone", summary); err != nil {
		fmt.Fprintf(out, "warning: the audit line could not be written: %v\n", err)
	}
	fmt.Fprintf(out, "Done. This node is now standalone at membership epoch %d. Restart it: systemctl restart dnshived\n", next.MembershipEpoch)
	return nil
}
