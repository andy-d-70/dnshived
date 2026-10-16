// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package daemonstatus

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"
)

// queryTimeout bounds a single systemctl/binary invocation.
const queryTimeout = 3 * time.Second

// Status describes one systemd unit's current state.
type Status struct {
	Unit          string `json:"unit"`
	LoadState     string `json:"load_state"`                // "loaded", "not-found", ...
	ActiveState   string `json:"active_state"`              // "active", "inactive", "failed", ...
	SubState      string `json:"sub_state"`                 // "running", "dead", "exited", ...
	UnitFileState string `json:"unit_file_state,omitempty"` // "enabled", "disabled", "static", ...
	UptimeSec     int64  `json:"uptime_seconds,omitempty"`
	Version       string `json:"version,omitempty"`
	Error         string `json:"error,omitempty"`
	PID           int    `json:"pid,omitempty"`
	User          string `json:"user,omitempty"`
	// ActiveCount/TotalCount are set only on the single synthetic "dnsmasq"
	// aggregate entry (cmd/dnshived's /api/v1/daemons handler).
	ActiveCount int `json:"active_count,omitempty"`
	TotalCount  int `json:"total_count,omitempty"`
}

// Query reads one unit's state via `systemctl show`.
func Query(unit, versionBin string) Status {
	s := Status{Unit: unit}

	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "show",
		"--property=LoadState,ActiveState,SubState,UnitFileState,ActiveEnterTimestampMonotonic,MainPID",
		"--", unit).Output()
	if err != nil {
		s.Error = "systemctl show: " + err.Error()
		return s
	}

	props := parseShow(string(out))
	s.LoadState = props["LoadState"]
	s.ActiveState = props["ActiveState"]
	s.SubState = props["SubState"]
	s.UnitFileState = props["UnitFileState"]

	if s.ActiveState == "active" {
		if usec, err := strconv.ParseInt(props["ActiveEnterTimestampMonotonic"], 10, 64); err == nil {
			if boot, err := readBootUptime(); err == nil {
				s.UptimeSec = uptimeSeconds(usec, boot)
			}
		}
	}
	s.PID, s.User = processIdentity(props["MainPID"])

	if versionBin != "" {
		s.Version = queryVersion(ctx, versionBin)
	}

	return s
}

// QueryMany queries multiple units in a single systemctl invocation
// instead of one subprocess per unit.
func QueryMany(units []string) map[string]Status {
	result := make(map[string]Status, len(units))
	if len(units) == 0 {
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	args := []string{"show", "--property=Id,LoadState,ActiveState,SubState,ActiveEnterTimestampMonotonic,MainPID", "--"}
	args = append(args, units...)
	out, err := exec.CommandContext(ctx, "systemctl", args...).Output()
	if err != nil {
		errMsg := "systemctl show: " + err.Error()
		for _, u := range units {
			result[u] = Status{Unit: u, Error: errMsg}
		}
		return result
	}

	boot, bootErr := readBootUptime()

	for _, block := range strings.Split(string(out), "\n\n") {
		props := parseShow(block)
		id := props["Id"]
		if id == "" {
			continue
		}
		s := Status{
			Unit:        id,
			LoadState:   props["LoadState"],
			ActiveState: props["ActiveState"],
			SubState:    props["SubState"],
		}
		if s.ActiveState == "active" && bootErr == nil {
			if usec, perr := strconv.ParseInt(props["ActiveEnterTimestampMonotonic"], 10, 64); perr == nil {
				s.UptimeSec = uptimeSeconds(usec, boot)
			}
		}
		s.PID, s.User = processIdentity(props["MainPID"])
		result[id] = s
	}
	return result
}

func QueryActiveGlob(pattern string) map[string]Status {
	result := make(map[string]Status)

	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "show",
		"--property=Id,LoadState,ActiveState,SubState,ActiveEnterTimestampMonotonic,MainPID",
		"--", pattern).Output()
	if err != nil {
		return result
	}

	boot, bootErr := readBootUptime()

	for _, block := range strings.Split(string(out), "\n\n") {
		props := parseShow(block)
		id := props["Id"]
		if id == "" {
			continue
		}
		s := Status{
			Unit:        id,
			LoadState:   props["LoadState"],
			ActiveState: props["ActiveState"],
			SubState:    props["SubState"],
		}
		if s.ActiveState == "active" && bootErr == nil {
			if usec, perr := strconv.ParseInt(props["ActiveEnterTimestampMonotonic"], 10, 64); perr == nil {
				s.UptimeSec = uptimeSeconds(usec, boot)
			}
		}
		s.PID, s.User = processIdentity(props["MainPID"])
		result[id] = s
	}
	return result
}

// parseShow parses `systemctl show --property=...` output (one KEY=VALUE
// pair per line, in the order the properties were requested) into a map.
func parseShow(out string) map[string]string {
	props := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		props[key] = value
	}
	return props
}

func uptimeSeconds(activeMonotonicUsec int64, bootUptimeSec float64) int64 {
	if activeMonotonicUsec <= 0 {
		return 0
	}
	elapsed := bootUptimeSec - float64(activeMonotonicUsec)/1e6
	if elapsed < 0 {
		return 0
	}
	return int64(elapsed)
}

// processIdentity resolves a MainPID string (from `systemctl show`) to the
// actual running process's PID and owning username, via
// /proc/<pid>/status.
func processIdentity(pidStr string) (int, string) {
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		return 0, ""
	}
	data, err := os.ReadFile("/proc/" + pidStr + "/status")
	if err != nil {
		return pid, ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || key != "Uid" {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			return pid, ""
		}
		if u, err := user.LookupId(fields[0]); err == nil {
			return pid, u.Username
		}
		return pid, "uid " + fields[0]
	}
	return pid, ""
}

func readBootUptime() (float64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, os.ErrInvalid
	}
	return strconv.ParseFloat(fields[0], 64)
}

type versionEntry struct {
	modTime time.Time
	size    int64
	version string
}

var (
	versionMu    sync.Mutex
	versionCache = map[string]versionEntry{}
	versionExec  = func(ctx context.Context, bin string) ([]byte, error) {
		return exec.CommandContext(ctx, bin, "--version").CombinedOutput()
	}
)

// queryVersion runs bin --version only when bin changed since the last
// run (a package upgrade); otherwise it answers from the cache.
func queryVersion(ctx context.Context, bin string) string {
	fi, statErr := os.Stat(bin)
	if statErr == nil {
		versionMu.Lock()
		e, ok := versionCache[bin]
		versionMu.Unlock()
		if ok && e.modTime.Equal(fi.ModTime()) && e.size == fi.Size() {
			return e.version
		}
	}
	out, err := versionExec(ctx, bin)
	if err != nil {
		return ""
	}
	v := parseVersionOutput(string(out))
	if statErr == nil {
		versionMu.Lock()
		versionCache[bin] = versionEntry{modTime: fi.ModTime(), size: fi.Size(), version: v}
		versionMu.Unlock()
	}
	return v
}

// Version runs bin --version once, standalone.
func Version(bin string) string {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	return queryVersion(ctx, bin)
}

func parseVersionOutput(out string) string {
	firstLine, _, _ := strings.Cut(out, "\n")
	line := strings.TrimSpace(firstLine)
	_, version, ok := strings.Cut(line, " ")
	if !ok {
		return line
	}
	return version
}
