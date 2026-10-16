// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package sysinfo reads system metrics from /proc for the /api/v1/system
// endpoint.
package sysinfo

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Info contains system-level metrics.
type Info struct {
	LoadAvg1    float64 `json:"load_avg_1"`
	LoadAvg5    float64 `json:"load_avg_5"`
	LoadAvg15   float64 `json:"load_avg_15"`
	CPUCount    int     `json:"cpu_count"`
	MemTotalMB  int64   `json:"memory_total_mb"`
	MemUsedMB   int64   `json:"memory_used_mb"`
	MemPct      int     `json:"memory_used_pct"`
	UptimeSec   int64   `json:"uptime_seconds"`
	CollectedAt string  `json:"collected_at"`
	// OS is this host's own short OS identification (e.g. "Debian GNU/Linux 13
	// (trixie)").
	OS string `json:"os,omitempty"`
}

// Collect reads system info from /proc.
func Collect() Info {
	info := Info{CollectedAt: time.Now().UTC().Format(time.RFC3339)}

	// Load average
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			info.LoadAvg1, _ = strconv.ParseFloat(fields[0], 64)
			info.LoadAvg5, _ = strconv.ParseFloat(fields[1], 64)
			info.LoadAvg15, _ = strconv.ParseFloat(fields[2], 64)
		}
	}

	// CPU count
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		info.CPUCount = strings.Count(string(data), "processor\t:")
	}

	// Memory
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, available int64
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			val, _ := strconv.ParseInt(fields[1], 10, 64)
			switch fields[0] {
			case "MemTotal:":
				total = val / 1024 // kB → MB
			case "MemAvailable:":
				available = val / 1024
			}
		}
		info.MemTotalMB = total
		info.MemUsedMB = total - available
		if total > 0 {
			info.MemPct = int(info.MemUsedMB * 100 / total)
		}
	}

	// Uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 1 {
			if f, err := strconv.ParseFloat(fields[0], 64); err == nil {
				info.UptimeSec = int64(f)
			}
		}
	}

	info.OS = readOSPrettyName()

	return info
}

// readOSPrettyName parses /etc/os-release's PRETTY_NAME= line.
func readOSPrettyName() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "PRETTY_NAME=") {
			continue
		}
		v := strings.TrimPrefix(line, "PRETTY_NAME=")
		return strings.Trim(v, "\"")
	}
	return ""
}
