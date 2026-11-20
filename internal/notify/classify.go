// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package notify

import "strings"

// Classify maps a daemon event to its impact class. The class follows the
// event's level first, then the subsystem that raised it, so events of equal
// weight land in one row of the matrix. Node loss itself is not an event of one
// node; it is derived from the cluster view (see Lost).
func Classify(level, prefix string) Impact {
	level = strings.ToUpper(level)
	switch level {
	case "DEBUG":
		return Info
	case "CRITICAL":
		return ServiceDegraded
	}
	p := strings.ToUpper(prefix)
	switch {
	case strings.HasPrefix(p, "AGENT:UNSERVED"), strings.HasPrefix(p, "AGENT:STANDALONE"),
		strings.HasPrefix(p, "DESIRED:SPLIT"), strings.HasPrefix(p, "AGENT:TOKEN_DENY"):
		return ServiceDegraded
	case strings.HasPrefix(p, "AGENT:DRIFT"), strings.HasPrefix(p, "AGENT:TOKEN_EXPIRE"),
		strings.HasPrefix(p, "AGENT:RATE_LIMIT"), strings.HasPrefix(p, "AGENT:SANITY"),
		strings.HasPrefix(p, "AGENT:WARN"), strings.HasPrefix(p, "CONFIG:WARN"):
		return Warning
	}
	switch level {
	case "ERROR":
		return ServiceDegraded
	case "WARNING", "WARN":
		return Warning
	}
	return Info
}

// Lost classifies the loss of cores. Two or more lost, or fewer reachable than
// a majority, puts the cluster at risk; one lost is a node loss.
func Lost(lost, total int) (Impact, bool) {
	switch {
	case lost <= 0 || total <= 0:
		return Info, false
	case lost >= 2 || total-lost <= total/2:
		return ClusterAtRisk, true
	}
	return NodeLost, true
}
