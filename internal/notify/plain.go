// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package notify

import (
	"regexp"
	"strings"
)

type plainText struct{ title, meaning string }

var plainByPrefix = map[string]plainText{
	"AGENT:UNSERVED":      {"A scope is not being served", "No core answers DHCP and DNS for this scope right now, so clients in that network get no address until it is served again."},
	"AGENT:STANDALONE":    {"A core runs apart from the cluster", "The core cannot reach the others and decides alone. Check the network between the cores."},
	"AGENT:DESIRED:SPLIT": {"The cores disagree about who serves what", "Different cores hold different assignments. It normally settles once they can talk to each other again."},
	"AGENT:TOKEN_DENY":    {"A request was refused because of its token", "Something tried to act on a core with a token the cluster does not accept."},
	"AGENT:DRIFT":         {"What runs differs from what is configured", "A core found that a service, address or setting does not match the configuration and repaired it. Repeated drift on the same scope is worth a look."},
	"AGENT:TOKEN_EXPIRE":  {"A token is about to expire", "Renew it before it stops working."},
	"AGENT:RATE_LIMIT":    {"Requests were rate limited", "A client sent more requests than a core accepts, and the surplus was refused."},
	"AGENT:SANITY":        {"A self check found a problem", "A core checked its own state and found something that should not be."},
	"AGENT:WARN":          {"A core reported a warning", "Nothing is down, but a core wants attention."},
	"AGENT:BACKUP":        {"Backup written", ""},
	"CONFIG:WARN":         {"The configuration needs a look", "The configuration is accepted but has a point worth checking."},
}

// compactKinds are routine events whose message already says everything: they
// show as one "Title: message" line.
var compactKinds = map[string]string{"AGENT:BACKUP": "automated backup written: "}

var vrrpCoherence = regexp.MustCompile(`gate_vrrp_coherence\s+DHCP gate is open but VRRP state is (\w+), not (\w+)`)

// Plain returns a title and a meaning in everyday words for an event kind,
// and rewrites internal check names inside the example message. An unknown
// kind keeps its own name as the title.
func Plain(prefix, message string) (title, meaning, example string) {
	example = vrrpCoherence.ReplaceAllString(message, "this core may answer DHCP but does not hold the scope's address (VRRP state $1, expected $2)")
	example = strings.Replace(example, "gate_closed", "the DHCP gate is closed", 1)
	if t, ok := plainByPrefix[prefix]; ok {
		return t.title, t.meaning, example
	}
	return prefix, "", example
}

// Lead is the one plain sentence an alert of this impact opens with.
func (i Impact) Lead() string {
	switch i {
	case ClusterAtRisk:
		return "The cluster has lost two cores or its majority: the next failure takes the service down."
	case NodeLost:
		return "One core is not reachable. The others carry the service."
	case ServiceDegraded:
		return "Something is not working as it should, but the cluster is still up."
	case Warning:
		return "Something needs a look, but nothing is down."
	case Info:
		return "For your information, no action needed."
	}
	return ""
}
