// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"dnshived/internal/notify"
	"dnshived/internal/webauth"
)

const (
	notifyTick        = time.Minute
	notifyEventWindow = 300
	webhookTimeout    = 10 * time.Second
)

// notifyState is what one web instance remembers between runs. It is local on
// purpose: every instance decides alone whether it is the one that sends.
type notifyState struct {
	LastSummary time.Time `json:"last_summary"`
	LastEvents  time.Time `json:"last_events"`
	Lost        []string  `json:"lost,omitempty"`
	StableSince time.Time `json:"stable_since,omitempty"`
	LastLeases  *int      `json:"last_leases,omitempty"`
	BackupsOK   int       `json:"backups_ok,omitempty"`
	BackupsBad  int       `json:"backups_bad,omitempty"`
}

func loadNotifyState(path string) notifyState {
	var st notifyState
	if data, err := os.ReadFile(path); err == nil {
		json.Unmarshal(data, &st)
	}
	return st
}

func saveNotifyState(path string, st notifyState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// notifyDeps are the outside calls of the sender, replaceable in tests.
type notifyDeps struct {
	settings func() notify.Settings
	nodes    func() []statusRow
	events   func(NodeConfig) ([]event, error)
	self     func() string
	cluster  string
	send     func(d notify.Destination, m notify.Message) error
	base     func() string
	backups  func() time.Duration
	update   func(version string) (state, latest, url string)
	record   func(reason string, d notify.Destination, subject, result string, err error)
	now      func() time.Time
	loc      *time.Location
	state    string
}

// isSender reports whether this instance is the first core, in the cluster's
// fixed order, that it can reach: the instances see the same order, so one of
// them sends and the others stay quiet.
func isSender(rows []statusRow, self string) bool {
	for _, r := range rows {
		if r.FetchError == "" {
			return r.Node.Name == self
		}
	}
	return false
}

func (d notifyDeps) tick() {
	s := d.settings()
	if len(s.Destinations) == 0 {
		return
	}
	rows := d.nodes()
	if !isSender(rows, d.self()) {
		return
	}
	d.cluster = s.ClusterLabel(clusterOf(rows))
	now := d.now()
	st := loadNotifyState(d.state)
	changed := false
	if stable := allStable(rows); stable && st.StableSince.IsZero() {
		st.StableSince, changed = now, true
	} else if !stable && !st.StableSince.IsZero() {
		st.StableSince, changed = time.Time{}, true
	}
	if st.LastSummary.IsZero() {
		st.LastSummary, changed = now, true
	}
	if st.LastEvents.IsZero() {
		st.LastEvents, changed = now, true
	}

	var lost []string
	for _, r := range rows {
		if r.FetchError != "" {
			lost = append(lost, r.Node.Name)
		}
	}
	sort.Strings(lost)
	if !equalStrings(lost, st.Lost) {
		d.sendLoss(s, lost, len(rows), now)
		st.Lost, changed = lost, true
	}

	if fresh := d.collect(rows, st.LastEvents); len(fresh) > 0 {
		d.sendAlerts(s, fresh)
		last := st.LastEvents
		for _, e := range fresh {
			if e.Time.After(last) {
				last = e.Time
			}
			switch {
			case isBackupWritten(e) && e.Level == "INFO":
				st.BackupsOK++
			case isBackupWritten(e):
				st.BackupsBad++
			}
		}
		st.LastEvents, changed = last, true
	}

	if s.Summary.Due(st.LastSummary, now, d.loc) {
		total := d.sendSummary(s, rows, st, now)
		st.LastSummary, st.LastLeases, changed = now, total, true
		st.BackupsOK, st.BackupsBad = 0, 0
	}
	if changed {
		if err := saveNotifyState(d.state, st); err != nil {
			log.Printf("[NOTIFY] save state: %v", err)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// collect returns the events after since from the reachable cores.
func (d notifyDeps) collect(rows []statusRow, since time.Time) []notify.Event {
	var out []notify.Event
	for _, r := range rows {
		if r.FetchError != "" {
			continue
		}
		evs, err := d.events(r.Node)
		if err != nil {
			continue
		}
		for _, e := range evs {
			if e.Timestamp.After(since) {
				out = append(out, notify.Event{Time: e.Timestamp, Level: e.Level, Prefix: e.Prefix, Message: e.Message, Node: r.Node.Name})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}

func isBackupWritten(e notify.Event) bool {
	return e.Prefix == "AGENT:BACKUP" && strings.HasPrefix(e.Message, "automated backup written")
}

// withoutRoutine drops the backup events a routine line already counts.
func withoutRoutine(events []notify.Event) []notify.Event {
	out := events[:0:0]
	for _, e := range events {
		if !(isBackupWritten(e) && e.Level == "INFO") {
			out = append(out, e)
		}
	}
	return out
}

func allStable(rows []statusRow) bool {
	for _, r := range rows {
		if r.FetchError != "" || r.Status.State != "STABLE" {
			return false
		}
	}
	return len(rows) > 0
}

func (d notifyDeps) link() string {
	if d.base == nil {
		return ""
	}
	return d.base()
}

func (d notifyDeps) deliver(reason string, dests []notify.Destination, m notify.Message) {
	subject := m.Subject()
	for _, dest := range dests {
		err := d.send(dest, m)
		if err != nil {
			log.Printf("[NOTIFY] %s (%s): %v", dest.Name, dest.Kind, err)
		}
		if d.record != nil {
			d.record(reason, dest, subject, "", err)
		}
	}
}

// deliverAlarm is deliver for alerts and loss messages: a destination inside
// one of its quiet schedules gets nothing, and the message is not kept for later.
func (d notifyDeps) deliverAlarm(s notify.Settings, reason string, dests []notify.Destination, m notify.Message) {
	at := d.now().In(d.loc)
	var open []notify.Destination
	for _, dest := range dests {
		if name, quiet := s.QuietBy(dest.ID, at); quiet {
			if d.record != nil {
				d.record(reason, dest, m.Subject(), "dropped, quiet schedule "+name, nil)
			}
			continue
		}
		open = append(open, dest)
	}
	d.deliver(reason, open, m)
}

func (d notifyDeps) sendAlerts(s notify.Settings, events []notify.Event) {
	by := map[notify.Impact][]notify.Event{}
	for _, e := range events {
		i := notify.Classify(e.Level, e.Prefix)
		by[i] = append(by[i], e)
	}
	for _, i := range notify.Impacts {
		list := by[i]
		dests := s.Route(i)
		if len(list) == 0 || len(dests) == 0 {
			continue
		}
		d.deliverAlarm(s, "alert: "+i.String(), dests, notify.Alert(i, d.cluster, list, d.loc, d.link()))
	}
}

func lossMessage(i notify.Impact, isLoss bool, cluster, link string, lost []string, total int, now time.Time, loc *time.Location) notify.Message {
	at := now.In(loc).Format("2006-01-02 15:04:05 MST")
	m := notify.Message{Cluster: cluster, At: now, Link: link}
	if !isLoss {
		m.Class = notify.ClassNotify
		m.Title = "all cores reachable again"
		m.Headline = "Every core answers again."
		m.Details = []notify.Detail{{Rows: []notify.Fact{{Label: "Since", Value: at}}}}
		return m
	}
	names := strings.Join(lost, ", ")
	m.Class = notify.ClassOf(i)
	m.Title = fmt.Sprintf("%s: %s", i, names)
	m.Headline = fmt.Sprintf("%s: %s. %s", i, names, i.Describe())
	m.Details = []notify.Detail{{Rows: []notify.Fact{
		{Label: "Not reachable", Value: names},
		{Label: "Since", Value: at},
		{Label: "Cores", Value: fmt.Sprintf("%d of %d reachable", total-len(lost), total)},
	}}}
	return m
}

func (d notifyDeps) sendLoss(s notify.Settings, lost []string, total int, now time.Time) {
	i, isLoss := notify.Lost(len(lost), total)
	reason := "alert: " + i.String()
	if !isLoss {
		i, reason = notify.Info, "recover"
	}
	d.deliverAlarm(s, reason, s.Route(i), lossMessage(i, isLoss, d.cluster, d.link(), lost, total, now, d.loc))
}

// sendSummary sends the daily report and returns the lease total it saw, to
// compare with the next one.
func (d notifyDeps) sendSummary(s notify.Settings, rows []statusRow, st notifyState, to time.Time) *int {
	facts := notify.Facts{Cluster: d.cluster, From: st.LastSummary, To: to, Link: d.link(), LeasesTotal: -1, StableSince: st.StableSince}
	var uptime int64
	leases, haveLeases := 0, false
	for _, r := range rows {
		facts.Nodes = append(facts.Nodes, notify.NodeLine{Name: r.Node.Name, Reachable: r.FetchError == "", State: r.Status.State})
		if r.FetchError != "" {
			continue
		}
		if r.HasSystem && r.System.UptimeSec > 0 && (uptime == 0 || r.System.UptimeSec < uptime) {
			uptime = r.System.UptimeSec
		}
		if r.Status.DHCPActive != nil && isCoreRole(r.Status.Role) {
			leases, haveLeases = leases+*r.Status.DHCPActive, true
		}
		if facts.Version == "" {
			facts.Version = r.Status.Version
		}
	}
	facts.Uptime = time.Duration(uptime) * time.Second
	var total *int
	if haveLeases {
		facts.LeasesTotal, total = leases, &leases
		if st.LastLeases != nil {
			facts.LeasesDelta, facts.HasDelta = leases-*st.LastLeases, true
		}
	}
	if d.update != nil {
		facts.UpdateState, facts.Latest, facts.LatestURL = d.update(facts.Version)
	}
	facts.Events = d.collect(rows, st.LastSummary)
	if d.backups != nil {
		if every := d.backups(); every > 0 {
			expected := int(to.Sub(st.LastSummary) / every)
			facts.Routines = []notify.Routine{{Name: "Backups", Verb: "written", Got: st.BackupsOK + st.BackupsBad, Expected: expected, Flagged: st.BackupsBad}}
		}
	}
	facts.Events = withoutRoutine(facts.Events)
	d.deliver("summary", s.SummaryTargets(), notify.BuildSummary(facts, d.loc))
	return total
}

// sampleMessage is what the test button sends for each class, with invented
// numbers and a note saying so.
func sampleMessage(kind, cluster, link, by string, now time.Time, loc *time.Location) (notify.Message, bool) {
	note := "Test message sent from the Notify page by " + by + ". Nothing is wrong."
	ev := func(level, prefix, msg string) []notify.Event {
		return []notify.Event{{Time: now, Level: level, Prefix: prefix, Message: msg, Node: "core-3"}}
	}
	var m notify.Message
	switch kind {
	case "", "notify":
		m = notify.Alert(notify.Info, cluster, ev("INFO", "AGENT:BACKUP", "automated backup written: backup-20261121-050040.enc, 48.2 KB, on 3 of 3 cores, checked"), loc, link)
	case "warning":
		m = notify.Alert(notify.Warning, cluster, ev("WARNING", "AGENT:DRIFT", "gate_vrrp_coherence DHCP gate is open but VRRP state is BACKUP, not MASTER"), loc, link)
	case "error":
		m = lossMessage(notify.NodeLost, true, cluster, link, []string{"core-3"}, 3, now, loc)
	case "summary":
		m = notify.BuildSummary(notify.Facts{
			Cluster: cluster, From: now.Add(-24 * time.Hour), To: now, Link: link,
			Nodes:    []notify.NodeLine{{Name: "core-1", Reachable: true, State: "STABLE"}, {Name: "core-2", Reachable: true, State: "STABLE"}, {Name: "core-3", Reachable: true, State: "STABLE"}},
			Routines: []notify.Routine{{Name: "Backups", Verb: "written", Got: 24, Expected: 24}},
			Uptime:   12*24*time.Hour + 3*time.Hour, StableSince: now.Add(-9 * 24 * time.Hour), LeasesTotal: 142, LeasesDelta: 7, HasDelta: true,
			Events:  ev("INFO", "AGENT:BACKUP", "backup"),
			Version: "0.9.8.10", Latest: "0.9.9", LatestURL: updateURLPrefix + "latest", UpdateState: "new",
		}, loc)
		m.Facts = append(m.Facts, notify.Fact{Label: "Note", Value: note})
		return m, true
	default:
		return m, false
	}
	m.Details = append(m.Details, notify.Detail{Title: "Test", Rows: []notify.Fact{{Label: "Note", Value: note}}})
	return m, true
}

const notifyLogSep = " | "

var notifyLogActions = map[string]bool{"notify.sent": true, "notify.failed": true, "notify.dropped": true, "notify.test": true}

// recordSend writes one audit entry per send attempt, on every core, so the
// message log reads the same on every web UI: reason, destination, result, subject.
// Addresses and webhook URLs are never part of it.
func recordSend(cfg *WebConfig, reason string, d notify.Destination, subject, result string, err error) {
	action := "notify.sent"
	switch {
	case err != nil:
		action, result = "notify.failed", "failed: "+err.Error()
	case strings.HasPrefix(result, "dropped"):
		action = "notify.dropped"
	case reason == "test":
		action, result = "notify.test", "sent"
	default:
		result = "sent"
	}
	if len(subject) > 300 {
		subject = subject[:300] + "…"
	}
	line := reason + notifyLogSep + d.Name + " (" + d.Kind + ")" + notifyLogSep + result + notifyLogSep + subject + notifyLogSep + newDestinationID()
	auditAll(cfg, "notify", action, line)
}

type notifyLogRow struct {
	Time                        time.Time
	Reason, To, Result, Subject string
	Bad                         bool
}

// fetchNotifyLog returns the newest notification entries, merged from every
// core that answers: a core that was down when a message went out lacks that
// entry, so no single core holds the whole log.
func fetchNotifyLog(nodes []NodeConfig, max int) []notifyLogRow {
	var rows []notifyLogRow
	seen := map[string]bool{}
	for _, sec := range fetchNodeAuditSections(nodes) {
		if sec.Err != nil {
			continue
		}
		for _, line := range strings.Split(sec.Body, "\n") {
			var e struct {
				TS      time.Time `json:"ts"`
				Action  string    `json:"action"`
				Summary string    `json:"summary"`
			}
			if json.Unmarshal([]byte(line), &e) != nil || !notifyLogActions[e.Action] {
				continue
			}
			p := strings.Split(e.Summary, notifyLogSep)
			if len(p) < 4 {
				continue
			}
			key := e.TS.Format(time.RFC3339Nano) + e.Summary
			if len(p) >= 5 {
				key = p[len(p)-1]
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			subject := p[3]
			if len(p) > 4 {
				subject = strings.Join(p[3:len(p)-1], notifyLogSep)
			}
			rows = append(rows, notifyLogRow{Time: e.TS.In(time.Local), Reason: p[0], To: p[1], Result: p[2], Subject: subject, Bad: e.Action == "notify.failed"})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Time.After(rows[j].Time) })
	if len(rows) > max {
		rows = rows[:max]
	}
	return rows
}

var webhookClient = &http.Client{
	Timeout:       webhookTimeout,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// sendWebhook posts {"text": ...}, the body Teams, Slack and Mattermost
// incoming webhooks accept. A redirect is not followed and the answer must be 2xx.
func sendWebhook(ctx context.Context, url, subject, body string) error {
	if err := notify.ValidateWebhookURL(url); err != nil {
		return err
	}
	text := subject + "\n\n" + body
	if len(text) > 8000 {
		text = text[:8000] + "…"
	}
	payload, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := webhookClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: %w", redactURL(err))
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook answered HTTP %d", resp.StatusCode)
	}
	return nil
}

// redactURL keeps the secret in a webhook path out of logs and pages.
func redactURL(err error) error {
	var ue interface{ Unwrap() error }
	if errors.As(err, &ue) && ue.Unwrap() != nil {
		return ue.Unwrap()
	}
	return err
}

func sendNotification(store *webauth.Store, d notify.Destination, m notify.Message) error {
	text := m.Text(time.Local)
	switch d.Kind {
	case notify.KindEmail:
		smtpCfg, _ := store.MailSettings()
		if smtpCfg.Host == "" || smtpCfg.From == "" {
			return errors.New("no mail server configured (Security, Mail & reset)")
		}
		return sendMailHTML(smtpCfg, d.Address, m.Subject(), text, renderMailHTML(m, time.Local))
	case notify.KindWebhook:
		ctx, cancel := context.WithTimeout(context.Background(), webhookTimeout)
		defer cancel()
		return sendWebhook(ctx, d.Address, m.Subject(), text)
	}
	return fmt.Errorf("unknown destination kind %q", d.Kind)
}

// runNotifier sends alerts and the periodic summary until ctx ends.
func runNotifier(ctx context.Context, store *webauth.Store, ref *configRef, self func() string) {
	d := notifyDeps{
		settings: store.NotifySettings,
		nodes: func() []statusRow {
			cfg := ref.Load()
			return fetchAllStatus(cfg, nodesIncludingSelf(cfg))
		},
		events: func(n NodeConfig) ([]event, error) { return fetchEvents(n, notifyEventWindow) },
		self:   self,
		send: func(dst notify.Destination, m notify.Message) error {
			return sendNotification(store, dst, m)
		},
		base: func() string {
			u, _ := resetBaseURL(store, ref.Load())
			return u
		},
		backups: func() time.Duration {
			c, _, err := firstReachableConfig(nodesIncludingSelf(ref.Load()))
			if err != nil || !c.BackupEnabled || c.BackupPassword == "" {
				return 0
			}
			if c.BackupIntervalHours <= 0 {
				return 24 * time.Hour
			}
			return time.Duration(c.BackupIntervalHours) * time.Hour
		},
		update: func(version string) (string, string, string) {
			info := updates.status(ref.Load().UpdateCheck, version)
			return info.State, info.Latest, info.URL
		},
		record: func(reason string, dst notify.Destination, subject, result string, err error) {
			recordSend(ref.Load(), reason, dst, subject, result, err)
		},
		now:   time.Now,
		loc:   time.Local,
		state: filepath.Join(filepath.Dir(ref.Load().UsersFile), "notify-state.json"),
	}
	go func() {
		t := time.NewTicker(notifyTick)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				d.tick()
			}
		}
	}()
}

func clusterOf(rows []statusRow) string {
	for _, r := range rows {
		if r.Status.ClusterID != "" {
			return r.Status.ClusterID
		}
	}
	return "cluster"
}

type notifyCell struct {
	Impact int
	ID     string
	On     bool
}

type notifyRow struct {
	Impact notify.Impact
	Cells  []notifyCell
}

type notifyScheduleRow struct {
	ID, Name, Days, Window, Applies string
}

var weekdayNames = []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}

type notifyPageData struct {
	Settings  notify.Settings
	Rows      []notifyRow
	SummaryOn map[string]bool
	Weekdays  []string
	Schedules []notifyScheduleRow
	MailSet   bool
	Log       []notifyLogRow
	NextDue   string
	Error     string
	Notice    string
}

var notifyTmpl = template.Must(template.New("notify").Parse(`<!doctype html>
<title>dnshived-web — notify</title>
` + styleHTML + `
` + navHTML + `
<h1>Notify</h1>
<p class="dim">Who hears about what. Events of equal impact are summed up into one message, and the matrix routes each
impact class to as many destinations as needed. Settings apply at once on every core. The core that sends is the first
one the web UIs can reach, so one message goes out, not one per core.</p>
{{if .Notice}}<p class="ok">{{.Notice}}</p>{{end}}
{{if .Error}}<p class="crit">{{.Error}}</p>{{end}}
{{if not .MailSet}}<p class="warn" title="Email destinations need the mail server of Security, Mail and reset; webhooks work without it.">No mail server is set up, so email destinations cannot send yet. <a href="/config/mail">Set it up</a></p>{{end}}

<h2>Destinations</h2>
<table border="1" cellpadding="4">
<tr><th>Name</th><th>Kind</th><th>Address or URL</th><th></th></tr>
{{range .Settings.Destinations}}<tr>
<td>{{.Name}}</td><td>{{.Kind}}</td>
<td>{{if eq .Kind "webhook"}}<span class="dim" title="The address is a secret and is never shown again.">webhook (address hidden)</span>{{else}}{{.Address}}{{end}}</td>
<td><form method="post" action="/notify" style="display:inline"><input type="hidden" name="id" value="{{.ID}}">
<button name="action" value="test" title="Sends one test message to this destination.">Send test</button>
<button name="action" value="remove" class="btn-cancel" title="Removes the destination and every route to it.">Remove</button></form></td>
</tr>{{else}}<tr><td colspan="4" class="dim">No destination yet.</td></tr>{{end}}
</table>
<form method="post" action="/notify" style="margin-top:.6rem">
<input name="name" placeholder="name, e.g. On-call" size="16">
<select name="kind" class="js-combo"><option value="email">email</option><option value="webhook">webhook (Teams, Slack, ...)</option></select>
<input name="address" placeholder="ops@example.org or https://..." size="40" autocomplete="off">
<button name="action" value="add" class="btn-success">Add destination</button></form>

<form method="post" action="/notify" style="margin:.8rem 0 0">
<label>Cluster name in subjects <input name="cluster_name" value="{{.Settings.ClusterName}}" placeholder="cluster id when empty" size="24" maxlength="64"></label>
<button name="action" value="save_name" class="btn-success">Save name</button>
<span class="info-ico" title="Every message subject starts with [name] and the class (Notify, Summary, Warning, Error). The link in each message is the Public URL under Security, Mail &amp; reset, or the management VIP.">ⓘ</span></form>

<h2>Summary report</h2>
<form method="post" action="/notify">
<table border="1" cellpadding="4">
<tr><td>Send a summary</td><td><label><input type="checkbox" name="enabled" {{if .Settings.Summary.Enabled}}checked{{end}}> enabled</label></td></tr>
<tr><td>Sent daily at</td><td><input type="time" name="time" step="900" value="{{printf "%02d:%02d" .Settings.Summary.Hour .Settings.Summary.Minute}}" required>
 <span class="info-ico" title="Local time of the web server, in steps of 15 minutes. Routine events (backups, commits) are collected here instead of being mailed one by one.">ⓘ</span></td></tr>
<tr><td>Goes to</td><td>{{range .Settings.Destinations}}<label style="margin-right:1rem"><input type="checkbox" name="target" value="{{.ID}}" {{if index $.SummaryOn .ID}}checked{{end}}> {{.Name}}</label>{{else}}<span class="dim">add a destination first</span>{{end}}</td></tr>
<tr><td>Next report</td><td>{{.NextDue}}</td></tr>
</table>
<p><button name="action" value="save_summary" class="btn-success">Save summary</button></p>
</form>

<h2>Quiet schedules</h2>
<p class="dim">Inside a window no alert and no node-loss message goes to the destinations it covers; they are dropped, not sent later. The summary report and test messages are not affected. Times are the local time of the web server.</p>
<table border="1" cellpadding="4">
<tr><th>Name</th><th>Days</th><th>Quiet from - to</th><th>Covers</th><th></th></tr>
{{range .Schedules}}<tr><td>{{.Name}}</td><td>{{.Days}}</td><td>{{.Window}}</td><td>{{.Applies}}</td>
<td><form method="post" action="/notify" style="display:inline"><input type="hidden" name="id" value="{{.ID}}"><button name="action" value="remove_schedule" class="btn-cancel">Remove</button></form></td></tr>{{else}}<tr><td colspan="5" class="dim">No schedule: alerts go out at any time.</td></tr>{{end}}
</table>
<form method="post" action="/notify" style="margin-top:.6rem">
<table border="1" cellpadding="4">
<tr><td>Name</td><td><input name="name" placeholder="e.g. Nights" size="20"></td></tr>
<tr><td>Days</td><td>{{range $i, $d := .Weekdays}}<label style="margin-right:.7rem"><input type="checkbox" name="day" value="{{$i}}"> {{$d}}</label>{{end}} <span class="dim">none ticked = every day</span></td></tr>
<tr><td>Quiet from - to</td><td><input type="time" name="start" step="900" value="22:00" required> - <input type="time" name="end" step="900" value="06:00" required> <span class="dim">a window that ends earlier than it starts runs past midnight</span></td></tr>
<tr><td>Covers</td><td>{{range .Settings.Destinations}}<label style="margin-right:1rem"><input type="checkbox" name="target" value="{{.ID}}"> {{.Name}}</label>{{else}}<span class="dim">add a destination first</span>{{end}} <span class="dim">none ticked = all</span></td></tr>
</table>
<p><button name="action" value="add_schedule" class="btn-success">Add schedule</button></p>
</form>

<h2>Alerts by impact</h2>
<form method="post" action="/notify">
<table border="1" cellpadding="4" class="notify-matrix">
<tr><th>Impact</th>{{range .Settings.Destinations}}<th>{{.Name}}</th>{{end}}</tr>
{{range .Rows}}<tr><td title="{{.Impact.Describe}}"><b>{{.Impact}}</b> <span class="dim">{{.Impact.Describe}}</span></td>
{{range .Cells}}<td style="text-align:center"><label style="display:block;cursor:pointer"><input type="checkbox" name="m_{{.Impact}}_{{.ID}}" {{if .On}}checked{{end}}></label></td>{{end}}</tr>{{end}}
</table>
<p class="dim">A tick sends the events of one impact class as a single message per destination, with a count per kind of event.</p>
<p><button name="action" value="save_matrix" class="btn-success">Save routes</button></p>
</form>

<h2>Message log</h2>
<p class="dim">Every message the notifier sent or held back, newest first: test, alert, recover and summary, with the result and the reason it was not sent. Addresses are not logged.</p>
<div class="table-wrap"><table border="1" cellpadding="4">
<thead><tr><th style="width:11rem">Time</th><th style="width:11rem">Reason</th><th style="width:12rem">To</th><th style="width:16rem">Result</th><th>Subject</th></tr></thead>
<tbody data-pager="10,25,50" data-pager-key="notify-log">{{range .Log}}<tr><td>{{.Time.Format "2006-01-02 15:04:05"}}</td><td>{{.Reason}}</td><td>{{.To}}</td><td class="{{if .Bad}}crit{{end}}" title="{{.Result}}">{{.Result}}</td><td title="{{.Subject}}">{{.Subject}}</td></tr>{{else}}<tr><td colspan="5" class="dim">Nothing sent yet.</td></tr>{{end}}</tbody>
</table></div>
`))

func summaryTime(r *http.Request) (hour, minute int, err error) {
	if v := r.FormValue("time"); v != "" {
		hh, mm, ok := strings.Cut(v, ":")
		hour, err = strconv.Atoi(hh)
		if err == nil && ok {
			minute, err = strconv.Atoi(mm)
		}
		if err != nil || !ok {
			return 0, 0, errors.New("invalid time")
		}
		return hour, minute, nil
	}
	hour, err = strconv.Atoi(r.FormValue("hour"))
	if err != nil {
		return 0, 0, errors.New("invalid hour")
	}
	if v := r.FormValue("minute"); v != "" {
		if minute, err = strconv.Atoi(v); err != nil {
			return 0, 0, errors.New("invalid minute")
		}
	}
	return hour, minute, nil
}

func notifyPage(store *webauth.Store, loc *time.Location, last time.Time) notifyPageData {
	s := store.NotifySettings()
	data := notifyPageData{Settings: s, SummaryOn: map[string]bool{}}
	smtpCfg, _ := store.MailSettings()
	data.MailSet = smtpCfg.Host != "" && smtpCfg.From != ""
	for _, id := range s.Summary.Targets {
		data.SummaryOn[id] = true
	}
	data.Weekdays = weekdayNames
	names := map[string]string{}
	for _, d := range s.Destinations {
		names[d.ID] = d.Name
	}
	for _, sc := range s.Schedules {
		row := notifyScheduleRow{ID: sc.ID, Name: sc.Name, Window: sc.Start + " - " + sc.End, Days: "every day", Applies: "all destinations"}
		if len(sc.Days) > 0 {
			var ds []string
			for _, d := range sc.Days {
				ds = append(ds, weekdayNames[d])
			}
			row.Days = strings.Join(ds, ", ")
		}
		if len(sc.Targets) > 0 {
			var ts []string
			for _, t := range sc.Targets {
				ts = append(ts, names[t])
			}
			row.Applies = strings.Join(ts, ", ")
		}
		data.Schedules = append(data.Schedules, row)
	}
	for _, i := range notify.Impacts {
		row := notifyRow{Impact: i}
		on := map[string]bool{}
		for _, id := range s.Matrix[notify.Key(i)] {
			on[id] = true
		}
		for _, d := range s.Destinations {
			row.Cells = append(row.Cells, notifyCell{Impact: int(i), ID: d.ID, On: on[d.ID]})
		}
		data.Rows = append(data.Rows, row)
	}
	switch {
	case !s.Summary.Enabled || len(s.Summary.Targets) == 0:
		data.NextDue = "none (off, or no destination chosen)"
	case last.IsZero():
		data.NextDue = s.Summary.NextDue(time.Now(), loc).In(loc).Format("2006-01-02 15:04 MST")
	default:
		data.NextDue = s.Summary.NextDue(last, loc).In(loc).Format("2006-01-02 15:04 MST")
	}
	return data
}

var notifyIDMu sync.Mutex

func newDestinationID() string {
	notifyIDMu.Lock()
	defer notifyIDMu.Unlock()
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func handleNotifyGet(store *webauth.Store, ref *configRef, statePath func() string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := notifyPage(store, time.Local, loadNotifyState(statePath()).LastSummary)
		if ref != nil {
			data.Log = fetchNotifyLog(nodesIncludingSelf(ref.Load()), 100)
		}
		renderTemplate(w, notifyTmpl, data, "notify")
	}
}

func handleNotifyPost(store *webauth.Store, repl *authSync, ref *configRef, statePath func() string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, _ := userFromContext(r)
		s := store.NotifySettings()
		action := r.FormValue("action")
		var notice string
		err := func() error {
			switch action {
			case "add":
				d := notify.Destination{
					ID:      newDestinationID(),
					Name:    strings.TrimSpace(r.FormValue("name")),
					Kind:    r.FormValue("kind"),
					Address: strings.TrimSpace(r.FormValue("address")),
				}
				s.Destinations = append(s.Destinations, d)
				notice = "Destination added."
			case "remove":
				s.RemoveDestination(r.FormValue("id"))
				notice = "Destination removed."
			case "save_name":
				s.ClusterName = strings.TrimSpace(r.FormValue("cluster_name"))
				notice = "Cluster name saved."
			case "save_summary":
				s.Summary.Enabled = r.FormValue("enabled") == "on"
				s.Summary.Interval = notify.DefaultInterval
				h, m, err := summaryTime(r)
				if err != nil {
					return err
				}
				s.Summary.Hour, s.Summary.Minute = h, m
				s.Summary.Targets = r.Form["target"]
				notice = "Summary settings saved."
			case "add_schedule":
				sc := notify.Schedule{
					ID:      newDestinationID(),
					Name:    strings.TrimSpace(r.FormValue("name")),
					Start:   r.FormValue("start"),
					End:     r.FormValue("end"),
					Targets: r.Form["target"],
				}
				for _, v := range r.Form["day"] {
					d, err := strconv.Atoi(v)
					if err != nil {
						return errors.New("invalid weekday")
					}
					sc.Days = append(sc.Days, d)
				}
				sort.Ints(sc.Days)
				s.Schedules = append(s.Schedules, sc)
				notice = "Schedule added."
			case "remove_schedule":
				kept := s.Schedules[:0:0]
				for _, sc := range s.Schedules {
					if sc.ID != r.FormValue("id") {
						kept = append(kept, sc)
					}
				}
				s.Schedules = kept
				notice = "Schedule removed."
			case "save_matrix":
				s.Matrix = map[string][]string{}
				for _, i := range notify.Impacts {
					for _, d := range s.Destinations {
						if r.FormValue(fmt.Sprintf("m_%d_%s", int(i), d.ID)) == "on" {
							s.Matrix[notify.Key(i)] = append(s.Matrix[notify.Key(i)], d.ID)
						}
					}
				}
				notice = "Routes saved."
			case "test":
				for _, d := range s.Destinations {
					if d.ID == r.FormValue("id") {
						cfg := ref.Load()
						cluster := s.ClusterLabel(clusterOf(fetchAllStatus(cfg, nodesIncludingSelf(cfg))))
						base, _ := resetBaseURL(store, cfg)
						msg, ok := sampleMessage(r.FormValue("kind"), cluster, base, user.Name, time.Now(), time.Local)
						if !ok {
							return errors.New("unknown test kind")
						}
						subject := msg.Subject()
						err := sendNotification(store, d, msg)
						recordSend(ref.Load(), "test", d, subject, "", err)
						if err != nil {
							return fmt.Errorf("test to %s failed: %w", d.Name, err)
						}
						notice = "Test sent to " + d.Name + "."
						return nil
					}
				}
				return errors.New("unknown destination")
			default:
				return fmt.Errorf("unknown action %q", action)
			}
			if err := s.Validate(); err != nil {
				return err
			}
			return repl.change(func(d *webauth.Store) error {
				saved := s.Clone()
				d.Notify = &saved
				return nil
			})
		}()
		data := notifyPage(store, time.Local, loadNotifyState(statePath()).LastSummary)
		data.Log = fetchNotifyLog(nodesIncludingSelf(ref.Load()), 100)
		if err != nil {
			data.Error = err.Error()
			w.WriteHeader(http.StatusBadRequest)
		} else {
			data.Notice = notice
			if action != "test" {
				auditAll(ref.Load(), user.Name, "notify."+action, "notification settings changed ("+action+")")
			}
		}
		renderTemplate(w, notifyTmpl, data, "notify")
	}
}
