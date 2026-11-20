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
	send     func(d notify.Destination, subject, body string) error
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
	d.cluster = clusterOf(rows)
	now := d.now()
	st := loadNotifyState(d.state)
	changed := false
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
		}
		st.LastEvents, changed = last, true
	}

	if s.Summary.Due(st.LastSummary, now, d.loc) {
		d.sendSummary(s, rows, st.LastSummary, now)
		st.LastSummary, changed = now, true
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

func (d notifyDeps) deliver(dests []notify.Destination, subject, body string) {
	for _, dest := range dests {
		if err := d.send(dest, subject, body); err != nil {
			log.Printf("[NOTIFY] %s (%s): %v", dest.Name, dest.Kind, err)
		}
	}
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
		subject, body := notify.Alert(i, d.cluster, list, d.loc)
		d.deliver(dests, subject, body)
	}
}

func (d notifyDeps) sendLoss(s notify.Settings, lost []string, total int, now time.Time) {
	i, isLoss := notify.Lost(len(lost), total)
	var subject, body string
	if isLoss {
		subject = fmt.Sprintf("dnshived %s: %s", strings.ToLower(i.String()), d.cluster)
		body = fmt.Sprintf("%s on %s\n%s\n\nNot reachable: %s\nSince %s\n", i, d.cluster, i.Describe(), strings.Join(lost, ", "), now.In(d.loc).Format("2006-01-02 15:04:05 MST"))
	} else {
		i = notify.Info
		subject = "dnshived: all cores reachable again: " + d.cluster
		body = "Every core answers again on " + d.cluster + " since " + now.In(d.loc).Format("2006-01-02 15:04:05 MST") + ".\n"
	}
	d.deliver(s.Route(i), subject, body)
}

func (d notifyDeps) sendSummary(s notify.Settings, rows []statusRow, from, to time.Time) {
	facts := notify.Facts{Cluster: d.cluster, From: from, To: to}
	for _, r := range rows {
		facts.Nodes = append(facts.Nodes, notify.NodeLine{Name: r.Node.Name, Reachable: r.FetchError == "", State: r.Status.State})
	}
	facts.Events = d.collect(rows, from)
	subject, body := notify.BuildSummary(facts, d.loc)
	d.deliver(s.SummaryTargets(), subject, body)
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

func sendNotification(store *webauth.Store, d notify.Destination, subject, body string) error {
	switch d.Kind {
	case notify.KindEmail:
		smtpCfg, _ := store.MailSettings()
		if smtpCfg.Host == "" || smtpCfg.From == "" {
			return errors.New("no mail server configured (Security, Mail & reset)")
		}
		return sendMail(smtpCfg, d.Address, subject, body+"\n— dnshived")
	case notify.KindWebhook:
		ctx, cancel := context.WithTimeout(context.Background(), webhookTimeout)
		defer cancel()
		return sendWebhook(ctx, d.Address, subject, body)
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
		send: func(dst notify.Destination, subject, body string) error {
			return sendNotification(store, dst, subject, body)
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

type notifyPageData struct {
	Settings  notify.Settings
	Rows      []notifyRow
	Intervals []struct {
		Name, Text string
		Selected   bool
	}
	SummaryOn map[string]bool
	Hours     []int
	MailSet   bool
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

<h2>Summary report</h2>
<form method="post" action="/notify">
<table border="1" cellpadding="4">
<tr><td>Send a summary</td><td><label><input type="checkbox" name="enabled" {{if .Settings.Summary.Enabled}}checked{{end}}> enabled</label></td></tr>
<tr><td>Interval</td><td><select name="interval" class="js-combo">{{range .Intervals}}<option value="{{.Name}}" {{if .Selected}}selected{{end}}>{{.Text}}</option>{{end}}</select>
 at <select name="hour" class="js-combo">{{range .Hours}}<option value="{{.}}" {{if eq . $.Settings.Summary.Hour}}selected{{end}}>{{printf "%02d" .}}:00</option>{{end}}</select>
 <span class="info-ico" title="Daily and weekly reports go out at this local hour of the web server; hourly and 6-hourly reports follow the previous one.">ⓘ</span></td></tr>
<tr><td>Goes to</td><td>{{range .Settings.Destinations}}<label style="margin-right:1rem"><input type="checkbox" name="target" value="{{.ID}}" {{if index $.SummaryOn .ID}}checked{{end}}> {{.Name}}</label>{{else}}<span class="dim">add a destination first</span>{{end}}</td></tr>
<tr><td>Next report</td><td>{{.NextDue}}</td></tr>
</table>
<p><button name="action" value="save_summary" class="btn-success">Save summary</button></p>
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
`))

func notifyPage(store *webauth.Store, loc *time.Location, last time.Time) notifyPageData {
	s := store.NotifySettings()
	data := notifyPageData{Settings: s, SummaryOn: map[string]bool{}}
	smtpCfg, _ := store.MailSettings()
	data.MailSet = smtpCfg.Host != "" && smtpCfg.From != ""
	for _, id := range s.Summary.Targets {
		data.SummaryOn[id] = true
	}
	for _, iv := range notify.Intervals {
		data.Intervals = append(data.Intervals, struct {
			Name, Text string
			Selected   bool
		}{iv.Name, iv.Text, iv.Name == s.Summary.Interval})
	}
	for h := 0; h < 24; h++ {
		data.Hours = append(data.Hours, h)
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
		data.NextDue = "at the first chosen hour after the sender starts"
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

func handleNotifyGet(store *webauth.Store, statePath func() string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, notifyTmpl, notifyPage(store, time.Local, loadNotifyState(statePath()).LastSummary), "notify")
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
			case "save_summary":
				s.Summary.Enabled = r.FormValue("enabled") == "on"
				s.Summary.Interval = r.FormValue("interval")
				h, err := strconv.Atoi(r.FormValue("hour"))
				if err != nil {
					return errors.New("invalid hour")
				}
				s.Summary.Hour = h
				s.Summary.Targets = r.Form["target"]
				notice = "Summary settings saved."
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
						if err := sendNotification(store, d, "dnshived test notification", "This is a test from the dnshived web UI, sent by "+user.Name+"."); err != nil {
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
