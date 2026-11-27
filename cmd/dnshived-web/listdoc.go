// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"time"

	"dnshived/internal/repldoc"
	"dnshived/internal/secretindex"
)

// A listDoc replicates one list of web.json (probe hosts, core nodes) between the web instances: the list carries a
// revision stamp, the newer one is taken, an instance that missed a change catches up on the next comparison. Once
// every core offers the secret index, a change is ordered by the cores per entry (first wins) and a received list is
// taken entry by entry, only where it holds what the index names.

type listSpec struct {
	tag     string
	path    string
	wireKey string
	part    string
	noun    string
	key     func(NodeConfig) string
	get     func(*WebConfig) []NodeConfig
	set     func(*WebConfig, []NodeConfig)
	stamp   func(*WebConfig) (*int64, *string, *string, *string)
	check   func([]NodeConfig) error
}

type listDoc struct {
	spec    listSpec
	ref     *configRef
	cfgPath string
	self    func() string

	// writeMu serialises this document's own writers (adopt, drift, first revision, ordered changes).
	writeMu sync.Mutex

	strict *usersStrict
	push   func()
	sync   func()
}

func stampNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// listHash is the content hash of a list, independent of its order.
func listHash(spec listSpec, list []NodeConfig) string {
	sorted := append([]NodeConfig(nil), list...)
	sort.Slice(sorted, func(i, j int) bool { return spec.key(sorted[i]) < spec.key(sorted[j]) })
	data, err := json.Marshal(sorted)
	if err != nil {
		return ""
	}
	return repldoc.BodyHash(data)
}

func (d *listDoc) stampOf(cfg *WebConfig) repldoc.Meta {
	v, at, origin, _ := d.spec.stamp(cfg)
	return repldoc.Meta{Version: *v, UpdatedAt: *at, Origin: *origin}
}

func (d *listDoc) setStamp(cfg *WebConfig, m repldoc.Meta) {
	v, at, origin, hash := d.spec.stamp(cfg)
	*v, *at, *origin = m.Version, m.UpdatedAt, m.Origin
	*hash = listHash(d.spec, d.spec.get(cfg))
}

func (d *listDoc) Meta() repldoc.Meta {
	cfg := d.ref.Load()
	m := d.stampOf(cfg)
	m.Hash = listHash(d.spec, d.spec.get(cfg))
	return m
}

func (d *listDoc) Marshal() ([]byte, error) {
	cfg := d.ref.Load()
	list := d.spec.get(cfg)
	if list == nil {
		list = []NodeConfig{}
	}
	m := d.Meta()
	return json.Marshal(map[string]any{"version": m.Version, "updated_at": m.UpdatedAt, "origin": m.Origin, "hash": m.Hash, d.spec.wireKey: list})
}

// publish writes next to web.json and makes it the live value, unless a handler changed the live value meanwhile
// (then it returns an error and the next comparison tries again).
func (d *listDoc) publish(old, next *WebConfig) error {
	if err := saveWebConfig(d.cfgPath, next); err != nil {
		return fmt.Errorf("save web.json: %w", err)
	}
	if !d.ref.CompareAndSwap(old, next) {
		return fmt.Errorf("web.json changed while the %s list was being updated; retrying on the next comparison", d.spec.noun)
	}
	return nil
}

// Adopt installs the list in raw when it is newer than this instance's. A never-replicated local list is merged by
// key, so no local entry is lost, and the merged result gets a new revision so it spreads.
func (d *listDoc) Adopt(raw []byte, from string) (adopted, spread bool, err error) {
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		return false, false, invalidDocError{"parse " + d.spec.noun + " document: " + err.Error()}
	}
	var meta repldoc.Meta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return false, false, invalidDocError{"parse " + d.spec.noun + " document: " + err.Error()}
	}
	rawList, ok := wire[d.spec.wireKey]
	if !ok || string(rawList) == "null" {
		return false, false, invalidDocError{d.spec.noun + " document has no " + d.spec.wireKey + " list"}
	}
	var list []NodeConfig
	if err := json.Unmarshal(rawList, &list); err != nil {
		return false, false, invalidDocError{"parse " + d.spec.noun + " document: " + err.Error()}
	}
	if err := repldoc.ValidMeta(meta); err != nil {
		return false, false, invalidDocError{err.Error()}
	}
	if err := d.spec.check(list); err != nil {
		return false, false, invalidDocError{err.Error()}
	}
	if d.strictOn() {
		return d.strictAdopt(meta, list, from)
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	cfg := d.ref.Load()
	local := d.stampOf(cfg)
	if !repldoc.Newer(meta, local) {
		return false, false, nil
	}
	merged := append([]NodeConfig(nil), list...)
	next := *cfg
	var kept []string
	if local.Version == 0 {
		have := make(map[string]bool, len(merged))
		for _, h := range merged {
			have[d.spec.key(h)] = true
		}
		for _, h := range d.spec.get(cfg) {
			if !have[d.spec.key(h)] {
				merged = append(merged, h)
				kept = append(kept, d.spec.key(h))
			}
		}
	}
	d.spec.set(&next, merged)
	d.setStamp(&next, meta)
	if len(kept) > 0 {
		d.setStamp(&next, repldoc.Meta{Version: meta.Version + 1, UpdatedAt: stampNow(), Origin: d.self()})
	}
	if err := d.publish(cfg, &next); err != nil {
		return false, false, err
	}
	log.Printf("[REPL] %s list %d → %d from %s (%d entries)", d.spec.noun, local.Version, d.stampOf(&next).Version, from, len(merged))
	if len(kept) > 0 {
		log.Printf("[REPL] kept this instance's own %s entries %v while joining the replicated list", d.spec.noun, kept)
		auditAll(d.ref.Load(), "system", d.spec.tag+".merge", fmt.Sprintf("merged %s %v from %s into the replicated list", d.spec.noun, kept, d.self()))
	}
	return true, len(kept) > 0, nil
}

// StartFirst begins revision 1 of a never-replicated list.
func (d *listDoc) StartFirst(self string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	cfg := d.ref.Load()
	if d.stampOf(cfg).Version != 0 {
		return nil
	}
	next := *cfg
	d.setStamp(&next, repldoc.Meta{Version: 1, UpdatedAt: stampNow(), Origin: self})
	return d.publish(cfg, &next)
}

// Drift stamps a new revision when the list was changed by a handler since the last stamp. A never-replicated
// list is not stamped here.
func (d *listDoc) Drift(self string) (bool, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	cfg := d.ref.Load()
	v, _, _, hash := d.spec.stamp(cfg)
	if *v == 0 {
		return false, nil
	}
	if listHash(d.spec, d.spec.get(cfg)) == *hash {
		return false, nil
	}
	next := *cfg
	d.setStamp(&next, repldoc.Meta{Version: *v + 1, UpdatedAt: stampNow(), Origin: self})
	if err := d.publish(cfg, &next); err != nil {
		return false, err
	}
	return true, nil
}

func newListSyncer(ref *configRef, doc *listDoc, self func() string) *repldoc.Syncer {
	return &repldoc.Syncer{
		Name:       "REPL:" + doc.spec.tag,
		Path:       doc.spec.path,
		Doc:        doc,
		Self:       self,
		Peers:      func() []repldoc.Peer { return replPeers(ref) },
		Do:         replDo(ref),
		DecodeMeta: decodeMeta,
		OnConflict: replConflict(ref, doc.spec.tag),
		AfterPass:  doc.settle,
		Logf:       log.Printf,
	}
}

func runListSync(ctx context.Context, s *repldoc.Syncer, delay time.Duration) {
	s.Run(ctx, delay, authSyncInterval)
}

func (d *listDoc) handlers(push func()) replHandlers {
	return replHandlers{ref: d.ref, doc: d, push: push}
}

func (d *listDoc) items(list []NodeConfig) (map[string][]byte, error) {
	out := make(map[string][]byte, len(list))
	for _, h := range list {
		raw, err := json.Marshal(h)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", d.spec.noun, d.spec.key(h), err)
		}
		out[d.spec.key(h)] = raw
	}
	return out, nil
}

// fromItems builds the list from items, in the order of order, then new entries by key.
func (d *listDoc) fromItems(items map[string][]byte, order []NodeConfig) ([]NodeConfig, error) {
	var keys []string
	for _, h := range order {
		keys = append(keys, d.spec.key(h))
	}
	var out []NodeConfig
	for _, k := range ordered(keys, items) {
		var h NodeConfig
		if err := json.Unmarshal(items[k], &h); err != nil || d.spec.key(h) != k {
			return nil, fmt.Errorf("%s item %q does not hold that entry", d.spec.noun, k)
		}
		out = append(out, h)
	}
	return out, nil
}

func ordered(order []string, have map[string][]byte) []string {
	seen := map[string]bool{}
	var out, rest []string
	for _, k := range order {
		if _, ok := have[k]; ok && !seen[k] {
			out = append(out, k)
			seen[k] = true
		}
	}
	for k := range have {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

func (d *listDoc) strictOn() bool { return d != nil && d.strict != nil && d.strict.active() }

func (d *listDoc) pendingPath() string { return d.cfgPath + "." + d.spec.tag + ".pending" }

// saveChange orders the change of this list from old to next (when strict mode is on and it changed); the caller
// saves next afterwards. ordered reports that a new revision was stamped into next.
func (d *listDoc) saveChange(old, next *WebConfig) (ordered bool, err error) {
	if !d.strictOn() {
		return false, nil
	}
	before, err := d.items(d.spec.get(old))
	if err != nil {
		return false, err
	}
	after, err := d.items(d.spec.get(next))
	if err != nil {
		return false, err
	}
	if len(secretindex.Changed(before, after)) == 0 {
		return false, nil
	}
	applied, err := orderChange(d.strict, d.pendingPath(), d.spec.part, d.self(), before, after)
	var ce *secretindex.ConflictError
	if errors.As(err, &ce) {
		msg := fmt.Sprintf("refused a change of %s %s on %s: it was changed by %s at %s", d.spec.noun, ce.Key, d.self(), ce.Entry.By, ce.Entry.At)
		log.Printf("[REPL] %s", msg)
		go auditAll(d.ref.Load(), "system", d.spec.tag+".rejected", msg)
		return false, fmt.Errorf("not saved: %s %s was changed on %s at %s since this page was loaded; reload and enter the change again if it is still needed", d.spec.noun, ce.Key, ce.Entry.By, ce.Entry.At)
	}
	if !applied {
		return false, err
	}
	v, _, _, _ := d.spec.stamp(next)
	d.setStamp(next, repldoc.Meta{Version: *v + 1, UpdatedAt: stampNow(), Origin: d.self()})
	return true, nil
}

// pullFromSiblings answers a sibling's direct change in strict mode: the list is fetched through the ordered
// comparison instead of being applied as sent.
func (d *listDoc) pullFromSiblings() bool {
	if !d.strictOn() {
		return false
	}
	if d.sync != nil {
		go d.sync()
	}
	return true
}

func (d *listDoc) strictAdopt(meta repldoc.Meta, list []NodeConfig, from string) (adopted, spread bool, err error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	cfg := d.ref.Load()
	if !repldoc.Newer(meta, d.stampOf(cfg)) {
		return false, false, nil
	}
	tree, err := d.strict.getIndex()
	if err != nil {
		return false, false, fmt.Errorf("%s list from %s not taken yet: the cores' change order cannot be read: %w", d.spec.noun, from, err)
	}
	idx, err := secretindex.Parse(tree, d.spec.part)
	if err != nil {
		return false, false, err
	}
	local, err := d.items(d.spec.get(cfg))
	if err != nil {
		return false, false, err
	}
	incoming, err := d.items(list)
	if err != nil {
		return false, false, invalidDocError{err.Error()}
	}
	out, refused, missing := secretindex.Reconcile(idx, local, incoming, nil)
	merged, err := d.fromItems(out, list)
	if err != nil {
		return false, false, invalidDocError{err.Error()}
	}
	next := *cfg
	d.spec.set(&next, merged)
	d.setStamp(&next, meta)
	if len(refused) > 0 {
		d.setStamp(&next, repldoc.Meta{Version: meta.Version + 1, UpdatedAt: stampNow(), Origin: d.self()})
		log.Printf("[REPL] %s from %s not taken (the cores ordered another version): %v", d.spec.noun, from, refused)
	}
	for _, k := range missing {
		log.Printf("[REPL] the cores name a version of %s %s that no instance holds; following %s's copy", d.spec.noun, k, from)
	}
	if err := d.publish(cfg, &next); err != nil {
		return false, false, err
	}
	return true, len(refused) > 0, nil
}

// settle applies, resends or drops a pending change of this list; it runs after every comparison.
func (d *listDoc) settle() {
	if !d.strictOn() {
		return
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	p, outcome, err := settlePendingChange(d.strict, d.pendingPath())
	if err != nil {
		log.Printf("[REPL] %s: %v", d.spec.noun, err)
	}
	switch outcome {
	case settleApply:
		cfg := d.ref.Load()
		cur, err := d.items(d.spec.get(cfg))
		if err != nil {
			return
		}
		p.applyItems(cur)
		list, err := d.fromItems(cur, d.spec.get(cfg))
		if err != nil {
			log.Printf("[REPL] confirmed %s change not applied: %v", d.spec.noun, err)
			return
		}
		next := *cfg
		d.spec.set(&next, list)
		v, _, _, _ := d.spec.stamp(cfg)
		d.setStamp(&next, repldoc.Meta{Version: *v + 1, UpdatedAt: stampNow(), Origin: d.self()})
		if err := d.publish(cfg, &next); err != nil {
			log.Printf("[REPL] confirmed %s change: %v", d.spec.noun, err)
			return
		}
		_ = os.Remove(d.pendingPath())
		log.Printf("[REPL] applied a %s change the cores confirmed after it was sent", d.spec.noun)
		if d.push != nil {
			go d.push()
		}
	case settleDropped:
		msg := fmt.Sprintf("dropped a %s change on %s that the cores refused: someone else changed it first", d.spec.noun, d.self())
		log.Printf("[REPL] %s", msg)
		go auditAll(d.ref.Load(), "system", d.spec.tag+".rejected", msg)
	}
}

// Replicated lists of this instance; nil in tests that do not set them.
var (
	probeHostsShared *listDoc
	nodesShared      *listDoc
)

// saveWebChange saves next (a change of old) to web.json and makes it live. In strict mode a replicated list that
// changed is ordered by the cores first; a refusal leaves everything as it was. One save changes at most one
// replicated list, since two orderings cannot be made atomic together.
func saveWebChange(cfgPath string, ref *configRef, old, next *WebConfig) error {
	var docs []*listDoc
	for _, d := range []*listDoc{probeHostsShared, nodesShared} {
		if d != nil {
			docs = append(docs, d)
		}
	}
	changed := 0
	for _, d := range docs {
		if listHash(d.spec, d.spec.get(old)) != listHash(d.spec, d.spec.get(next)) {
			changed++
		}
	}
	if changed > 1 {
		return errors.New("not saved: one change may touch either the probe hosts or the nodes, not both")
	}
	for _, d := range docs {
		d.writeMu.Lock()
		defer d.writeMu.Unlock()
	}
	var done []*listDoc
	for _, d := range docs {
		ordered, err := d.saveChange(old, next)
		if err != nil {
			return err
		}
		if ordered {
			done = append(done, d)
		}
	}
	if err := saveWebConfig(cfgPath, next); err != nil {
		return err
	}
	ref.Store(next)
	for _, d := range done {
		_ = os.Remove(d.pendingPath())
		if d.push != nil {
			go d.push()
		}
	}
	return nil
}
