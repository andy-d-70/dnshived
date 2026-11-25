// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"dnshived/internal/cfgjournal"
	"dnshived/internal/changeset"
)

// With the configuration journal on, the templates (templates, option sets, scope groups) are one shared document in
// the journal, the same on every web instance. The local file stays as a cache and as the store when the journal is
// off.

const templatesDocName = "templates"

var errTemplateConflict = errors.New("someone else changed this template meanwhile; the page shows the current state, enter the change again")

type templateShare struct {
	mu     sync.Mutex
	joined bool
	base   any
	rev    uint64

	active func() bool
	get    func() (uint64, any, error)
	post   func(author string, changes []cfgjournal.Entry) error
}

var templatesShare = &templateShare{}

func (s *TemplateStore) tree() (any, error) {
	s.mu.RLock()
	raw, err := json.Marshal(s)
	s.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	return cfgjournal.DecodeTree(raw)
}

func (s *TemplateStore) replaceFrom(tree any) error {
	raw, err := json.Marshal(tree)
	if err != nil {
		return err
	}
	var n TemplateStore
	if err := json.Unmarshal(raw, &n); err != nil {
		return err
	}
	s.mu.Lock()
	s.Templates, s.OptionSets, s.ScopeGroups = n.Templates, n.OptionSets, n.ScopeGroups
	s.mu.Unlock()
	return nil
}

// refresh follows the shared document. On first contact it contributes the templates only this instance has (a
// template the shared document already holds with other content is left alone and logged, never overwritten). It
// never replaces a change that is made in memory but not saved yet.
func (sh *templateShare) refresh(store *TemplateStore) {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.active == nil || !sh.active() {
		sh.joined = false
		return
	}
	rev, remote, err := sh.get()
	if err != nil {
		return
	}
	if !sh.joined {
		local, err := store.tree()
		if err != nil {
			return
		}
		all, err := cfgjournal.FromChange(templatesDocName, remote, local, 0)
		if err != nil {
			return
		}
		var add []cfgjournal.Entry
		copied := map[string]bool{}
		for _, e := range all {
			item := itemPath(e.Path)
			switch {
			case e.Old == nil && item == e.Path:
				add = append(add, e)
			case !copied[item]:
				copied[item] = true
				if c, ok := localCopy(item, local, remote); ok {
					log.Printf("[TEMPLATES] %s differs from the shared copy; this instance's version is kept as %s", item, c.Path)
					add = append(add, c)
				}
			}
		}
		if len(add) > 0 {
			if err := sh.post("web", add); err != nil {
				log.Printf("[TEMPLATES] contributing local templates: %v", err)
			}
			if rev, remote, err = sh.get(); err != nil {
				return
			}
		}
		if err := store.replaceFrom(remote); err != nil {
			return
		}
		if base, err := store.tree(); err == nil {
			sh.base, sh.rev, sh.joined = base, rev, true
		}
		return
	}
	if rev == sh.rev {
		return
	}
	cur, err := store.tree()
	if err != nil || !reflect.DeepEqual(cur, sh.base) {
		return
	}
	if err := store.replaceFrom(remote); err == nil {
		if base, err := store.tree(); err == nil {
			sh.base, sh.rev = base, rev
		}
	}
}

// save sends what changed in the store since it last matched the shared document. A refused change reloads the store
// from the shared document and returns errTemplateConflict.
func (sh *templateShare) save(store *TemplateStore, author string) error {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if !sh.joined {
		return nil
	}
	cur, err := store.tree()
	if err != nil {
		return err
	}
	changes, err := cfgjournal.FromChange(templatesDocName, sh.base, cur, 0)
	if err != nil || len(changes) == 0 {
		return err
	}
	if perr := sh.post(author, changes); perr != nil {
		if rev, remote, err := sh.get(); err == nil && store.replaceFrom(remote) == nil {
			if base, err := store.tree(); err == nil {
				sh.base, sh.rev = base, rev
			}
		}
		if errors.Is(perr, cfgjournal.ErrConflict) {
			return errTemplateConflict
		}
		return perr
	}
	sh.base = cur
	return nil
}

// useTemplateShare connects the shared templates to the cluster nodes and follows them in the background.
func useTemplateShare(store *TemplateStore, nodes func() []NodeConfig) {
	sh := templatesShare
	sh.active = func() bool { return journalActive(nodes()) }
	sh.get = func() (uint64, any, error) { return fetchSharedDoc(nodes(), templatesDocName) }
	sh.post = func(author string, changes []cfgjournal.Entry) error {
		return postSharedDocChanges(nodes(), templatesDocName, author, changes)
	}
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			sh.refresh(store)
			<-t.C
		}
	}()
}

func fetchSharedDoc(nodes []NodeConfig, name string) (uint64, any, error) {
	var last error
	for _, n := range nodes {
		var ans struct {
			Rev  uint64          `json:"rev"`
			Tree json.RawMessage `json:"tree"`
		}
		status, err := doGet(httpClient, n, "/api/v1/journal/docs/"+name, &ans)
		if err != nil || status != http.StatusOK {
			last = fmt.Errorf("%s: status %d: %v", n.Name, status, err)
			continue
		}
		tree, err := cfgjournal.DecodeTree(ans.Tree)
		if err != nil {
			return 0, nil, err
		}
		return ans.Rev, tree, nil
	}
	return 0, nil, fmt.Errorf("no node answered: %v", last)
}

func postSharedDocChanges(nodes []NodeConfig, name, author string, changes []cfgjournal.Entry) error {
	body, err := json.Marshal(map[string]any{"author": author, "changes": changes})
	if err != nil {
		return err
	}
	var last error
	for _, n := range nodes {
		status, resp, err := postNodeJSON(n, "/api/v1/journal/docs/"+name+"/changes", body)
		if err != nil {
			last = err
			continue
		}
		switch status {
		case http.StatusOK:
			return nil
		case http.StatusConflict:
			return fmt.Errorf("%w: %s", cfgjournal.ErrConflict, bytes.TrimSpace(resp))
		}
		return fmt.Errorf("%s: status %d: %s", n.Name, status, bytes.TrimSpace(resp))
	}
	return fmt.Errorf("no node answered: %v", last)
}

// itemPath is the path of the template, option set or scope group a change lies in ("templates/[cams]/body" ->
// "templates/[cams]").
func itemPath(p string) string {
	segs := strings.SplitN(p, "/", 3)
	if len(segs) >= 2 && strings.HasPrefix(segs[1], "[") {
		return segs[0] + "/" + segs[1]
	}
	return p
}

// localCopy turns this instance's version of a differing shared item into a new item with its own id, so neither
// version is lost when instances that kept templates apart join the shared document.
func localCopy(path string, local, remote any) (cfgjournal.Entry, bool) {
	v, ok := changeset.Get(local, path)
	if !ok {
		return cfgjournal.Entry{}, false
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return cfgjournal.Entry{}, false
	}
	var item map[string]any
	if json.Unmarshal(raw, &item) != nil {
		return cfgjournal.Entry{}, false
	}
	id, _ := item["id"].(string)
	parent := path[:strings.LastIndex(path, "/")]
	for n := 1; n < 1000; n++ {
		cand := fmt.Sprintf("%s-local-%d", id, n)
		path := parent + "/[" + cand + "]"
		if _, taken := changeset.Get(remote, path); taken {
			continue
		}
		item["id"] = cand
		if name, _ := item["name"].(string); name != "" {
			item["name"] = name + " (local copy)"
		}
		raw, err := json.Marshal(item)
		if err != nil {
			return cfgjournal.Entry{}, false
		}
		return cfgjournal.Entry{Doc: templatesDocName, Path: path, New: raw}, true
	}
	return cfgjournal.Entry{}, false
}
