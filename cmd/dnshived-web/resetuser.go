// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"dnshived/internal/webauth"
)

func runResetUser(cfgPath, usersFileFlag, name, role, password, email string) {
	if !webauth.ValidRole(role) {
		log.Fatalf("-role must be one of %s (got %q)", strings.Join(webauth.Roles, ", "), role)
	}

	usersFile := usersFileFlag
	if usersFile == "" {
		cfg, err := loadWebConfig(cfgPath)
		if err != nil {
			log.Fatalf("-users-file not given, and could not read it from %s: %v", cfgPath, err)
		}
		usersFile = cfg.UsersFile
	}

	if password == "" {
		password = promptPassword()
	}
	if password == "" {
		log.Fatalf("empty password refused")
	}

	store, err := webauth.Load(usersFile)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Fatalf("load %s: %v", usersFile, err)
		}
		store = &webauth.Store{}
	}

	_, existed := store.Lookup(name)
	hash, err := webauth.HashPassword(password)
	if err != nil {
		log.Fatalf("%v", err)
	}
	host, _ := os.Hostname()
	err = store.Mutate("console@"+host, func(d *webauth.Store) error {
		for i := range d.Users {
			if d.Users[i].Name == name {
				d.Users[i].PasswordHash = hash
				d.Users[i].Role = role
				d.Users[i].Disabled = false
				d.Users[i].SessionEpoch++
				if email != "" {
					d.Users[i].Email = email
				}
				return nil
			}
		}
		d.Users = append(d.Users, webauth.User{Name: name, PasswordHash: hash, Role: role, Email: email})
		return nil
	})
	if err != nil {
		log.Fatalf("%v", err)
	}
	if err := store.Save(usersFile); err != nil {
		log.Fatalf("%v", err)
	}

	verb := "added"
	if existed {
		verb = "password reset (and account enabled) for"
	}
	fmt.Printf("%s user %q (role=%s) in %s — the running web UI picks it up within seconds and spreads it to the other cores\n", verb, name, role, usersFile)
}

// promptPassword reads a password from the controlling terminal with echo
// disabled, matching a normal passwd(1)-style prompt.
func promptPassword() string {
	fmt.Print("New password: ")
	exec.Command("stty", "-F", "/dev/tty", "-echo").Run()
	reader := bufio.NewReader(os.Stdin)
	pw, _ := reader.ReadString('\n')
	exec.Command("stty", "-F", "/dev/tty", "echo").Run()
	fmt.Println()
	return strings.TrimSpace(pw)
}
