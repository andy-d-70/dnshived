package clientrc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RC is the parsed content of ~/.dnshived/rc.
type RC struct {
	Addr          string
	TLS           bool
	TLSSkipVerify bool
	Token         string
	ProbeAddr     string
	ProbeName     string
}

// Path returns ~/.dnshived/rc for the current user, or "" if the home
// directory can't be resolved.
func Path() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".dnshived", "rc")
}

// Load reads and parses ~/.dnshived/rc.
func Load() (*RC, error) {
	path := Path()
	if path == "" {
		return &RC{}, nil
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return &RC{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf(
			"%s is readable by group/other (mode %04o) — refusing to read it, it can hold a live API token; run: chmod 600 %s",
			path, info.Mode().Perm(), path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	rc := &RC{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "addr":
			rc.Addr = val
		case "tls":
			rc.TLS = val == "true" || val == "1"
		case "tls_skip_verify":
			rc.TLSSkipVerify = val == "true" || val == "1"
		case "token":
			rc.Token = val
		case "probe_addr":
			rc.ProbeAddr = val
		case "probe_name":
			rc.ProbeName = val
		}
	}
	return rc, nil
}
