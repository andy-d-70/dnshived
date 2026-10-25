package clientrc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_MissingFileReturnsZeroValueNoError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	rc, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.Addr != "" || rc.TLS || rc.TLSSkipVerify || rc.Token != "" {
		t.Fatalf("expected zero-value RC, got %+v", rc)
	}
}

func TestLoad_RefusesGroupReadableFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".dnshived")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "rc")
	if err := os.WriteFile(path, []byte("token=abc\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	_, err := Load()
	if err == nil {
		t.Fatal("expected an error for a group-readable rc file, got nil")
	}
}

func TestLoad_ParsesKnownKeys(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".dnshived")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "# comment\naddr=10.0.0.1:9443\ntls=true\ntls_skip_verify=1\ntoken=deadbeef\nprobe_addr=10.0.0.2:9444\nprobe_name=probe1\ntls_cert=/home/u/cluster.pem\n\nunknown_key=ignored\n"
	if err := os.WriteFile(filepath.Join(dir, "rc"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	rc, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.Addr != "10.0.0.1:9443" || !rc.TLS || !rc.TLSSkipVerify || rc.Token != "deadbeef" ||
		rc.ProbeAddr != "10.0.0.2:9444" || rc.ProbeName != "probe1" || rc.TLSCert != "/home/u/cluster.pem" {
		t.Fatalf("unexpected parse result: %+v", rc)
	}
}
