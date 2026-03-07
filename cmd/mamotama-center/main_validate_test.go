package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateConfigFlag(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "center.config.json")
	cfg := `{
  "auth":{"enrollment_license_keys":["test-license-key-1234"]},
  "storage":{"path":"./center-data/devices.json","sqlite_path":"./center-data/center.db"}
}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := exec.Command("go", "run", ".", "-config", cfgPath, "-validate-config")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("validate config command failed: %v\noutput=%s", err, out)
	}
	if !strings.Contains(string(out), "config is valid: "+cfgPath) {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestDBInitAndCheckFlags(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "center.config.json")
	dbPath := filepath.Join(t.TempDir(), "center-data", "center.db")
	cfg := `{
  "auth":{"enrollment_license_keys":["test-license-key-1234"]},
  "storage":{"path":"./center-data/devices.json","sqlite_path":"` + dbPath + `"}
}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmdInit := exec.Command("go", "run", ".", "-config", cfgPath, "-db-init")
	outInit, err := cmdInit.CombinedOutput()
	if err != nil {
		t.Fatalf("db init command failed: %v\noutput=%s", err, outInit)
	}
	if !strings.Contains(string(outInit), "sqlite initialized: "+dbPath) {
		t.Fatalf("unexpected db-init output: %s", outInit)
	}

	cmdCheck := exec.Command("go", "run", ".", "-config", cfgPath, "-db-check")
	outCheck, err := cmdCheck.CombinedOutput()
	if err != nil {
		t.Fatalf("db check command failed: %v\noutput=%s", err, outCheck)
	}
	if !strings.Contains(string(outCheck), "sqlite check ok: "+dbPath) {
		t.Fatalf("unexpected db-check output: %s", outCheck)
	}
}

func TestValidateConfigFlagInvalidConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "center.config-invalid.json")
	cfg := `{"unknown_field":true}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}

	cmd := exec.Command("go", "run", ".", "-config", cfgPath, "-validate-config")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected command failure for invalid config, output=%s", out)
	}
	if !strings.Contains(string(out), "load config:") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestValidateConfigFlagInvalidStorageBackend(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "center.config-invalid-backend.json")
	cfg := `{
  "auth":{"enrollment_license_keys":["test-license-key-1234"]},
  "storage":{"backend":"postgres","path":"./center-data/devices.json","sqlite_path":"./center-data/center.db"}
}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write invalid backend config: %v", err)
	}

	cmd := exec.Command("go", "run", ".", "-config", cfgPath, "-validate-config")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected command failure for invalid backend, output=%s", out)
	}
	if !strings.Contains(string(out), "storage.backend must be one of: file, sqlite") {
		t.Fatalf("unexpected output: %s", out)
	}
}
