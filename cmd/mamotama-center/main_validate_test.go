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
  "storage":{"path":"./center-data/devices.json"}
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
