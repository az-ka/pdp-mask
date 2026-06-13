package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cliApplyCSV = `id,email,no_hp,note
1,budi@example.test,081234567890,keep
2,budi@example.test,081234567890,
`

const cliApplyPlan = `version: 1
columns:
  - column: "email"
    action: "mask"
    type: "email"
    strategy: "deterministic_email"
  - column: "no_hp"
    action: "mask"
    type: "phone_id"
    strategy: "deterministic_phone_id"
`

func TestRunApplyWritesMaskedCSV(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "customers.csv")
	config := filepath.Join(dir, "mask.yml")
	output := filepath.Join(dir, "safe.csv")
	mustWriteFile(t, input, cliApplyCSV)
	mustWriteFile(t, config, cliApplyPlan)
	t.Setenv("PDP_MASK_SALT", "0123456789abcdef")
	if err := run([]string{"apply", input, "--config", config, "--out", output}); err != nil {
		t.Fatalf("run apply returned error: %v", err)
	}
	payload := string(mustReadFile(t, output))
	for _, raw := range []string{"budi@example.test", "081234567890"} {
		if strings.Contains(payload, raw) {
			t.Fatalf("masked CSV leaked raw value %q:\n%s", raw, payload)
		}
	}
	if !strings.Contains(payload, "keep") {
		t.Fatalf("untargeted note not preserved:\n%s", payload)
	}
}

func TestRunApplyRequiresSalt(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "customers.csv")
	config := filepath.Join(dir, "mask.yml")
	output := filepath.Join(dir, "safe.csv")
	mustWriteFile(t, input, cliApplyCSV)
	mustWriteFile(t, config, cliApplyPlan)
	err := run([]string{"apply", input, "--config", config, "--out", output})
	if err == nil {
		t.Fatal("run apply returned nil error without salt")
	}
	if !strings.Contains(err.Error(), "salt") {
		t.Fatalf("error = %q, want salt", err.Error())
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("output exists after salt error, stat err=%v", err)
	}
}

func TestRunApplyRejectsExistingOutput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "customers.csv")
	config := filepath.Join(dir, "mask.yml")
	output := filepath.Join(dir, "safe.csv")
	mustWriteFile(t, input, cliApplyCSV)
	mustWriteFile(t, config, cliApplyPlan)
	mustWriteFile(t, output, "existing")
	t.Setenv("PDP_MASK_SALT", "0123456789abcdef")
	err := run([]string{"apply", input, "--config", config, "--out", output})
	if err == nil {
		t.Fatal("run apply returned nil error for existing output")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error = %q, want already exists", err.Error())
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return payload
}
