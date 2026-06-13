package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const cliVerifyCSV = `id,email,no_hp,note
1,budi@example.test,081234567890,keep
2,budi@example.test,081234567890,
`

const cliVerifyPlan = `version: 1
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

func TestRunVerifyPasses(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "customers.csv")
	config := filepath.Join(dir, "mask.yml")
	output := filepath.Join(dir, "safe.csv")
	mustWriteFile(t, input, cliVerifyCSV)
	mustWriteFile(t, config, cliVerifyPlan)
	t.Setenv("PDP_MASK_SALT", "0123456789abcdef")
	if err := run([]string{"apply", input, "--config", config, "--out", output}); err != nil {
		t.Fatalf("run apply returned error: %v", err)
	}
	if err := run([]string{"verify", input, "--config", config, "--out", output}); err != nil {
		t.Fatalf("run verify returned error: %v", err)
	}
}

func TestRunVerifyFailsOnReview(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "customers.csv")
	config := filepath.Join(dir, "mask.yml")
	output := filepath.Join(dir, "safe.csv")
	mustWriteFile(t, input, cliVerifyCSV)
	mustWriteFile(t, config, `version: 1
columns:
  - column: "email"
    action: "review"
    type: "email"
    strategy: "deterministic_email"
`)
	if err := os.WriteFile(output, []byte(cliVerifyCSV), 0o644); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"verify", input, "--config", config, "--out", output})
	if err == nil {
		t.Fatal("run verify passed but plan has review action")
	}
	var cliErr CLIError
	if !strings.Contains(err.Error(), "unresolved action") {
		t.Fatalf("error = %v", err)
	}
	if errors.As(err, &cliErr) && cliErr.Code != 3 {
		t.Fatalf("exit code = %d, want 3", cliErr.Code)
	}
}

func TestRunVerifyFailsOnShapeMismatch(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "customers.csv")
	config := filepath.Join(dir, "mask.yml")
	output := filepath.Join(dir, "safe.csv")
	mustWriteFile(t, input, cliVerifyCSV)
	mustWriteFile(t, config, cliVerifyPlan)
	mustWriteFile(t, output, `id,email
1,budi@example.test
`)
	err := run([]string{"verify", input, "--config", config, "--out", output})
	if err == nil {
		t.Fatal("run verify passed but output shape mismatched")
	}
	var cliErr CLIError
	if errors.As(err, &cliErr) && cliErr.Code != 4 {
		t.Fatalf("exit code = %d, want 4", cliErr.Code)
	}
}
