package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/az-ka/pdp-mask/internal/scan"
)

func TestRunPlanWritesMaskYAML(t *testing.T) {
	dir := t.TempDir()
	scanPath := writeScanReport(t, dir)
	outPath := filepath.Join(dir, "mask.yml")
	if err := run([]string{"plan", scanPath, "--out", outPath}); err != nil {
		t.Fatalf("run plan returned error: %v", err)
	}
	payload, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read mask.yml: %v", err)
	}
	yaml := string(payload)
	for _, want := range []string{
		"version: 1",
		"action: \"mask\"",
		"action: \"review\"",
		"strategy: \"deterministic_email\"",
		"strategy: \"deterministic_name_id\"",
		"findings: 7",
	} {
		if !strings.Contains(yaml, want) {
			t.Fatalf("mask.yml missing %q:\n%s", want, yaml)
		}
	}
	for _, raw := range []string{"siti.aminah@example.test", "0812-3456-7890", "3173054401010001", "Siti Aminah"} {
		if strings.Contains(yaml, raw) {
			t.Fatalf("mask.yml leaked raw value %q:\n%s", raw, yaml)
		}
	}
}

func TestRunPlanRejectsExistingOutput(t *testing.T) {
	dir := t.TempDir()
	scanPath := writeScanReport(t, dir)
	outPath := filepath.Join(dir, "mask.yml")
	if err := os.WriteFile(outPath, []byte("existing"), 0o644); err != nil {
		t.Fatalf("write existing output: %v", err)
	}
	err := run([]string{"plan", scanPath, "--out", outPath})
	if err == nil {
		t.Fatal("run plan returned nil error for existing output")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error = %q, want already exists", err.Error())
	}
}

func TestRunPlanRejectsInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "scan.json")
	outPath := filepath.Join(dir, "mask.yml")
	if err := os.WriteFile(scanPath, []byte("{"), 0o644); err != nil {
		t.Fatalf("write invalid json: %v", err)
	}
	err := run([]string{"plan", scanPath, "--out", outPath})
	if err == nil {
		t.Fatal("run plan returned nil error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parse scan JSON") {
		t.Fatalf("error = %q, want parse scan JSON", err.Error())
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Fatalf("output exists after invalid JSON, stat err=%v", err)
	}
}

func writeScanReport(t *testing.T, dir string) string {
	t.Helper()
	report, err := scan.ScanCSV("../../testdata/customers_pii.csv", scan.CSVOptions{SampleRows: 500})
	if err != nil {
		t.Fatalf("ScanCSV returned error: %v", err)
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	path := filepath.Join(dir, "scan.json")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatalf("write scan report: %v", err)
	}
	return path
}
