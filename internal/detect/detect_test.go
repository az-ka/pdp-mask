package detect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRulesAndDetect(t *testing.T) {
	tempDir := t.TempDir()
	rulesFile := filepath.Join(tempDir, "custom_rules.yml")
	ruleYAML := `version: 1
pack_name: custom
rules:
  - name: "custom_id"
    category: "custom_pii"
    column_patterns: ["my_secret_col"]
    value_pattern: "^SEC-[0-9]{4}$"
    value_weight: 0.90
    column_weight: 0.70
`
	if err := os.WriteFile(rulesFile, []byte(ruleYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	originalRules := append([]Rule(nil), ActiveRules...)
	defer func() {
		ActiveRules = originalRules
	}()

	if err := LoadRules(rulesFile); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	found := false
	for _, rule := range ActiveRules {
		if rule.Name == "custom_id" {
			found = true
			if rule.Category != "custom_pii" || rule.ColumnWeight != 0.70 {
				t.Fatalf("unexpected custom rule values: %+v", rule)
			}
			break
		}
	}
	if !found {
		t.Fatal("custom rule not found in ActiveRules")
	}

	signals := columnSignals("my_secret_col")
	sig, ok := signals["custom_pii"]
	if !ok {
		t.Fatal("missing custom_pii column signal")
	}
	if sig.score != 0.70 {
		t.Fatalf("column score = %f, want 0.70", sig.score)
	}

	matches := matchValue("SEC-1234")
	if len(matches) != 1 || matches[0].category != "custom_pii" {
		t.Fatalf("unexpected value matches: %+v", matches)
	}
}
