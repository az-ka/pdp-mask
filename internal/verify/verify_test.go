package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/az-ka/pdp-mask/internal/apply"
)

const verifyFixtureCSV = `id,email,no_hp,nik,nama_lengkap,note
1,budi@example.test,081234567890,3173050101900001,Budi Santoso,keep me
2,budi@example.test,081234567890,3173050101900001,Budi Santoso,
3,,siti@example.test,,,
`

const verifyPlanYAML = `version: 1
columns:
  - column: "email"
    action: "mask"
    type: "email"
    strategy: "deterministic_email"
  - column: "no_hp"
    action: "mask"
    type: "phone_id"
    strategy: "deterministic_phone_id"
  - column: "nik"
    action: "mask"
    type: "nik"
    strategy: "deterministic_nik"
  - column: "nama_lengkap"
    action: "mask"
    type: "name"
    strategy: "deterministic_name_id"
`

func TestVerifyCleanRoundTrip(t *testing.T) {
	paths := writeVerifyFixture(t, verifyFixtureCSV, verifyPlanYAML)
	safeCSV := filepath.Join(paths.dir, "safe.csv")
	salt := []byte("0123456789abcdef")
	_, err := apply.ApplyCSV(apply.Options{
		InputPath:  paths.input,
		PlanPath:   paths.plan,
		OutputPath: safeCSV,
		Salt:       salt,
	})
	if err != nil {
		t.Fatalf("ApplyCSV returned error: %v", err)
	}

	result, err := Verify(Options{
		ConfigPath: paths.plan,
		InputPath:  paths.input,
		OutputPath: safeCSV,
	})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !result.Passed {
		t.Fatalf("Verify failed unexpectedly: %v", result.Issues)
	}
}

func TestVerifyFailsOnReviewAction(t *testing.T) {
	planYAML := `version: 1
columns:
  - column: "email"
    action: "review"
    type: "email"
    strategy: "deterministic_email"
`
	paths := writeVerifyFixture(t, verifyFixtureCSV, planYAML)
	safeCSV := filepath.Join(paths.dir, "safe.csv")
	if err := os.WriteFile(safeCSV, []byte(verifyFixtureCSV), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(Options{
		ConfigPath: paths.plan,
		InputPath:  paths.input,
		OutputPath: safeCSV,
	})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Passed {
		t.Fatal("Verify passed but plan has action=review")
	}
	mustContainIssue(t, result.Issues, "has unresolved action \"review\"")
}

func TestVerifyFailsOnUnclassifiedHighInInput(t *testing.T) {
	planYAML := `version: 1
columns: []
`
	paths := writeVerifyFixture(t, verifyFixtureCSV, planYAML)
	safeCSV := filepath.Join(paths.dir, "safe.csv")
	if err := os.WriteFile(safeCSV, []byte(verifyFixtureCSV), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(Options{
		ConfigPath: paths.plan,
		InputPath:  paths.input,
		OutputPath: safeCSV,
	})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Passed {
		t.Fatal("Verify passed but input has unclassified high PII")
	}
	mustContainIssue(t, result.Issues, "unclassified column \"email\"")
}

func TestVerifyFailsOnLeakageInOutput(t *testing.T) {
	paths := writeVerifyFixture(t, verifyFixtureCSV, verifyPlanYAML)
	safeCSV := filepath.Join(paths.dir, "safe.csv")
	leakCSV := `id,nama_lengkap,email,no_hp,nik,note
1,Dewi Lestari,budi@example.test,081999999999,3453000000000000,keep me
2,Dewi Lestari,budi@example.test,081999999999,3453000000000000,
3,,siti@example.test,,,
`
	if err := os.WriteFile(safeCSV, []byte(leakCSV), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(Options{
		ConfigPath: paths.plan,
		InputPath:  paths.input,
		OutputPath: safeCSV,
	})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Passed {
		t.Fatal("Verify passed but output leaked email")
	}
	mustContainIssue(t, result.Issues, "column \"email\" still triggers email")
}

func TestVerifyFailsOnArtifactShapeMismatch(t *testing.T) {
	paths := writeVerifyFixture(t, verifyFixtureCSV, verifyPlanYAML)
	safeCSV := filepath.Join(paths.dir, "safe.csv")
	mismatchCSV := `id,nama_lengkap,email
1,Raka Lestari,user_1@example.invalid
`
	if err := os.WriteFile(safeCSV, []byte(mismatchCSV), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(Options{
		ConfigPath: paths.plan,
		InputPath:  paths.input,
		OutputPath: safeCSV,
	})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Passed {
		t.Fatal("Verify passed but output shape mismatched")
	}
	mustContainIssue(t, result.Issues, "header count mismatch")
}

func TestVerifyFailsOnHighKeepOverride(t *testing.T) {
	planYAML := `version: 1
columns:
  - column: "email"
    action: "keep"
    type: "email"
`
	paths := writeVerifyFixture(t, verifyFixtureCSV, planYAML)
	safeCSV := filepath.Join(paths.dir, "safe.csv")
	if err := os.WriteFile(safeCSV, []byte(verifyFixtureCSV), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(Options{
		ConfigPath: paths.plan,
		InputPath:  paths.input,
		OutputPath: safeCSV,
	})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Passed {
		t.Fatal("Verify passed but high-confidence email was kept without mask")
	}
	mustContainIssue(t, result.Issues, "kept without mask")
}

func TestVerifyRejectsNoOpMask(t *testing.T) {
	noOpFixtureCSV := `id,nik,note
1,3173050101900001,keep me
2,3173050101900002,
3,3173050101900003,keep me
`
	noOpPlanYAML := `version: 1
columns:
  - column: "nik"
    action: "mask"
    type: "nik"
    strategy: "deterministic_nik"
`
	paths := writeVerifyFixture(t, noOpFixtureCSV, noOpPlanYAML)
	safeCSV := filepath.Join(paths.dir, "safe.csv")
	if err := os.WriteFile(safeCSV, []byte(noOpFixtureCSV), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(Options{
		ConfigPath: paths.plan,
		InputPath:  paths.input,
		OutputPath: safeCSV,
	})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Passed {
		t.Fatalf("Verify passed but output is byte-identical to input (no-op mask); issues=%v", result.Issues)
	}
	if result.OutputLeakageStatus == "PASS" {
		t.Fatalf("Verify reported OutputLeakageStatus=PASS despite byte-identical masked column; issues=%v", result.Issues)
	}
	mustContainIssue(t, result.Issues, "nik")
}

func TestVerifyRejectsNoOpMaskAtStrategyLevel(t *testing.T) {
	// Input has three NIKs that all look 16-char digit-shaped (so the
	// legacy placeholder-shape check accepts every row). Output keeps
	// the first and third NIK byte-identical to the input and only
	// changes the second. The column as a whole therefore differs
	// (the pre-fix column-level identical check does NOT trip), yet
	// two out of three rows leaked their raw value through the mask.
	// The per-row strategy.WasChanged check is what catches this.
	noOpFixtureCSV := `id,nik,note
1,0000000000000001,keep me
2,0000000000000002,keep me
3,0000000000000003,keep me
`
	noOpOutputCSV := `id,nik,note
1,0000000000000001,keep me
2,9999999999999999,keep me
3,0000000000000003,keep me
`
	noOpPlanYAML := `version: 1
columns:
  - column: "nik"
    action: "mask"
    type: "nik"
    strategy: "deterministic_nik"
`
	paths := writeVerifyFixture(t, noOpFixtureCSV, noOpPlanYAML)
	safeCSV := filepath.Join(paths.dir, "safe.csv")
	if err := os.WriteFile(safeCSV, []byte(noOpOutputCSV), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(Options{
		ConfigPath: paths.plan,
		InputPath:  paths.input,
		OutputPath: safeCSV,
	})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Passed {
		t.Fatalf("Verify passed but masked column leaked raw value at the per-row level; issues=%v", result.Issues)
	}
	if result.OutputLeakageStatus == "PASS" {
		t.Fatalf("Verify reported OutputLeakageStatus=PASS despite per-row strategy.WasChanged finding; issues=%v", result.Issues)
	}
	mustContainIssue(t, result.Issues, "nik")
}

type verifyPaths struct {
	dir   string
	input string
	plan  string
}

func writeVerifyFixture(t *testing.T, csvText, planText string) verifyPaths {
	t.Helper()
	dir := t.TempDir()
	input := filepath.Join(dir, "input.csv")
	planPath := filepath.Join(dir, "mask.yml")
	if err := os.WriteFile(input, []byte(csvText), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if err := os.WriteFile(planPath, []byte(planText), 0o644); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	return verifyPaths{dir: dir, input: input, plan: planPath}
}

func mustContainIssue(t *testing.T, issues []string, expectedSubstring string) {
	t.Helper()
	for _, issue := range issues {
		if strings.Contains(issue, expectedSubstring) {
			return
		}
	}
	t.Fatalf("expected issue containing %q not found in %v", expectedSubstring, issues)
}
