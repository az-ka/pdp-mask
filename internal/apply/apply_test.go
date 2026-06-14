package apply

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/az-ka/pdp-mask/internal/plan"
	"github.com/az-ka/pdp-mask/internal/strategy"
)

const applyFixture = `id,nama_lengkap,email,no_hp,nik,note
1,Budi Santoso,budi@example.test,081234567890,3173050101900001,keep me
2,Budi Santoso,budi@example.test,081234567890,3173050101900001,
3,,siti@example.test,,,
`

const applyPlan = `version: 1
columns:
  - column: "nama_lengkap"
    action: "mask"
    type: "name"
    strategy: "deterministic_name_id"
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
`

func TestApplyCSVDeterministicAndConsistent(t *testing.T) {
	paths := writeApplyFixture(t, applyPlan)
	first := filepath.Join(paths.dir, "safe-1.csv")
	second := filepath.Join(paths.dir, "safe-2.csv")
	salt := []byte("0123456789abcdef")
	result, err := ApplyCSV(Options{InputPath: paths.input, PlanPath: paths.plan, OutputPath: first, Salt: salt})
	if err != nil {
		t.Fatalf("ApplyCSV returned error: %v", err)
	}
	if result.Rows != 3 || result.MaskedColumns != 4 || result.MaskedValues != 9 {
		t.Fatalf("result = %+v, want rows=3 masked columns=4 values=9", result)
	}
	if _, err := ApplyCSV(Options{InputPath: paths.input, PlanPath: paths.plan, OutputPath: second, Salt: salt}); err != nil {
		t.Fatalf("second ApplyCSV returned error: %v", err)
	}
	firstPayload := mustRead(t, first)
	secondPayload := mustRead(t, second)
	if !bytes.Equal(firstPayload, secondPayload) {
		t.Fatalf("same salt output differed\nfirst:\n%s\nsecond:\n%s", firstPayload, secondPayload)
	}

	records := readCSV(t, first)
	if got := strings.Join(records[0], ","); got != "id,nama_lengkap,email,no_hp,nik,note" {
		t.Fatalf("header = %q", got)
	}
	if records[1][0] != "1" || records[1][5] != "keep me" {
		t.Fatalf("untargeted values not preserved: %+v", records[1])
	}
	if records[1][1] != records[2][1] || records[1][2] != records[2][2] || records[1][3] != records[2][3] || records[1][4] != records[2][4] {
		t.Fatalf("duplicate PII did not map consistently: row1=%+v row2=%+v", records[1], records[2])
	}
	if records[3][1] != "" || records[3][3] != "" || records[3][4] != "" {
		t.Fatalf("empty targeted values changed: %+v", records[3])
	}
	assertNoRawPII(t, string(firstPayload))
}

func TestApplyCSVDifferentSaltChangesMaskedValues(t *testing.T) {
	paths := writeApplyFixture(t, applyPlan)
	first := filepath.Join(paths.dir, "safe-1.csv")
	second := filepath.Join(paths.dir, "safe-2.csv")
	if _, err := ApplyCSV(Options{InputPath: paths.input, PlanPath: paths.plan, OutputPath: first, Salt: []byte("0123456789abcdef")}); err != nil {
		t.Fatalf("first ApplyCSV returned error: %v", err)
	}
	if _, err := ApplyCSV(Options{InputPath: paths.input, PlanPath: paths.plan, OutputPath: second, Salt: []byte("abcdef0123456789")}); err != nil {
		t.Fatalf("second ApplyCSV returned error: %v", err)
	}
	if bytes.Equal(mustRead(t, first), mustRead(t, second)) {
		t.Fatal("different salts produced identical output")
	}
}

func TestApplyCSVBlocksReviewActions(t *testing.T) {
	paths := writeApplyFixture(t, `version: 1
columns:
  - column: "email"
    action: "review"
    type: "email"
    strategy: "deterministic_email"
`)
	_, err := ApplyCSV(Options{InputPath: paths.input, PlanPath: paths.plan, OutputPath: filepath.Join(paths.dir, "safe.csv"), Salt: []byte("0123456789abcdef")})
	if err == nil {
		t.Fatal("ApplyCSV returned nil error for review action")
	}
	if !strings.Contains(err.Error(), "requires review") {
		t.Fatalf("error = %q, want requires review", err.Error())
	}
}
func TestRulesForHeadersRejectsTraversal(t *testing.T) {
	headers := []string{"id", "nama_lengkap", "email"}
	doc := &plan.Document{
		Version: 1,
		Columns: []plan.ColumnPlan{
			{
				Input:    "../data/customers.csv",
				Column:   "nama_lengkap",
				Action:   "mask",
				Type:     "name",
				Strategy: "deterministic_name_id",
			},
		},
	}
	rules, err := rulesForHeaders(doc, "uploads/customers.csv", headers)
	if err == nil {
		t.Fatalf("rulesForHeaders accepted traversal input; rules = %+v", rules)
	}
	if !strings.Contains(err.Error(), "../data/customers.csv") {
		t.Fatalf("error = %q, want it to mention the traversal path", err.Error())
	}
}

func TestApplyCSVRequiresSalt(t *testing.T) {
	paths := writeApplyFixture(t, applyPlan)
	_, err := ApplyCSV(Options{InputPath: paths.input, PlanPath: paths.plan, OutputPath: filepath.Join(paths.dir, "safe.csv"), Salt: []byte("short")})
	if err == nil {
		t.Fatal("ApplyCSV returned nil error for short salt")
	}
	if !strings.Contains(err.Error(), "salt") {
		t.Fatalf("error = %q, want salt", err.Error())
	}
}

type applyPaths struct {
	dir   string
	input string
	plan  string
}

func writeApplyFixture(t *testing.T, planText string) applyPaths {
	t.Helper()
	dir := t.TempDir()
	input := filepath.Join(dir, "customers.csv")
	planPath := filepath.Join(dir, "mask.yml")
	if err := os.WriteFile(input, []byte(applyFixture), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if err := os.WriteFile(planPath, []byte(planText), 0o644); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	return applyPaths{dir: dir, input: input, plan: planPath}
}

func readCSV(t *testing.T, path string) [][]string {
	t.Helper()
	reader := csv.NewReader(strings.NewReader(string(mustRead(t, path))))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return records
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return payload
}

func assertNoRawPII(t *testing.T, text string) {
	t.Helper()
	for _, raw := range []string{"Budi Santoso", "budi@example.test", "081234567890", "3173050101900001", "siti@example.test"} {
		if strings.Contains(text, raw) {
			t.Fatalf("output leaked raw value %q:\n%s", raw, text)
		}
	}
}

// The tests below pin the HMAC keying contract that maskValue now relies
// on. apply.go no longer owns digestHex; it calls strategy.Digest. If a
// future refactor ever drops the strategy name or the column from the
// HMAC key, these tests fail loudly instead of silently changing masked
// output for every existing plan.

func TestHMACKeyingIsNameAware(t *testing.T) {
	salt := []byte("0123456789abcdef")
	email := strategy.Digest(salt, "col", "deterministic_email", "value")
	nik := strategy.Digest(salt, "col", "deterministic_nik", "value")
	if email == nik {
		t.Fatalf("strategy name must change digest, got %q for both", email)
	}
}

func TestHMACKeyingIncludesColumn(t *testing.T) {
	salt := []byte("0123456789abcdef")
	a := strategy.Digest(salt, "a", "deterministic_email", "value")
	b := strategy.Digest(salt, "b", "deterministic_email", "value")
	if a == b {
		t.Fatalf("column must change digest, got %q for both", a)
	}
}

func TestHMACIsDeterministic(t *testing.T) {
	salt := []byte("0123456789abcdef")
	first := strategy.Digest(salt, "col", "deterministic_email", "value")
	for i := 0; i < 100; i++ {
		got := strategy.Digest(salt, "col", "deterministic_email", "value")
		if got != first {
			t.Fatalf("iteration %d: digest %q != %q", i, got, first)
		}
	}
}

// TestApplyRejectsOversizedInput exercises the MaxInputSize guard. The cap
// is a package-level var so we shrink it for the test (the production value
// is 1 GiB) and assert that a 100-byte input is rejected when the cap is 16.
func TestApplyRejectsOversizedInput(t *testing.T) {
	paths := writeApplyFixture(t, applyPlan)
	output := filepath.Join(paths.dir, "safe.csv")

	orig := MaxInputSize
	MaxInputSize = 16
	defer func() { MaxInputSize = orig }()

	_, err := ApplyCSV(Options{InputPath: paths.input, PlanPath: paths.plan, OutputPath: output, Salt: []byte("0123456789abcdef")})
	if err == nil {
		t.Fatal("ApplyCSV accepted a 100-byte input against a 16-byte cap")
	}
	if !strings.Contains(err.Error(), "exceeds MaxInputSize") {
		t.Fatalf("error = %q, want contains 'exceeds MaxInputSize'", err.Error())
	}
}

// TestApplyRejectsSymlinkInputDefault exercises the default policy: the
// symlink path is refused with the documented message. The FollowSymlinks
// override is covered at the CLI layer in extra_test.go.
func TestApplyRejectsSymlinkInputDefault(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.csv")
	planPath := filepath.Join(dir, "mask.yml")
	link := filepath.Join(dir, "link.csv")
	if err := os.WriteFile(real, []byte(applyFixture), 0o644); err != nil {
		t.Fatalf("write real: %v", err)
	}
	if err := os.WriteFile(planPath, []byte(applyPlan), 0o644); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	output := filepath.Join(dir, "safe.csv")

	_, err := ApplyCSV(Options{InputPath: link, PlanPath: planPath, OutputPath: output, Salt: []byte("0123456789abcdef")})
	if err == nil {
		t.Fatal("ApplyCSV accepted a symlink input without FollowSymlinks")
	}
	if !strings.Contains(err.Error(), "refusing symlink input") {
		t.Fatalf("error = %q, want contains 'refusing symlink input'", err.Error())
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Fatalf("output should not exist after a refused symlink; stat err = %v", statErr)
	}
}

// TestApplyFollowsSymlinkWhenOptedIn asserts the FollowSymlinks override
// resolves the symlink and proceeds to mask the real file's content.
func TestApplyFollowsSymlinkWhenOptedIn(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.csv")
	planPath := filepath.Join(dir, "mask.yml")
	link := filepath.Join(dir, "link.csv")
	if err := os.WriteFile(real, []byte(applyFixture), 0o644); err != nil {
		t.Fatalf("write real: %v", err)
	}
	if err := os.WriteFile(planPath, []byte(applyPlan), 0o644); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	output := filepath.Join(dir, "safe.csv")

	if _, err := ApplyCSV(Options{InputPath: link, PlanPath: planPath, OutputPath: output, Salt: []byte("0123456789abcdef"), FollowSymlinks: true}); err != nil {
		t.Fatalf("ApplyCSV with FollowSymlinks rejected the symlink: %v", err)
	}
	payload, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if len(payload) == 0 {
		t.Fatal("output is empty after a successful apply")
	}
	assertNoRawPII(t, string(payload))
}

// TestOutputFileModeIs0600 pins two contracts of the output file produced by
// ApplyCSV:
//  1. The file's permission bits are 0o600 (owner read/write only). On
//     Windows the Go runtime reports 0o666 on the perm bits regardless of
//     the mode arg passed to OpenFile, so the perm assertion is gated to
//     non-Windows platforms; the O_EXCL refusal test below is portable.
//  2. Re-running ApplyCSV with the same OutputPath fails because
//     SecureOpenOutput opens the file with O_EXCL — an existing file at
//     the destination is an error, not a silent clobber.
func TestOutputFileModeIs0600(t *testing.T) {
	paths := writeApplyFixture(t, applyPlan)
	output := filepath.Join(paths.dir, "safe.csv")
	salt := []byte("0123456789abcdef")

	if _, err := ApplyCSV(Options{InputPath: paths.input, PlanPath: paths.plan, OutputPath: output, Salt: salt}); err != nil {
		t.Fatalf("first ApplyCSV returned error: %v", err)
	}

	info, err := os.Stat(output)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("output is a symlink: %s", info.Mode())
	}
	if runtime.GOOS != "windows" {
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("output mode perm = %o, want 0o600", got)
		}
	}

	_, err = ApplyCSV(Options{InputPath: paths.input, PlanPath: paths.plan, OutputPath: output, Salt: salt})
	if err == nil {
		t.Fatal("second ApplyCSV to the same output path succeeded; O_EXCL should have refused")
	}
}
