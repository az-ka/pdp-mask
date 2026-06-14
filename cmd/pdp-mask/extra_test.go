package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// captureRun redirects os.Stdout and os.Stderr for the duration of run()
// and returns the captured output along with the error.
func captureRun(t *testing.T, args []string) (string, string, error) {
	t.Helper()
	origStdout, origStderr := os.Stdout, os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stdout = wOut
	os.Stderr = wErr

	runErr := run(args)

	// Restore before draining so writes can complete.
	wOut.Close()
	wErr.Close()
	os.Stdout = origStdout
	os.Stderr = origStderr

	var bufOut, bufErr bytes.Buffer
	_, _ = io.Copy(&bufOut, rOut)
	_, _ = io.Copy(&bufErr, rErr)
	return bufOut.String(), bufErr.String(), runErr
}

const cliScanCSV = `id,nama_lengkap,email,no_hp
1,Siti Aminah,siti.aminah@example.test,0812-3456-7890
2,Budi Santoso,budi.santoso@example.test,0812-1111-2222
`

const cliScanYAMLPlan = `version: 1
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

// ---------------------------------------------------------------------------
// run (top-level dispatcher)
// ---------------------------------------------------------------------------

func TestRun_Dispatch(t *testing.T) {
	t.Run("no_args_returns_error", func(t *testing.T) {
		_, stderr, err := captureRun(t, nil)
		if err == nil {
			t.Fatal("expected error for empty args")
		}
		if !strings.Contains(err.Error(), "missing command") {
			t.Fatalf("err = %q, want missing command", err)
		}
		if !strings.Contains(stderr, "Usage:") {
			t.Fatalf("expected usage text in stderr, got %q", stderr)
		}
	})

	t.Run("unknown_command_returns_error", func(t *testing.T) {
		_, stderr, err := captureRun(t, []string{"bogus"})
		if err == nil {
			t.Fatal("expected error for unknown command")
		}
		if !strings.Contains(err.Error(), "unknown command") {
			t.Fatalf("err = %q, want unknown command", err)
		}
		if !strings.Contains(stderr, "Usage:") {
			t.Fatalf("expected usage text in stderr, got %q", stderr)
		}
	})

	t.Run("help_returns_nil", func(t *testing.T) {
		stdout, _, err := captureRun(t, []string{"help"})
		if err != nil {
			t.Fatalf("run(help) returned err: %v", err)
		}
		if !strings.Contains(stdout, "Usage:") {
			t.Fatalf("expected usage on stdout, got %q", stdout)
		}
	})

	t.Run("long_help_flag_returns_nil", func(t *testing.T) {
		stdout, _, err := captureRun(t, []string{"--help"})
		if err != nil {
			t.Fatalf("run(--help) returned err: %v", err)
		}
		if !strings.Contains(stdout, "pdp-mask apply") {
			t.Fatalf("expected usage on stdout, got %q", stdout)
		}
	})

	t.Run("short_help_flag_returns_nil", func(t *testing.T) {
		stdout, _, err := captureRun(t, []string{"-h"})
		if err != nil {
			t.Fatalf("run(-h) returned err: %v", err)
		}
		if !strings.Contains(stdout, "Usage:") {
			t.Fatalf("expected usage on stdout, got %q", stdout)
		}
	})
}

// ---------------------------------------------------------------------------
// splitArgs
// ---------------------------------------------------------------------------

func TestSplitArgs(t *testing.T) {
	needs := func(string) bool { return true }
	none := func(string) bool { return false }

	cases := []struct {
		name      string
		args      []string
		needs     func(string) bool
		wantFlags []string
		wantIn    []string
	}{
		{
			name:      "empty",
			args:      nil,
			needs:     none,
			wantFlags: []string{},
			wantIn:    []string{},
		},
		{
			name:      "single_positional",
			args:      []string{"a.csv"},
			needs:     none,
			wantFlags: []string{},
			wantIn:    []string{"a.csv"},
		},
		{
			name:      "multiple_positional",
			args:      []string{"a.csv", "b.csv"},
			needs:     none,
			wantFlags: []string{},
			wantIn:    []string{"a.csv", "b.csv"},
		},
		{
			name:      "value_with_space_is_single_token",
			args:      []string{"--out", "name with space.csv"},
			needs:     needs,
			wantFlags: []string{"--out", "name with space.csv"},
			wantIn:    []string{},
		},
		{
			name:      "equals_syntax_does_not_consume_next",
			args:      []string{"--out=path/x.csv", "input.csv"},
			needs:     needs,
			wantFlags: []string{"--out=path/x.csv"},
			wantIn:    []string{"input.csv"},
		},
		{
			name:      "flag_without_value_needsValue_false",
			args:      []string{"--verbose", "input.csv"},
			needs:     none,
			wantFlags: []string{"--verbose"},
			wantIn:    []string{"input.csv"},
		},
		{
			name:      "flag_at_end_no_next_value",
			args:      []string{"input.csv", "--out"},
			needs:     needs,
			wantFlags: []string{"--out"},
			wantIn:    []string{"input.csv"},
		},
		{
			name:      "multiple_flags_mixed",
			args:      []string{"--config", "mask.yml", "--out", "safe.csv", "input.csv"},
			needs:     needs,
			wantFlags: []string{"--config", "mask.yml", "--out", "safe.csv"},
			wantIn:    []string{"input.csv"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotFlags, gotIn := splitArgs(tc.args, tc.needs)
			if !equalStrings(gotFlags, tc.wantFlags) {
				t.Fatalf("flags = %#v, want %#v", gotFlags, tc.wantFlags)
			}
			if !equalStrings(gotIn, tc.wantIn) {
				t.Fatalf("inputs = %#v, want %#v", gotIn, tc.wantIn)
			}
		})
	}
}

func TestSplitScanArgs_UsesScanPredicate(t *testing.T) {
	// --format needs a value; --json needs a value; the bare flag --preset
	// consumes the next arg because the predicate says so.
	flags, inputs := splitScanArgs([]string{"--format", "csv", "in.csv"})
	if !equalStrings(flags, []string{"--format", "csv"}) {
		t.Fatalf("flags = %#v", flags)
	}
	if !equalStrings(inputs, []string{"in.csv"}) {
		t.Fatalf("inputs = %#v", inputs)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// resolveFormat
// ---------------------------------------------------------------------------

func TestResolveFormat(t *testing.T) {
	cases := []struct {
		name      string
		path      string
		requested string
		want      string
		wantErr   string
	}{
		{name: "explicit_csv", path: "anything.txt", requested: "csv", want: "csv"},
		{name: "auto_csv_extension", path: "x.csv", requested: "auto", want: "csv"},
		{name: "auto_csv_extension_uppercase", path: "X.CSV", requested: "auto", want: "csv"},
		{name: "auto_unknown_extension", path: "x.txt", requested: "auto", wantErr: "could not auto-detect"},
		{name: "unsupported_format", path: "x.csv", requested: "json", wantErr: "unsupported format"},
		{name: "empty_format", path: "x.csv", requested: "", wantErr: "unsupported format"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveFormat(tc.path, tc.requested)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %q, want contains %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// loadSalt
// ---------------------------------------------------------------------------

func TestLoadSalt_EnvUnset(t *testing.T) {
	t.Setenv("PDP_MASK_SALT_EMPTY_TEST", "")
	salt, err := loadSalt("PDP_MASK_SALT_EMPTY_TEST", "")
	if err == nil {
		t.Fatalf("expected error for unset env, got salt %q", salt)
	}
	if !strings.Contains(err.Error(), "must contain at least") {
		t.Fatalf("err = %q", err.Error())
	}
}

func TestLoadSalt_EnvShort(t *testing.T) {
	t.Setenv("PDP_MASK_SALT_SHORT_TEST", "short")
	_, err := loadSalt("PDP_MASK_SALT_SHORT_TEST", "")
	if err == nil {
		t.Fatal("expected error for short env salt")
	}
	if !strings.Contains(err.Error(), "PDP_MASK_SALT_SHORT_TEST") {
		t.Fatalf("err = %q", err.Error())
	}
}

func TestLoadSalt_EnvLongHex(t *testing.T) {
	t.Setenv("PDP_MASK_SALT_LONG_TEST", "0123456789abcdef")
	salt, err := loadSalt("PDP_MASK_SALT_LONG_TEST", "")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(salt) != "0123456789abcdef" {
		t.Fatalf("salt = %q", string(salt))
	}
}

func TestLoadSalt_EmptyEnvName(t *testing.T) {
	// EnvName is empty so the file branch is not taken; env name "" triggers
	// the explicit guard.
	t.Setenv("PDP_MASK_SALT_LONG_TEST", "0123456789abcdef")
	_, err := loadSalt("", "")
	if err == nil {
		t.Fatal("expected error for empty env name")
	}
	if !strings.Contains(err.Error(), "env name is required") {
		t.Fatalf("err = %q", err.Error())
	}
}

func TestLoadSalt_FileOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "salt")
	if err := os.WriteFile(path, []byte("0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	salt, err := loadSalt("PDP_MASK_SALT_LONG_TEST", path)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(salt) != "0123456789abcdef" {
		t.Fatalf("salt = %q", string(salt))
	}
}

func TestLoadSalt_FileShort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "salt")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadSalt("PDP_MASK_SALT_LONG_TEST", path)
	if err == nil {
		t.Fatal("expected error for short file salt")
	}
	if !strings.Contains(err.Error(), "must be at least") {
		t.Fatalf("err = %q", err.Error())
	}
}

func TestLoadSalt_FileMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "no-such-file")
	_, err := loadSalt("PDP_MASK_SALT_LONG_TEST", path)
	if err == nil {
		t.Fatal("expected error for missing salt file")
	}
	if !strings.Contains(err.Error(), "salt file") {
		t.Fatalf("err = %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// runScan
// ---------------------------------------------------------------------------

func writeCSVDataset(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "data.csv")
	if err := os.WriteFile(p, []byte(cliScanCSV), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunScan_HappyPath(t *testing.T) {
	dir := t.TempDir()
	csv := writeCSVDataset(t, dir)
	stdout, _, err := captureRun(t, []string{"scan", csv, "--sample-rows", "100"})
	if err != nil {
		t.Fatalf("run scan: %v", err)
	}
	for _, want := range []string{"pdp-mask scan", "Likely PII", "email", "no_hp"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("scan stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunScan_WritesJSON(t *testing.T) {
	dir := t.TempDir()
	csv := writeCSVDataset(t, dir)
	reportPath := filepath.Join(dir, "report.json")
	_, _, err := captureRun(t, []string{"scan", csv, "--json", reportPath})
	if err != nil {
		t.Fatalf("run scan with --json: %v", err)
	}
	payload, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read json: %v", err)
	}
	if !bytes.Contains(payload, []byte("\"findings\"")) {
		t.Fatalf("json report missing findings: %s", payload)
	}
}

func TestRunScan_OutAlias(t *testing.T) {
	dir := t.TempDir()
	csv := writeCSVDataset(t, dir)
	reportPath := filepath.Join(dir, "out-alias.json")
	_, _, err := captureRun(t, []string{"scan", csv, "--out", reportPath})
	if err != nil {
		t.Fatalf("run scan with --out alias: %v", err)
	}
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatalf("expected json at %s: %v", reportPath, err)
	}
}

func TestRunScan_Errors(t *testing.T) {
	dir := t.TempDir()
	csv := writeCSVDataset(t, dir)

	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "missing_input",
			args:    []string{"scan"},
			wantErr: "scan requires exactly one input file",
		},
		{
			name:    "unknown_flag",
			args:    []string{"scan", csv, "--bogus"},
			wantErr: "flag provided but not defined",
		},
		{
			name:    "unsupported_preset",
			args:    []string{"scan", csv, "--preset", "us"},
			wantErr: "unsupported preset",
		},
		{
			name:    "auto_format_on_non_csv",
			args:    []string{"scan", filepath.Join(dir, "no.dat")},
			wantErr: "could not auto-detect",
		},
		{
			name:    "explicit_unsupported_format",
			args:    []string{"scan", csv, "--format", "parquet"},
			wantErr: "unsupported format",
		},
		{
			name:    "bad_rules_path",
			args:    []string{"scan", csv, "--rules", filepath.Join(dir, "missing.yml")},
			wantErr: "", // accept any error; path resolves to a missing file
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Make a real file for cases that need it
			if tc.name == "auto_format_on_non_csv" {
				if err := os.WriteFile(filepath.Join(dir, "no.dat"), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			_, _, err := captureRun(t, tc.args)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %q, want contains %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestRunScan_BadJSONOutputPath(t *testing.T) {
	dir := t.TempDir()
	csv := writeCSVDataset(t, dir)
	// Path whose parent directory does not exist -> os.Create fails.
	bad := filepath.Join(dir, "missing", "nested", "report.json")
	_, _, err := captureRun(t, []string{"scan", csv, "--json", bad})
	if err == nil {
		t.Fatal("expected error writing json to nonexistent directory")
	}
	if !strings.Contains(err.Error(), "create json report") {
		t.Fatalf("err = %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// runApply additional cases
// ---------------------------------------------------------------------------

func TestRunApply_Errors(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "customers.csv")
	config := filepath.Join(dir, "mask.yml")
	output := filepath.Join(dir, "safe.csv")
	mustWriteFile(t, input, cliApplyCSV)
	mustWriteFile(t, config, cliScanYAMLPlan)
	t.Setenv("PDP_MASK_SALT", "0123456789abcdef")

	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "no_args",
			args:    []string{"apply"},
			wantErr: "apply requires exactly one input CSV file",
		},
		{
			name:    "missing_config",
			args:    []string{"apply", input, "--out", output},
			wantErr: "apply requires --config",
		},
		{
			name:    "missing_out",
			args:    []string{"apply", input, "--config", config},
			wantErr: "apply requires --out",
		},
		{
			name:    "unknown_flag",
			args:    []string{"apply", input, "--config", config, "--out", output, "--bogus"},
			wantErr: "flag provided but not defined",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := captureRun(t, tc.args)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %q, want contains %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestRunApply_SaltEnvUnset(t *testing.T) {
	// Explicitly clear salt env so loadSalt must error.
	t.Setenv("PDP_MASK_SALT", "")
	dir := t.TempDir()
	input := filepath.Join(dir, "customers.csv")
	config := filepath.Join(dir, "mask.yml")
	output := filepath.Join(dir, "safe.csv")
	mustWriteFile(t, input, cliApplyCSV)
	mustWriteFile(t, config, cliScanYAMLPlan)

	_, _, err := captureRun(t, []string{"apply", input, "--config", config, "--out", output})
	if err == nil {
		t.Fatal("expected error for empty salt env")
	}
	if !strings.Contains(err.Error(), "salt") {
		t.Fatalf("err = %q", err.Error())
	}
}

func TestRunApply_ExistingOutputCheckedEvenWithoutSalt(t *testing.T) {
	// The existing-output guard fires before loadSalt; ensure it does.
	dir := t.TempDir()
	input := filepath.Join(dir, "customers.csv")
	config := filepath.Join(dir, "mask.yml")
	output := filepath.Join(dir, "safe.csv")
	mustWriteFile(t, input, cliApplyCSV)
	mustWriteFile(t, config, cliScanYAMLPlan)
	mustWriteFile(t, output, "pre-existing")
	t.Setenv("PDP_MASK_SALT", "0123456789abcdef")

	_, _, err := captureRun(t, []string{"apply", input, "--config", config, "--out", output})
	if err == nil {
		t.Fatal("expected error for existing output")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %q", err.Error())
	}
}

func TestRunApply_StatErrorPropagates(t *testing.T) {
	// Make --out a path whose parent directory cannot be stat'd by giving an
	// output path inside a non-existent directory under a file (so os.Stat
	// returns a non-IsNotExist error on some platforms, OR a sane error path
	// otherwise). This exercises the Stat error branch alongside the success
	// branch already covered.
	dir := t.TempDir()
	input := filepath.Join(dir, "customers.csv")
	config := filepath.Join(dir, "mask.yml")
	// Create a file, then try to use a path under it as if it were a dir.
	blocker := filepath.Join(dir, "blocker")
	mustWriteFile(t, blocker, "i am a file")
	output := filepath.Join(blocker, "safe.csv")
	mustWriteFile(t, input, cliApplyCSV)
	mustWriteFile(t, config, cliScanYAMLPlan)
	t.Setenv("PDP_MASK_SALT", "0123456789abcdef")

	_, _, err := captureRun(t, []string{"apply", input, "--config", config, "--out", output})
	if err == nil {
		t.Fatal("expected error for output path under non-directory")
	}
	// On Windows this is an access-denied style; on POSIX ENOTDIR. Either way
	// the message must NOT be "already exists" because the file does not
	// exist as a sibling.
	if strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %q, expected stat error not exists-mismatch", err.Error())
	}
}

func TestRunApply_BadPlanYAML(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "customers.csv")
	config := filepath.Join(dir, "mask.yml")
	output := filepath.Join(dir, "safe.csv")
	mustWriteFile(t, input, cliApplyCSV)
	mustWriteFile(t, config, "not: valid: yaml: [")
	t.Setenv("PDP_MASK_SALT", "0123456789abcdef")

	_, _, err := captureRun(t, []string{"apply", input, "--config", config, "--out", output})
	if err == nil {
		t.Fatal("expected error for malformed plan YAML")
	}
}

// ---------------------------------------------------------------------------
// runVerify additional cases
// ---------------------------------------------------------------------------

func TestRunVerify_Errors(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "customers.csv")
	config := filepath.Join(dir, "mask.yml")
	output := filepath.Join(dir, "safe.csv")
	mustWriteFile(t, input, cliVerifyCSV)
	mustWriteFile(t, config, cliVerifyPlan)
	mustWriteFile(t, output, cliVerifyCSV)

	cases := []struct {
		name     string
		args     []string
		wantErr  string
		wantCode int
	}{
		{
			name:     "no_args",
			args:     []string{"verify"},
			wantErr:  "verify requires exactly one input CSV file",
			wantCode: 1,
		},
		{
			name:     "missing_config",
			args:     []string{"verify", input, "--out", output},
			wantErr:  "verify requires --config",
			wantCode: 1,
		},
		{
			name:     "missing_out",
			args:     []string{"verify", input, "--config", config},
			wantErr:  "verify requires --out",
			wantCode: 1,
		},
		{
			name:     "unknown_flag",
			args:     []string{"verify", input, "--config", config, "--out", output, "--bogus"},
			wantErr:  "flag provided but not defined",
			wantCode: 1,
		},
		{
			name:     "config_not_found",
			args:     []string{"verify", input, "--config", filepath.Join(dir, "missing.yml"), "--out", output},
			wantErr:  "read config",
			wantCode: 2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := captureRun(t, tc.args)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %q, want contains %q", err.Error(), tc.wantErr)
			}
			var cliErr CLIError
			if tc.wantCode != 0 {
				if !errors.As(err, &cliErr) {
					t.Fatalf("expected CLIError, got %T: %v", err, err)
				}
				if cliErr.Code != tc.wantCode {
					t.Fatalf("code = %d, want %d", cliErr.Code, tc.wantCode)
				}
				// Also exercise Unwrap so its coverage is real.
				if cliErr.Unwrap() == nil {
					t.Fatal("Unwrap returned nil")
				}
			}
		})
	}
}

func TestRunVerify_BadRulesPath(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "customers.csv")
	config := filepath.Join(dir, "mask.yml")
	output := filepath.Join(dir, "safe.csv")
	mustWriteFile(t, input, cliVerifyCSV)
	mustWriteFile(t, config, cliVerifyPlan)
	mustWriteFile(t, output, cliVerifyCSV)

	_, _, err := captureRun(t, []string{"verify", input, "--config", config, "--out", output, "--rules", filepath.Join(dir, "missing.yml")})
	if err == nil {
		t.Fatal("expected error for missing rules file")
	}
	var cliErr CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("expected CLIError, got %T: %v", err, err)
	}
	if cliErr.Code != 1 {
		t.Fatalf("code = %d, want 1", cliErr.Code)
	}
}

func TestRunVerify_UnsupportedPlanVersion(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "customers.csv")
	config := filepath.Join(dir, "mask.yml")
	output := filepath.Join(dir, "safe.csv")
	mustWriteFile(t, input, cliVerifyCSV)
	mustWriteFile(t, config, `version: 999
columns: []
`)
	mustWriteFile(t, output, cliVerifyCSV)

	_, _, err := captureRun(t, []string{"verify", input, "--config", config, "--out", output})
	if err == nil {
		t.Fatal("expected error for unsupported plan version")
	}
	var cliErr CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("expected CLIError, got %T", err)
	}
	if cliErr.Code != 2 {
		t.Fatalf("code = %d, want 2", cliErr.Code)
	}
	if !strings.Contains(err.Error(), "unsupported plan version") {
		t.Fatalf("err = %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// runPlan additional cases
// ---------------------------------------------------------------------------

func TestRunPlan_Errors(t *testing.T) {
	dir := t.TempDir()
	scanPath := writeScanReport(t, dir)
	outPath := filepath.Join(dir, "mask.yml")

	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "no_args",
			args:    []string{"plan"},
			wantErr: "plan requires exactly one scan JSON file",
		},
		{
			name:    "missing_out",
			args:    []string{"plan", scanPath},
			wantErr: "plan requires --out",
		},
		{
			name:    "unknown_flag",
			args:    []string{"plan", scanPath, "--out", outPath, "--bogus"},
			wantErr: "flag provided but not defined",
		},
		{
			name:    "missing_scan_json",
			args:    []string{"plan", filepath.Join(dir, "missing.json"), "--out", outPath},
			wantErr: "read scan JSON",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := captureRun(t, tc.args)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %q, want contains %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// runScan / runApply symlink guards
// ---------------------------------------------------------------------------

// TestRunApplyRejectsSymlinkInputCLI asserts the default policy: a symlinked
// input file is refused at the CLI layer before ApplyCSV runs.
func TestRunApplyRejectsSymlinkInputCLI(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.csv")
	planPath := filepath.Join(dir, "mask.yml")
	link := filepath.Join(dir, "link.csv")
	output := filepath.Join(dir, "safe.csv")
	mustWriteFile(t, real, cliApplyCSV)
	mustWriteFile(t, planPath, cliApplyPlan)
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	t.Setenv("PDP_MASK_SALT", "0123456789abcdef")

	_, _, err := captureRun(t, []string{"apply", link, "--config", planPath, "--out", output})
	if err == nil {
		t.Fatal("expected error for symlinked input without --follow-symlinks")
	}
	if !strings.Contains(err.Error(), "refusing symlink input") {
		t.Fatalf("err = %q, want contains 'refusing symlink input'", err.Error())
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Fatalf("output should not exist after refusal; stat err = %v", statErr)
	}
}

// TestRunApplyFollowsSymlinkWithFlag asserts --follow-symlinks resolves the
// symlink and ApplyCSV proceeds to produce a masked output file.
func TestRunApplyFollowsSymlinkWithFlag(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.csv")
	planPath := filepath.Join(dir, "mask.yml")
	link := filepath.Join(dir, "link.csv")
	output := filepath.Join(dir, "safe.csv")
	mustWriteFile(t, real, cliApplyCSV)
	mustWriteFile(t, planPath, cliApplyPlan)
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	t.Setenv("PDP_MASK_SALT", "0123456789abcdef")

	_, _, err := captureRun(t, []string{"apply", link, "--config", planPath, "--out", output, "--follow-symlinks"})
	if err != nil {
		t.Fatalf("run apply with --follow-symlinks returned error: %v", err)
	}
	payload := string(mustReadFile(t, output))
	if !strings.Contains(payload, "id,email,no_hp,note") {
		t.Fatalf("output missing header row:\n%s", payload)
	}
	if strings.Contains(payload, "budi@example.test") {
		t.Fatalf("output leaked raw PII after symlink follow:\n%s", payload)
	}
}

// TestRunScanRejectsSymlinkInputCLI asserts the scan subcommand also refuses
// a symlinked input by default. The FollowSymlinks override path mirrors
// apply; we just need to pin the default-refusal at the scan boundary.
func TestRunScanRejectsSymlinkInputCLI(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.csv")
	link := filepath.Join(dir, "link.csv")
	mustWriteFile(t, real, cliScanCSV)
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}

	_, _, err := captureRun(t, []string{"scan", link})
	if err == nil {
		t.Fatal("expected error for symlinked scan input without --follow-symlinks")
	}
	if !strings.Contains(err.Error(), "refusing symlink input") {
		t.Fatalf("err = %q, want contains 'refusing symlink input'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// loadSalt file-mode guard
// ---------------------------------------------------------------------------

// TestSaltFileRejectedIfWorldReadable pins the loadSalt mode check: a salt
// file with group- or world-readable bits is refused. The check is gated to
// non-Windows because Go's os.WriteFile / os.Stat on Windows ignore the
// mode arg and always report 0o666 on the perm bits; on Windows the test
// is skipped with a clear message.
func TestSaltFileRejectedIfWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skipf("salt file mode check is a no-op on Windows (Go ignores the WriteFile mode arg): %s", runtime.GOOS)
	}

	t.Run("accepts_0o600", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "salt")
		if err := os.WriteFile(path, []byte("0123456789abcdef\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		salt, err := loadSalt("PDP_MASK_SALT_LONG_TEST", path)
		if err != nil {
			t.Fatalf("loadSalt returned error for 0o600 file: %v", err)
		}
		if string(salt) != "0123456789abcdef" {
			t.Fatalf("salt = %q", string(salt))
		}
	})

	t.Run("rejects_0o644", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "salt")
		if err := os.WriteFile(path, []byte("0123456789abcdef\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := loadSalt("PDP_MASK_SALT_LONG_TEST", path)
		if err == nil {
			t.Fatal("loadSalt accepted a 0o644 salt file; the mode check did not fire")
		}
		if !strings.Contains(err.Error(), "insecure salt file mode") || !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("err = %q, want contains 'insecure salt file mode' and 'refusing'", err.Error())
		}
	})

	t.Run("rejects_0o666", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "salt")
		if err := os.WriteFile(path, []byte("0123456789abcdef\n"), 0o666); err != nil {
			t.Fatal(err)
		}
		_, err := loadSalt("PDP_MASK_SALT_LONG_TEST", path)
		if err == nil {
			t.Fatal("loadSalt accepted a 0o666 salt file; the mode check did not fire")
		}
		if !strings.Contains(err.Error(), "insecure salt file mode") {
			t.Fatalf("err = %q, want contains 'insecure salt file mode'", err.Error())
		}
	})

	t.Run("rejects_0o640", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "salt")
		if err := os.WriteFile(path, []byte("0123456789abcdef\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		_, err := loadSalt("PDP_MASK_SALT_LONG_TEST", path)
		if err == nil {
			t.Fatal("loadSalt accepted a 0o640 salt file; the mode check did not fire")
		}
		if !strings.Contains(err.Error(), "insecure salt file mode") {
			t.Fatalf("err = %q, want contains 'insecure salt file mode'", err.Error())
		}
	})
}
