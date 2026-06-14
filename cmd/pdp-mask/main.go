package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/az-ka/pdp-mask/internal/apply"
	"github.com/az-ka/pdp-mask/internal/detect"
	"github.com/az-ka/pdp-mask/internal/plan"
	"github.com/az-ka/pdp-mask/internal/scan"
	"github.com/az-ka/pdp-mask/internal/verify"
)

type CLIError struct {
	Code int
	Err  error
}

func (e CLIError) Error() string {
	return e.Err.Error()
}

func (e CLIError) Unwrap() error {
	return e.Err
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		var cliErr CLIError
		if errors.As(err, &cliErr) {
			fmt.Fprintf(os.Stderr, "pdp-mask: %v\n", cliErr.Err)
			os.Exit(cliErr.Code)
		}
		fmt.Fprintf(os.Stderr, "pdp-mask: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return errors.New("missing command")
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:])
	case "plan":
		return runPlan(args[1:])
	case "apply":
		return runApply(args[1:])
	case "verify":
		return runVerify(args[1:])
	case "help", "--help", "-h":
		printUsage(os.Stdout)
		return nil
	default:
		printUsage(os.Stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func splitScanArgs(args []string) ([]string, []string) {
	return splitArgs(args, scanFlagNeedsValue)
}

func splitArgs(args []string, needsValue func(string) bool) ([]string, []string) {
	flagArgs := make([]string, 0, len(args))
	inputs := make([]string, 0, 1)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if !strings.Contains(arg, "=") && needsValue(arg) && i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}
		inputs = append(inputs, arg)
	}
	return flagArgs, inputs
}

func scanFlagNeedsValue(flagName string) bool {
	switch flagName {
	case "--format", "-format", "--json", "-json", "--out", "-out", "--sample-rows", "-sample-rows", "--preset", "-preset", "--rules", "-rules":
		return true
	default:
		return false
	}
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	format := fs.String("format", "auto", "input format: auto or csv")
	jsonPath := fs.String("json", "", "write machine-readable JSON report")
	outPath := fs.String("out", "", "alias for --json")
	sampleRows := fs.Int("sample-rows", 500, "maximum non-empty values sampled per column")
	preset := fs.String("preset", "indonesia", "detector preset")
	rulesPath := fs.String("rules", "", "path to custom rules YAML pack")
	followSymlinks := fs.Bool("follow-symlinks", false, "follow a symlinked input file (refused by default)")
	flagArgs, inputs := splitScanArgs(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if *rulesPath != "" {
		if err := detect.LoadRules(*rulesPath); err != nil {
			return err
		}
	}
	if len(inputs) != 1 {
		return errors.New("scan requires exactly one input file")
	}
	if *outPath != "" && *jsonPath == "" {
		*jsonPath = *outPath
	}
	if *preset != "indonesia" {
		return fmt.Errorf("unsupported preset %q", *preset)
	}
	input := inputs[0]
	scanInput, err := guardInputForScan(input, *followSymlinks)
	if err != nil {
		return err
	}
	resolvedFormat, err := resolveFormat(scanInput, *format)
	if err != nil {
		return err
	}
	if resolvedFormat != "csv" {
		return fmt.Errorf("unsupported format %q", resolvedFormat)
	}
	report, err := scan.ScanCSV(scanInput, scan.CSVOptions{SampleRows: *sampleRows})
	if err != nil {
		return err
	}
	printScanReport(os.Stdout, report)
	if *jsonPath != "" {
		if err := writeJSON(*jsonPath, report); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "\nWrote JSON report: %s\n", *jsonPath)
	}
	return nil
}

// guardInputForScan mirrors apply.validateInputPath for the scan path: refuse
// symlinks unless followSymlinks is set, and refuse inputs larger than
// apply.MaxInputSize. Returns the path to feed to scan.ScanCSV.
func guardInputForScan(inputPath string, followSymlinks bool) (string, error) {
	info, err := os.Lstat(inputPath)
	if err != nil {
		return "", fmt.Errorf("stat input: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if !followSymlinks {
			return "", fmt.Errorf("refusing symlink input %q (use --follow-symlinks to override)", inputPath)
		}
		resolved, err := filepath.EvalSymlinks(inputPath)
		if err != nil {
			return "", fmt.Errorf("resolve symlink input: %w", err)
		}
		resolvedInfo, err := os.Stat(resolved)
		if err != nil {
			return "", fmt.Errorf("stat resolved input: %w", err)
		}
		if resolvedInfo.Size() > apply.MaxInputSize {
			return "", fmt.Errorf("input file %q is %d bytes, exceeds MaxInputSize (%d bytes)", inputPath, resolvedInfo.Size(), apply.MaxInputSize)
		}
		return resolved, nil
	}
	if info.Size() > apply.MaxInputSize {
		return "", fmt.Errorf("input file %q is %d bytes, exceeds MaxInputSize (%d bytes)", inputPath, info.Size(), apply.MaxInputSize)
	}
	return inputPath, nil
}

func runPlan(args []string) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outPath := fs.String("out", "", "write masking plan YAML")
	force := fs.Bool("force", false, "overwrite output file if it exists")
	flagArgs, inputs := splitArgs(args, planFlagNeedsValue)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if len(inputs) != 1 {
		return errors.New("plan requires exactly one scan JSON file")
	}
	if *outPath == "" {
		return errors.New("plan requires --out")
	}
	if !*force {
		if _, err := os.Stat(*outPath); err == nil {
			return fmt.Errorf("output file already exists: %s", *outPath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("check output file: %w", err)
		}
	}
	scanPath := inputs[0]
	payload, err := os.ReadFile(scanPath)
	if err != nil {
		return fmt.Errorf("read scan JSON: %w", err)
	}
	var report scan.Report
	if err := json.Unmarshal(payload, &report); err != nil {
		return fmt.Errorf("parse scan JSON: %w", err)
	}
	doc, err := plan.Generate(&report, scanPath, payload)
	if err != nil {
		return err
	}
	if err := secureWriteFile(*outPath, plan.RenderYAML(doc)); err != nil {
		return fmt.Errorf("write plan: %w", err)
	}
	printPlanReport(os.Stdout, scanPath, *outPath, doc)
	return nil
}

// secureWriteFile creates path with O_EXCL (and O_NOFOLLOW on platforms that
// support it) so the destination must not exist and must not be a symlink.
// The O_EXCL policy is consistent with the --force opt-in: callers that
// want overwrite behavior should pre-check and delete first. Mode is fixed
// to 0o600 by apply.SecureOpenOutput.
func secureWriteFile(path string, payload []byte) error {
	f, err := apply.SecureOpenOutput(path)
	if err != nil {
		return fmt.Errorf("open output: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(payload); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func runApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "masking plan YAML")
	outPath := fs.String("out", "", "masked CSV output path")
	force := fs.Bool("force", false, "overwrite output file if it exists")
	saltEnv := fs.String("salt-env", "PDP_MASK_SALT", "environment variable containing masking salt")
	saltFile := fs.String("salt-file", "", "file containing masking salt")
	followSymlinks := fs.Bool("follow-symlinks", false, "follow a symlinked input file (refused by default)")
	flagArgs, inputs := splitArgs(args, applyFlagNeedsValue)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if len(inputs) != 1 {
		return errors.New("apply requires exactly one input CSV file")
	}
	if *configPath == "" {
		return errors.New("apply requires --config")
	}
	if *outPath == "" {
		return errors.New("apply requires --out")
	}
	if !*force {
		if _, err := os.Stat(*outPath); err == nil {
			return fmt.Errorf("output file already exists: %s", *outPath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("check output file: %w", err)
		}
	}
	salt, err := loadSalt(*saltEnv, *saltFile)
	if err != nil {
		return err
	}
	result, err := apply.ApplyCSV(apply.Options{
		InputPath:      inputs[0],
		PlanPath:       *configPath,
		OutputPath:     *outPath,
		Salt:           salt,
		FollowSymlinks: *followSymlinks,
	})
	if err != nil {
		return err
	}
	printApplyReport(os.Stdout, inputs[0], *outPath, result)
	return nil
}

func applyFlagNeedsValue(flagName string) bool {
	switch flagName {
	case "--config", "-config", "--out", "-out", "--salt-env", "-salt-env", "--salt-file", "-salt-file":
		return true
	default:
		return false
	}
}
func loadSalt(envName, filePath string) ([]byte, error) {
	if filePath != "" {
		// Refuse to read a salt file that is readable by group or other.
		// On Windows the kernel's permission bits are not exposed via
		// os.FileMode (Go's WriteFile/Stat on Windows ignore the mode arg
		// and always report 0o666 on the perm bits), so the check is a
		// no-op there. Operators on Windows must rely on NTFS ACLs.
		if runtime.GOOS != "windows" {
			info, err := os.Stat(filePath)
			if err != nil {
				return nil, fmt.Errorf("stat salt file: %w", err)
			}
			if info.Mode().Perm()&0o077 != 0 {
				return nil, fmt.Errorf("insecure salt file mode %s on %q: refusing (recommend: chmod 600 %q)", info.Mode(), filePath, filePath)
			}
		}
		payload, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read salt file: %w", err)
		}
		payload = []byte(strings.TrimSpace(string(payload)))
		if len(payload) < apply.MinSaltLength {
			return nil, fmt.Errorf("salt must be at least %d bytes", apply.MinSaltLength)
		}
		return payload, nil
	}
	if envName == "" {
		return nil, errors.New("salt env name is required")
	}
	salt := []byte(os.Getenv(envName))
	if len(salt) < apply.MinSaltLength {
		return nil, fmt.Errorf("salt env %s must contain at least %d bytes", envName, apply.MinSaltLength)
	}
	return salt, nil
}

func planFlagNeedsValue(flagName string) bool {
	switch flagName {
	case "--out", "-out":
		return true
	default:
		return false
	}
}

func resolveFormat(path, requested string) (string, error) {
	switch requested {
	case "csv":
		return "csv", nil
	case "auto":
		if strings.EqualFold(filepath.Ext(path), ".csv") {
			return "csv", nil
		}
		return "", fmt.Errorf("could not auto-detect format for %s; pass --format csv", path)
	default:
		return "", fmt.Errorf("unsupported format %q", requested)
	}
}

func printScanReport(out *os.File, report *scan.Report) {
	input := report.Inputs[0]
	fmt.Fprintf(out, "pdp-mask scan %s\n\n", input.Path)
	fmt.Fprintf(out, "Input        %s\n", input.Path)
	fmt.Fprintf(out, "Format       %s\n", input.Format)
	fmt.Fprintf(out, "Table        %s\n", input.Table)
	fmt.Fprintf(out, "Rows         %d\n", input.Rows)
	fmt.Fprintf(out, "Columns      %d\n", input.Columns)
	fmt.Fprintf(out, "Sample rows  up to %d non-empty values per column\n\n", input.SampleRows)
	if len(report.Findings) == 0 {
		fmt.Fprintln(out, "Likely PII: none")
		return
	}
	fmt.Fprintln(out, "Likely PII")
	for _, finding := range report.Findings {
		fmt.Fprintf(out, "  %-32s %-14s %-7s %s\n", finding.Table+"."+finding.Column, finding.Category, finding.Band, strings.Join(finding.Evidence, "+"))
	}
	fmt.Fprintln(out, "\nNext step")
	fmt.Fprintln(out, "  pdp-mask plan <scan.json> --out mask.yml")
}

func writeJSON(path string, report *scan.Report) error {
	// O_EXCL via apply.SecureOpenOutput so a pre-existing file or a symlink
	// at `path` blocks the write; mode 0o600 is consistent with the apply
	// --out policy.
	file, err := apply.SecureOpenOutput(path)
	if err != nil {
		return fmt.Errorf("create json report: %w", err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("write json report: %w", err)
	}
	return nil
}

func printPlanReport(out *os.File, scanPath, outPath string, doc *plan.Document) {
	fmt.Fprintf(out, "pdp-mask plan %s\n\n", scanPath)
	fmt.Fprintf(out, "Output   %s\n", outPath)
	fmt.Fprintf(out, "Inputs   %d\n", len(doc.Inputs))
	fmt.Fprintf(out, "Findings %d\n", doc.Findings)
	fmt.Fprintf(out, "Actions  mask=%d review=%d\n", doc.Summary.Mask, doc.Summary.Review)
	fmt.Fprintln(out, "\nNext step")
	fmt.Fprintln(out, "  pdp-mask apply <input> --config mask.yml --out <masked-output>")
}

func printApplyReport(out *os.File, inputPath, outPath string, result apply.Result) {
	fmt.Fprintf(out, "pdp-mask apply %s\n\n", inputPath)
	fmt.Fprintf(out, "Output         %s\n", outPath)
	fmt.Fprintf(out, "Rows           %d\n", result.Rows)
	fmt.Fprintf(out, "Masked columns %d\n", result.MaskedColumns)
	fmt.Fprintf(out, "Masked values  %d\n", result.MaskedValues)
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "masking plan YAML")
	outPath := fs.String("out", "", "masked CSV output path")
	rulesPath := fs.String("rules", "", "path to custom rules YAML pack")
	flagArgs, inputs := splitArgs(args, verifyFlagNeedsValue)
	if err := fs.Parse(flagArgs); err != nil {
		return CLIError{Code: 1, Err: err}
	}
	if *rulesPath != "" {
		if err := detect.LoadRules(*rulesPath); err != nil {
			return CLIError{Code: 1, Err: err}
		}
	}
	if len(inputs) != 1 {
		return CLIError{Code: 1, Err: errors.New("verify requires exactly one input CSV file")}
	}
	if *configPath == "" {
		return CLIError{Code: 1, Err: errors.New("verify requires --config")}
	}
	if *outPath == "" {
		return CLIError{Code: 1, Err: errors.New("verify requires --out")}
	}

	result, err := verify.Verify(verify.Options{
		ConfigPath: *configPath,
		InputPath:  inputs[0],
		OutputPath: *outPath,
	})
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "read config") || strings.Contains(errStr, "parse config YAML") || strings.Contains(errStr, "unsupported plan version") {
			return CLIError{Code: 2, Err: err}
		}
		if strings.Contains(errStr, "scan input CSV") || strings.Contains(errStr, "scan safe CSV") || strings.Contains(errStr, "read input headers") || strings.Contains(errStr, "read output headers") || strings.Contains(errStr, "count input rows") || strings.Contains(errStr, "count output rows") || strings.Contains(errStr, "read csv row") {
			return CLIError{Code: 2, Err: err}
		}
		return CLIError{Code: 1, Err: err}
	}

	printVerifyReport(os.Stdout, result)

	if !result.Passed {
		code := 3
		for _, issue := range result.Issues {
			if strings.Contains(issue, "header count mismatch") ||
				strings.Contains(issue, "header mismatch") ||
				strings.Contains(issue, "row count mismatch") ||
				strings.Contains(issue, "byte-identical") {
				code = 4
				break
			}
		}
		return CLIError{Code: code, Err: fmt.Errorf("verification failed (%d checks failed): %s", len(result.Issues), strings.Join(result.Issues, "; "))}
	}
	return nil
}

func verifyFlagNeedsValue(flagName string) bool {
	switch flagName {
	case "--config", "-config", "--out", "-out", "--rules", "-rules":
		return true
	default:
		return false
	}
}

func printVerifyReport(out *os.File, result *verify.VerificationResult) {
	fmt.Fprintf(out, "Plan policy         %s\n", result.PlanPolicyStatus)
	fmt.Fprintf(out, "Input coverage      %s\n", result.InputCoverageStatus)
	fmt.Fprintf(out, "Output leakage      %s\n", result.OutputLeakageStatus)
	fmt.Fprintf(out, "Artifact shape      %s\n", result.ArtifactShapeStatus)
	fmt.Fprintf(out, "Strategy validation %s\n", result.StrategyValStatus)
	fmt.Fprintln(out)
	if result.Passed {
		fmt.Fprintln(out, "Result: PASS")
	} else {
		fmt.Fprintf(out, "Result: FAIL (%d checks failed)\n", len(result.Issues))
		for _, issue := range result.Issues {
			fmt.Fprintf(out, "  - %s\n", issue)
		}
	}
}

func printUsage(out *os.File) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  pdp-mask scan <file.csv> [--json report.json] [--sample-rows 500]")
	fmt.Fprintln(out, "  pdp-mask plan <scan.json> --out mask.yml")
	fmt.Fprintln(out, "  pdp-mask apply <file.csv> --config mask.yml --out safe.csv")
	fmt.Fprintln(out, "  pdp-mask verify <file.csv> --config mask.yml --out safe.csv")
}
