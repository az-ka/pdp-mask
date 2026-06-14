package apply

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/az-ka/pdp-mask/internal/plan"
	"github.com/az-ka/pdp-mask/internal/strategy"
	"gopkg.in/yaml.v3"
)

const MinSaltLength = 16

// MaxInputSize caps the input CSV at 1 GiB. The cap is a var (not const) so
// tests can shrink it; production callers must not mutate it.
var MaxInputSize int64 = 1 << 30

// FollowSymlinks opts into resolving a symlinked input to its target before
// applying. Default is false; pass true to accept --follow-symlinks.
type Options struct {
	InputPath      string
	PlanPath       string
	OutputPath     string
	Salt           []byte
	FollowSymlinks bool
}

type Result struct {
	Rows          int
	MaskedColumns int
	MaskedValues  int
}

// validateInputPath enforces the input guards before ApplyCSV opens the file:
//   - Refuse symlinks unless FollowSymlinks is set (then resolve with
//     filepath.EvalSymlinks so the open hits the real file).
//   - Refuse inputs larger than MaxInputSize to bound memory during CSV read.
//
// Returns the path to actually open (original or resolved) and the file size.
func validateInputPath(inputPath string, followSymlinks bool) (string, int64, error) {
	info, err := os.Lstat(inputPath)
	if err != nil {
		return "", 0, fmt.Errorf("stat input: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if !followSymlinks {
			return "", 0, fmt.Errorf("refusing symlink input %q (use --follow-symlinks to override)", inputPath)
		}
		resolved, err := filepath.EvalSymlinks(inputPath)
		if err != nil {
			return "", 0, fmt.Errorf("resolve symlink input: %w", err)
		}
		resolvedInfo, err := os.Stat(resolved)
		if err != nil {
			return "", 0, fmt.Errorf("stat resolved input: %w", err)
		}
		if resolvedInfo.Size() > MaxInputSize {
			return "", 0, fmt.Errorf("input file %q is %d bytes, exceeds MaxInputSize (%d bytes)", inputPath, resolvedInfo.Size(), MaxInputSize)
		}
		return resolved, resolvedInfo.Size(), nil
	}
	if info.Size() > MaxInputSize {
		return "", 0, fmt.Errorf("input file %q is %d bytes, exceeds MaxInputSize (%d bytes)", inputPath, info.Size(), MaxInputSize)
	}
	return inputPath, info.Size(), nil
}

// SecureOpenOutput creates a new file at path with mode 0o600, refusing to
// follow a symlink at the destination or to overwrite an existing file.
// On platforms that expose O_NOFOLLOW (Unix), the kernel enforces the
// symlink refusal at open time; on Windows the Lstat pre-check below
// covers the same case. O_EXCL is set on all platforms so callers cannot
// silently clobber an existing file.
func SecureOpenOutput(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing symlink output %q (remove it and retry)", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat output: %w", err)
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|NoFollowFlag, 0o600)
}

func ApplyCSV(opts Options) (Result, error) {
	if opts.InputPath == "" {
		return Result{}, fmt.Errorf("input path is required")
	}
	if opts.PlanPath == "" {
		return Result{}, fmt.Errorf("config path is required")
	}
	if opts.OutputPath == "" {
		return Result{}, fmt.Errorf("output path is required")
	}
	if opts.InputPath == opts.OutputPath {
		return Result{}, fmt.Errorf("refusing to overwrite source input")
	}
	if len(opts.Salt) < MinSaltLength {
		return Result{}, fmt.Errorf("salt must be at least %d bytes", MinSaltLength)
	}
	resolvedInput, _, err := validateInputPath(opts.InputPath, opts.FollowSymlinks)
	if err != nil {
		return Result{}, err
	}
	doc, err := loadPlan(opts.PlanPath)
	if err != nil {
		return Result{}, err
	}
	input, err := os.Open(resolvedInput)
	if err != nil {
		return Result{}, fmt.Errorf("open input: %w", err)
	}
	defer input.Close()

	reader := csv.NewReader(input)
	reader.FieldsPerRecord = -1
	headers, err := reader.Read()
	if err != nil {
		if err == io.EOF {
			return Result{}, fmt.Errorf("empty csv: %s", opts.InputPath)
		}
		return Result{}, fmt.Errorf("read csv header: %w", err)
	}
	reader.FieldsPerRecord = len(headers)
	rules, err := rulesForHeaders(doc, opts.InputPath, headers)
	if err != nil {
		return Result{}, err
	}

	// Open the output with O_EXCL (and O_NOFOLLOW on platforms that support
	// it). The Lstat inside SecureOpenOutput closes the same TOCTOU window
	// for Windows where O_NOFOLLOW is not available.
	output, err := SecureOpenOutput(opts.OutputPath)
	if err != nil {
		return Result{}, fmt.Errorf("create output: %w", err)
	}
	defer output.Close()
	writer := csv.NewWriter(output)
	if err := writer.Write(headers); err != nil {
		return Result{}, fmt.Errorf("write csv header: %w", err)
	}

	result := Result{MaskedColumns: len(rules)}
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Result{}, fmt.Errorf("read csv row %d: %w", result.Rows+2, err)
		}
		result.Rows++
		for index, rule := range rules {
			masked := maskValue(opts.Salt, rule, record[index])
			if masked != record[index] {
				result.MaskedValues++
			}
			record[index] = masked
		}
		if err := writer.Write(record); err != nil {
			return Result{}, fmt.Errorf("write csv row %d: %w", result.Rows+1, err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return Result{}, fmt.Errorf("write csv output: %w", err)
	}
	return result, nil
}

type rule struct {
	Column   string
	Strategy string
}

func loadPlan(path string) (*plan.Document, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var doc plan.Document
	if err := yaml.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("parse config YAML: %w", err)
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("unsupported plan version %d", doc.Version)
	}
	return &doc, nil
}

func rulesForHeaders(doc *plan.Document, inputPath string, headers []string) (map[int]rule, error) {
	indexes := make(map[string]int, len(headers))
	for index, header := range headers {
		indexes[header] = index
	}
	rules := make(map[int]rule)
	for _, column := range doc.Columns {
		if column.Action == "review" {
			return nil, fmt.Errorf("column %s requires review before apply", column.Column)
		}
		if column.Action == "keep" {
			continue
		}
		if column.Action != "mask" {
			return nil, fmt.Errorf("unsupported action %q for column %s", column.Action, column.Column)
		}

		// Reject explicit directory-traversal attempts (e.g. "../data/customers.csv")
		// before the suffix-based input check, so a ".." segment cannot smuggle a
		// planned column into a different sibling file.
		if cleaned := filepath.Clean(column.Input); strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) || cleaned == ".." {
			return nil, fmt.Errorf("planned column %s input %q escapes the project directory", column.Column, column.Input)
		}
		if column.Input != "" && column.Input != inputPath && !strings.HasSuffix(inputPath, string(os.PathSeparator)+column.Input) {
			continue
		}
		index, ok := indexes[column.Column]
		if !ok {
			return nil, fmt.Errorf("planned column %s not found in CSV header", column.Column)
		}
		rules[index] = rule{Column: column.Column, Strategy: column.Strategy}
	}
	return rules, nil
}

// maskValue looks up the strategy registered for rule.Strategy and asks
// it to mask `value`. The HMAC digest is keyed on (column, strategy
// name, value) by strategy.Digest, so reclassifying a column under a
// different strategy name cannot collide with the previous category's
// output. If no strategy is registered (defensive: indicates a plan
// that escaped validation), fall back to the redaction-style prefix
// so the raw PII is never written through.
func maskValue(salt []byte, rule rule, value string) string {
	if value == "" {
		return value
	}
	digest := strategy.Digest(salt, rule.Column, rule.Strategy, value)
	s, ok := strategy.Get(rule.Strategy)
	if !ok {
		return "masked_" + digest[:16]
	}
	return s.Apply(digest, value)
}
