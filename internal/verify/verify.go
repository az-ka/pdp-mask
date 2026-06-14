package verify

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/az-ka/pdp-mask/internal/plan"
	"github.com/az-ka/pdp-mask/internal/scan"
	"github.com/az-ka/pdp-mask/internal/strategy"
	"gopkg.in/yaml.v3"
)

type Options struct {
	ConfigPath string
	InputPath  string
	OutputPath string
}

type VerificationResult struct {
	PlanPolicyStatus    string
	InputCoverageStatus string
	OutputLeakageStatus string
	ArtifactShapeStatus string
	StrategyValStatus   string
	Passed              bool
	Issues              []string
}

func Verify(opts Options) (*VerificationResult, error) {
	if opts.ConfigPath == "" {
		return nil, fmt.Errorf("config path is required")
	}
	if opts.InputPath == "" {
		return nil, fmt.Errorf("input path is required")
	}
	if opts.OutputPath == "" {
		return nil, fmt.Errorf("output path is required")
	}
	payload, err := os.ReadFile(opts.ConfigPath)
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

	result := &VerificationResult{
		PlanPolicyStatus:    "PASS",
		InputCoverageStatus: "PASS",
		OutputLeakageStatus: "PASS",
		ArtifactShapeStatus: "PASS",
		StrategyValStatus:   "PASS",
		Passed:              true,
	}

	fail := func(check *string, msg string) {
		*check = "FAIL"
		result.Passed = false
		result.Issues = append(result.Issues, msg)
	}
	planColumns := make(map[string]plan.ColumnPlan)
	for _, col := range doc.Columns {
		planColumns[col.Column] = col
		if col.Action == "review" {
			fail(&result.PlanPolicyStatus, fmt.Sprintf("column %q has unresolved action \"review\"", col.Column))
		}
		if col.Action == "mask" {
			if col.Strategy == "" {
				fail(&result.StrategyValStatus, fmt.Sprintf("mask column %q has empty strategy", col.Column))
			} else if _, ok := strategy.Get(col.Strategy); !ok && !strings.HasPrefix(col.Strategy, "masked_") {
				fail(&result.StrategyValStatus, fmt.Sprintf("column %q has unknown strategy %q", col.Column, col.Strategy))
			}
		}
	}

	inputReport, err := scan.ScanCSV(opts.InputPath, scan.CSVOptions{SampleRows: 500})
	if err != nil {
		return nil, fmt.Errorf("scan input CSV: %w", err)
	}

	for _, finding := range inputReport.Findings {
		colRule, planned := planColumns[finding.Column]
		if !planned {
			if finding.Band == "high" || finding.Band == "medium" {
				fail(&result.InputCoverageStatus, fmt.Sprintf("unclassified column %q (triggers %s PII finding)", finding.Column, finding.Band))
			}
		} else {
			if colRule.Action == "keep" || colRule.Action == "ignore" {
				if finding.Band == "high" {
					fail(&result.InputCoverageStatus, fmt.Sprintf("high confidence column %q kept without mask", finding.Column))
				}
			}
		}
	}

	outputReport, err := scan.ScanCSV(opts.OutputPath, scan.CSVOptions{SampleRows: 500})
	if err != nil {
		return nil, fmt.Errorf("scan safe CSV: %w", err)
	}

	inputHeaders, err := readCSVHeaders(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("read input headers: %w", err)
	}
	outputHeaders, err := readCSVHeaders(opts.OutputPath)
	if err != nil {
		return nil, fmt.Errorf("read output headers: %w", err)
	}
	if len(inputHeaders) != len(outputHeaders) {
		fail(&result.ArtifactShapeStatus, fmt.Sprintf("header count mismatch: got %d columns, want %d", len(outputHeaders), len(inputHeaders)))
	} else {
		for i, h := range inputHeaders {
			if h != outputHeaders[i] {
				fail(&result.ArtifactShapeStatus, fmt.Sprintf("header mismatch at index %d: got %q, want %q", i, outputHeaders[i], h))
			}
		}
	}

	inputRows, err := countCSVRows(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("count input rows: %w", err)
	}
	outputRows, err := countCSVRows(opts.OutputPath)
	if err != nil {
		return nil, fmt.Errorf("count output rows: %w", err)
	}
	if inputRows != outputRows {
		fail(&result.ArtifactShapeStatus, fmt.Sprintf("row count mismatch: got %d rows, want %d", outputRows, inputRows))
	}

	identicalCol, err := checkIdenticalMaskedColumns(opts.InputPath, opts.OutputPath, planColumns)
	if err != nil {
		return nil, err
	}
	if identicalCol != "" {
		fail(&result.OutputLeakageStatus, fmt.Sprintf("column %q is byte-identical in safe.csv (no-op mask leaked the original value)", identicalCol))
	}

	for _, finding := range outputReport.Findings {
		colRule, planned := planColumns[finding.Column]
		if planned && colRule.Action == "mask" {
			if finding.Band == "high" {
				isPlaceholder, err := verifyColumnPlaceholders(opts.OutputPath, finding.Column, colRule.Strategy)
				if err != nil {
					return nil, err
				}
				if !isPlaceholder {
					fail(&result.OutputLeakageStatus, fmt.Sprintf("column %q still triggers %s (%s) in safe.csv", finding.Column, finding.Category, finding.Band))
				}
			}
		}
	}

	return result, nil
}

func readCSVHeaders(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	return reader.Read()
}

func countCSVRows(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	if _, err := reader.Read(); err != nil {
		if err == io.EOF {
			return 0, nil
		}
		return 0, err
	}
	rows := 0
	for {
		_, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		rows++
	}
	return rows, nil
}

func checkIdenticalMaskedColumns(inputPath, outputPath string, planColumns map[string]plan.ColumnPlan) (string, error) {
	inputPayload, err := os.ReadFile(inputPath)
	if err != nil {
		return "", err
	}
	outputPayload, err := os.ReadFile(outputPath)
	if err != nil {
		return "", err
	}
	inputReader := csv.NewReader(bytes.NewReader(inputPayload))
	inputReader.FieldsPerRecord = -1
	inputHeaders, err := inputReader.Read()
	if err != nil {
		return "", err
	}

	outputReader := csv.NewReader(bytes.NewReader(outputPayload))
	outputReader.FieldsPerRecord = -1
	outputHeaders, err := outputReader.Read()
	if err != nil {
		return "", err
	}
	_ = outputHeaders

	maskCols := make(map[int]string)
	maskStrategies := make(map[int]strategy.Strategy)
	for idx, header := range inputHeaders {
		colRule, planned := planColumns[header]
		if planned && colRule.Action == "mask" {
			maskCols[idx] = header
			if s, ok := strategy.Get(colRule.Strategy); ok {
				maskStrategies[idx] = s
			}
		}
	}

	if len(maskCols) == 0 {
		return "", nil
	}

	nonEmptySeen := make(map[int]bool)
	differSeen := make(map[int]bool)

	for {
		inputRec, inputErr := inputReader.Read()
		outputRec, outputErr := outputReader.Read()

		if inputErr == io.EOF || outputErr == io.EOF {
			break
		}
		if inputErr != nil || outputErr != nil {
			return "", nil
		}

		for idx, colName := range maskCols {
			if idx >= len(inputRec) || idx >= len(outputRec) {
				continue
			}
			inVal := inputRec[idx]
			outVal := outputRec[idx]
			if inVal != "" {
				nonEmptySeen[idx] = true
			}
			if inVal != outVal {
				differSeen[idx] = true
				continue
			}
			if inVal == "" {
				continue
			}
			s, ok := maskStrategies[idx]
			if !ok {
				continue
			}
			if !s.WasChanged(inVal, outVal) {
				return colName, nil
			}
		}
	}

	for idx, colName := range maskCols {
		if nonEmptySeen[idx] && !differSeen[idx] {
			return colName, nil
		}
	}

	return "", nil
}

func verifyColumnPlaceholders(path, columnName, strategyName string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	headers, err := reader.Read()
	if err != nil {
		return false, err
	}
	colIdx := -1
	for idx, h := range headers {
		if h == columnName {
			colIdx = idx
			break
		}
	}
	if colIdx == -1 {
		return false, nil
	}

	s, ok := strategy.Get(strategyName)
	if !ok {
		return false, fmt.Errorf("unknown strategy %q", strategyName)
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, err
		}
		if colIdx >= len(record) {
			continue
		}
		val := record[colIdx]
		if val == "" {
			continue
		}
		if !s.Placeholder(val) {
			return false, nil
		}
	}
	return true, nil
}
