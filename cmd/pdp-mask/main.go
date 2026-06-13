package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/az-ka/pdp-mask/internal/scan"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
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
	case "help", "--help", "-h":
		printUsage(os.Stdout)
		return nil
	default:
		printUsage(os.Stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func splitScanArgs(args []string) ([]string, []string) {
	flagArgs := make([]string, 0, len(args))
	inputs := make([]string, 0, 1)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if !strings.Contains(arg, "=") && scanFlagNeedsValue(arg) && i+1 < len(args) {
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
	case "--format", "-format", "--json", "-json", "--out", "-out", "--sample-rows", "-sample-rows", "--preset", "-preset":
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
	flagArgs, inputs := splitScanArgs(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
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
	resolvedFormat, err := resolveFormat(input, *format)
	if err != nil {
		return err
	}
	if resolvedFormat != "csv" {
		return fmt.Errorf("unsupported format %q", resolvedFormat)
	}
	report, err := scan.ScanCSV(input, scan.CSVOptions{SampleRows: *sampleRows})
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
	file, err := os.Create(path)
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

func printUsage(out *os.File) {
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  pdp-mask scan <file.csv> [--json report.json] [--sample-rows 500]")
}
