package scan

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/az-ka/pdp-mask/internal/detect"
)

type Input struct {
	Path       string `json:"path"`
	Format     string `json:"format"`
	Table      string `json:"table"`
	Rows       int    `json:"rows"`
	Columns    int    `json:"columns"`
	SampleRows int    `json:"sample_rows"`
}

type Summary struct {
	Findings int `json:"findings"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
}

type Report struct {
	Version  int              `json:"version"`
	Inputs   []Input          `json:"inputs"`
	Findings []detect.Finding `json:"findings"`
	Summary  Summary          `json:"summary"`
}

type CSVOptions struct {
	SampleRows int
}

func ScanCSV(path string, opts CSVOptions) (*Report, error) {
	if opts.SampleRows <= 0 {
		opts.SampleRows = 500
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open input: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1

	headers, err := reader.Read()
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("empty csv: %s", path)
		}
		return nil, fmt.Errorf("read csv header: %w", err)
	}
	if len(headers) == 0 {
		return nil, fmt.Errorf("empty csv header: %s", path)
	}
	headers = normalizeHeaders(headers)
	reader.FieldsPerRecord = len(headers)

	stats := make([]detect.ColumnStats, len(headers))
	for i, header := range headers {
		stats[i] = detect.NewColumnStats(header)
	}

	rows := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read csv row %d: %w", rows+2, err)
		}
		rows++
		for i, value := range record {
			if stats[i].Sampled >= opts.SampleRows {
				continue
			}
			detect.ObserveValue(&stats[i], value)
		}
	}

	table := tableName(path)
	findings := make([]detect.Finding, 0, len(headers))
	for _, columnStats := range stats {
		findings = append(findings, detect.AnalyzeColumn(path, table, columnStats)...)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Band != findings[j].Band {
			return bandRank(findings[i].Band) > bandRank(findings[j].Band)
		}
		if findings[i].Confidence != findings[j].Confidence {
			return findings[i].Confidence > findings[j].Confidence
		}
		if findings[i].Column != findings[j].Column {
			return findings[i].Column < findings[j].Column
		}
		return findings[i].Category < findings[j].Category
	})

	report := &Report{
		Version: 1,
		Inputs: []Input{{
			Path:       path,
			Format:     "csv",
			Table:      table,
			Rows:       rows,
			Columns:    len(headers),
			SampleRows: opts.SampleRows,
		}},
		Findings: findings,
	}
	for _, finding := range findings {
		report.Summary.Findings++
		switch finding.Band {
		case "high":
			report.Summary.High++
		case "medium":
			report.Summary.Medium++
		}
	}
	return report, nil
}

func normalizeHeaders(headers []string) []string {
	seen := make(map[string]int, len(headers))
	out := make([]string, len(headers))
	for i, header := range headers {
		trimmed := strings.TrimSpace(header)
		if trimmed == "" {
			trimmed = fmt.Sprintf("column_%d", i+1)
		}
		count := seen[trimmed]
		seen[trimmed] = count + 1
		if count > 0 {
			trimmed = fmt.Sprintf("%s_%d", trimmed, count+1)
		}
		out[i] = trimmed
	}
	return out
}

func tableName(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	if ext == "" {
		return base
	}
	return strings.TrimSuffix(base, ext)
}

func bandRank(band string) int {
	switch band {
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}
