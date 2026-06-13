package plan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/az-ka/pdp-mask/internal/detect"
	"github.com/az-ka/pdp-mask/internal/scan"
)

type Source struct {
	Scan       string
	ScanSHA256 string
}

type ColumnPlan struct {
	Input      string
	Table      string
	Column     string
	Action     string
	Type       string
	Strategy   string
	Confidence string
	Score      float64
	Sampled    int
	Matches    int
	Evidence   []string
}

type ActionSummary struct {
	Mask   int
	Review int
}

type Document struct {
	Version  int
	Source   Source
	Inputs   []scan.Input
	Columns  []ColumnPlan
	Summary  ActionSummary
	Findings int
}

func Generate(report *scan.Report, sourcePath string, sourceBytes []byte) (*Document, error) {
	if report == nil {
		return nil, fmt.Errorf("nil scan report")
	}
	if report.Version != 1 {
		return nil, fmt.Errorf("unsupported scan report version %d", report.Version)
	}
	for _, input := range report.Inputs {
		if input.Format != "csv" {
			return nil, fmt.Errorf("unsupported input format %q for %s", input.Format, input.Path)
		}
	}
	doc := &Document{
		Version:  1,
		Source:   Source{Scan: sourcePath, ScanSHA256: hashHex(sourceBytes)},
		Inputs:   append([]scan.Input(nil), report.Inputs...),
		Findings: len(report.Findings),
	}
	doc.Columns = make([]ColumnPlan, 0, len(report.Findings))
	for _, finding := range report.Findings {
		column := ColumnPlan{
			Input:      finding.Input,
			Table:      finding.Table,
			Column:     finding.Column,
			Action:     actionFor(finding),
			Type:       finding.Category,
			Strategy:   strategyFor(finding.Category),
			Confidence: finding.Band,
			Score:      finding.Confidence,
			Sampled:    finding.Sampled,
			Matches:    finding.Matches,
			Evidence:   append([]string(nil), finding.Evidence...),
		}
		sort.Strings(column.Evidence)
		doc.Columns = append(doc.Columns, column)
	}
	sort.Slice(doc.Columns, func(i, j int) bool {
		left, right := doc.Columns[i], doc.Columns[j]
		if left.Input != right.Input {
			return left.Input < right.Input
		}
		if left.Table != right.Table {
			return left.Table < right.Table
		}
		if left.Column != right.Column {
			return left.Column < right.Column
		}
		return left.Type < right.Type
	})
	for _, column := range doc.Columns {
		switch column.Action {
		case "mask":
			doc.Summary.Mask++
		case "review":
			doc.Summary.Review++
		}
	}
	return doc, nil
}

func RenderYAML(doc *Document) []byte {
	var b bytes.Buffer
	b.WriteString("version: 1\n")
	b.WriteString("source:\n")
	writeKV(&b, 2, "scan", doc.Source.Scan)
	writeKV(&b, 2, "scan_sha256", doc.Source.ScanSHA256)
	b.WriteString("inputs:\n")
	for _, input := range doc.Inputs {
		b.WriteString("  - path: ")
		b.WriteString(quoteYAML(input.Path))
		b.WriteByte('\n')
		writeKV(&b, 4, "format", input.Format)
		writeKV(&b, 4, "table", input.Table)
		writeInt(&b, 4, "rows", input.Rows)
		writeInt(&b, 4, "columns", input.Columns)
	}
	b.WriteString("columns:\n")
	for _, column := range doc.Columns {
		b.WriteString("  - input: ")
		b.WriteString(quoteYAML(column.Input))
		b.WriteByte('\n')
		writeKV(&b, 4, "table", column.Table)
		writeKV(&b, 4, "column", column.Column)
		writeKV(&b, 4, "action", column.Action)
		writeKV(&b, 4, "type", column.Type)
		writeKV(&b, 4, "strategy", column.Strategy)
		writeKV(&b, 4, "confidence", column.Confidence)
		writeFloat(&b, 4, "score", column.Score)
		writeInt(&b, 4, "sampled", column.Sampled)
		writeInt(&b, 4, "matches", column.Matches)
		b.WriteString("    evidence:\n")
		for _, evidence := range column.Evidence {
			b.WriteString("      - ")
			b.WriteString(quoteYAML(evidence))
			b.WriteByte('\n')
		}
	}
	b.WriteString("summary:\n")
	writeInt(&b, 2, "inputs", len(doc.Inputs))
	writeInt(&b, 2, "findings", doc.Findings)
	b.WriteString("  actions:\n")
	writeInt(&b, 4, "mask", doc.Summary.Mask)
	writeInt(&b, 4, "review", doc.Summary.Review)
	return b.Bytes()
}

func actionFor(finding detect.Finding) string {
	if finding.Band == "high" || finding.RecommendedAction == "mask" {
		return "mask"
	}
	return "review"
}

func strategyFor(category string) string {
	switch category {
	case detect.CategoryEmail:
		return "deterministic_email"
	case detect.CategoryPhoneID:
		return "deterministic_phone_id"
	case detect.CategoryNIK:
		return "deterministic_nik"
	case detect.CategoryNPWP:
		return "deterministic_npwp"
	case detect.CategoryName:
		return "deterministic_name_id"
	case detect.CategoryAddress:
		return "deterministic_address_id"
	case detect.CategoryDateOfBirth:
		return "date_shift"
	case detect.CategoryBankAccount:
		return "deterministic_digits"
	default:
		return "deterministic_redaction"
	}
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeKV(b *bytes.Buffer, indent int, key, value string) {
	writeIndent(b, indent)
	b.WriteString(key)
	b.WriteString(": ")
	b.WriteString(quoteYAML(value))
	b.WriteByte('\n')
}

func writeInt(b *bytes.Buffer, indent int, key string, value int) {
	writeIndent(b, indent)
	b.WriteString(key)
	b.WriteString(": ")
	b.WriteString(strconv.Itoa(value))
	b.WriteByte('\n')
}

func writeFloat(b *bytes.Buffer, indent int, key string, value float64) {
	writeIndent(b, indent)
	b.WriteString(key)
	b.WriteString(": ")
	b.WriteString(strconv.FormatFloat(value, 'f', 2, 64))
	b.WriteByte('\n')
}

func writeIndent(b *bytes.Buffer, indent int) {
	for i := 0; i < indent; i++ {
		b.WriteByte(' ')
	}
}

func quoteYAML(value string) string {
	return strconv.Quote(strings.ReplaceAll(value, "\r\n", "\n"))
}
