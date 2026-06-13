package plan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/az-ka/pdp-mask/internal/detect"
	"github.com/az-ka/pdp-mask/internal/scan"
)

func TestGeneratePlanFromScanReport(t *testing.T) {
	report := sampleReport(t)
	payload := marshalReport(t, report)
	doc, err := Generate(report, "scan.json", payload)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if got, want := len(doc.Columns), 7; got != want {
		t.Fatalf("columns = %d, want %d", got, want)
	}
	mustColumn(t, doc, "email", "mask", detect.CategoryEmail, "deterministic_email")
	mustColumn(t, doc, "no_hp", "mask", detect.CategoryPhoneID, "deterministic_phone_id")
	mustColumn(t, doc, "nik", "mask", detect.CategoryNIK, "deterministic_nik")
	mustColumn(t, doc, "npwp", "mask", detect.CategoryNPWP, "deterministic_npwp")
	mustColumn(t, doc, "alamat", "mask", detect.CategoryAddress, "deterministic_address_id")
	mustColumn(t, doc, "tgl_lahir", "mask", detect.CategoryDateOfBirth, "date_shift")
	mustColumn(t, doc, "nama_lengkap", "review", detect.CategoryName, "deterministic_name_id")
	if doc.Summary.Mask != 6 || doc.Summary.Review != 1 {
		t.Fatalf("summary = mask:%d review:%d, want mask:6 review:1", doc.Summary.Mask, doc.Summary.Review)
	}
}

func TestRenderYAMLDoesNotLeakRawValues(t *testing.T) {
	report := sampleReport(t)
	yaml := string(RenderYAML(mustGenerate(t, report)))
	for _, raw := range []string{
		"siti.aminah@example.test",
		"0812-3456-7890",
		"3173054401010001",
		"12.345.678.9-012.000",
		"Siti Aminah",
		"Jl. Melati",
		"1991-01-04",
	} {
		if strings.Contains(yaml, raw) {
			t.Fatalf("YAML leaked raw value %q:\n%s", raw, yaml)
		}
	}
}

func TestRenderYAMLDeterministic(t *testing.T) {
	report := sampleReport(t)
	first := string(RenderYAML(mustGenerate(t, report)))
	second := string(RenderYAML(mustGenerate(t, report)))
	if first != second {
		t.Fatalf("RenderYAML not deterministic\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestGenerateRejectsNonCSVInput(t *testing.T) {
	report := sampleReport(t)
	report.Inputs[0].Format = "postgres-dump"
	_, err := Generate(report, "scan.json", marshalReport(t, report))
	if err == nil {
		t.Fatal("Generate returned nil error for non-CSV input")
	}
	if !strings.Contains(err.Error(), "unsupported input format") {
		t.Fatalf("error = %q, want unsupported input format", err.Error())
	}
}

func sampleReport(t *testing.T) *scan.Report {
	t.Helper()
	report, err := scan.ScanCSV("../../testdata/customers_pii.csv", scan.CSVOptions{SampleRows: 500})
	if err != nil {
		t.Fatalf("ScanCSV returned error: %v", err)
	}
	return report
}

func mustGenerate(t *testing.T, report *scan.Report) *Document {
	t.Helper()
	doc, err := Generate(report, "scan.json", marshalReport(t, report))
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	return doc
}

func marshalReport(t *testing.T, report *scan.Report) []byte {
	t.Helper()
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	return payload
}

func mustColumn(t *testing.T, doc *Document, column, action, category, strategy string) {
	t.Helper()
	for _, planned := range doc.Columns {
		if planned.Column != column {
			continue
		}
		if planned.Action != action || planned.Type != category || planned.Strategy != strategy {
			t.Fatalf("column %s = action:%s type:%s strategy:%s, want action:%s type:%s strategy:%s", column, planned.Action, planned.Type, planned.Strategy, action, category, strategy)
		}
		if len(planned.Evidence) == 0 {
			t.Fatalf("column %s has no evidence", column)
		}
		return
	}
	t.Fatalf("missing planned column %s; doc=%+v", column, doc.Columns)
}
