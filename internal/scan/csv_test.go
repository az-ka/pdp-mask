package scan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/az-ka/pdp-mask/internal/detect"
)

func TestScanCSVDetectsIndonesianPII(t *testing.T) {
	report, err := ScanCSV("../../testdata/customers_pii.csv", CSVOptions{SampleRows: 500})
	if err != nil {
		t.Fatalf("ScanCSV returned error: %v", err)
	}
	if got, want := report.Inputs[0].Rows, 3; got != want {
		t.Fatalf("rows = %d, want %d", got, want)
	}
	mustFinding(t, report, "email", detect.CategoryEmail, "high", "mask")
	mustFinding(t, report, "no_hp", detect.CategoryPhoneID, "high", "mask")
	mustFinding(t, report, "nik", detect.CategoryNIK, "high", "mask")
	mustFinding(t, report, "npwp", detect.CategoryNPWP, "high", "mask")
	mustFinding(t, report, "nama_lengkap", detect.CategoryName, "medium", "review")
	mustFinding(t, report, "alamat", detect.CategoryAddress, "high", "mask")
	mustFinding(t, report, "tgl_lahir", detect.CategoryDateOfBirth, "high", "mask")
	mustNotFinding(t, report, "id")
	mustNotFinding(t, report, "status")
	mustNotFinding(t, report, "created_at")
}

func TestScanCSVOperationalColumnsAreNotPII(t *testing.T) {
	report, err := ScanCSV("../../testdata/ops_false_positives.csv", CSVOptions{SampleRows: 500})
	if err != nil {
		t.Fatalf("ScanCSV returned error: %v", err)
	}
	for _, column := range []string{"id", "user_id", "order_id", "invoice_number", "amount", "total", "qty", "status", "type", "created_at", "updated_at", "reference_code"} {
		mustNotFinding(t, report, column)
	}
}

func TestScanCSVReportDoesNotContainRawValues(t *testing.T) {
	report, err := ScanCSV("../../testdata/customers_pii.csv", CSVOptions{SampleRows: 500})
	if err != nil {
		t.Fatalf("ScanCSV returned error: %v", err)
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	jsonText := string(payload)
	for _, raw := range []string{
		"siti.aminah@example.test",
		"0812-3456-7890",
		"3173054401010001",
		"12.345.678.9-012.000",
		"Siti Aminah",
		"Jl. Melati",
	} {
		if strings.Contains(jsonText, raw) {
			t.Fatalf("JSON report leaked raw value %q: %s", raw, jsonText)
		}
	}
}

func TestScanCSVMalformedInput(t *testing.T) {
	_, err := ScanCSV("../../testdata/malformed.csv", CSVOptions{SampleRows: 500})
	if err == nil {
		t.Fatal("ScanCSV returned nil error for malformed CSV")
	}
	if !strings.Contains(err.Error(), "read csv row") {
		t.Fatalf("error = %q, want row context", err.Error())
	}
}

func mustFinding(t *testing.T, report *Report, column, category, band, action string) {
	t.Helper()
	for _, finding := range report.Findings {
		if finding.Column == column && finding.Category == category {
			if finding.Band != band {
				t.Fatalf("%s/%s band = %s, want %s", column, category, finding.Band, band)
			}
			if finding.RecommendedAction != action {
				t.Fatalf("%s/%s action = %s, want %s", column, category, finding.RecommendedAction, action)
			}
			if len(finding.Evidence) == 0 {
				t.Fatalf("%s/%s has no evidence", column, category)
			}
			return
		}
	}
	t.Fatalf("missing finding for column=%s category=%s; findings=%+v", column, category, report.Findings)
}

func mustNotFinding(t *testing.T, report *Report, column string) {
	t.Helper()
	for _, finding := range report.Findings {
		if finding.Column == column {
			t.Fatalf("unexpected finding for column %s: %+v", column, finding)
		}
	}
}
