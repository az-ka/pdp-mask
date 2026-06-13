package apply

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/az-ka/pdp-mask/internal/detect"
	"github.com/az-ka/pdp-mask/internal/plan"
	"gopkg.in/yaml.v3"
)

const MinSaltLength = 16

type Options struct {
	InputPath  string
	PlanPath   string
	OutputPath string
	Salt       []byte
}

type Result struct {
	Rows          int
	MaskedColumns int
	MaskedValues  int
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
	doc, err := loadPlan(opts.PlanPath)
	if err != nil {
		return Result{}, err
	}
	input, err := os.Open(opts.InputPath)
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

	output, err := os.Create(opts.OutputPath)
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
	Type     string
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
		if column.Input != "" && column.Input != inputPath && !strings.HasSuffix(inputPath, column.Input) {
			continue
		}
		index, ok := indexes[column.Column]
		if !ok {
			return nil, fmt.Errorf("planned column %s not found in CSV header", column.Column)
		}
		rules[index] = rule{Column: column.Column, Type: column.Type, Strategy: column.Strategy}
	}
	return rules, nil
}

func maskValue(salt []byte, rule rule, value string) string {
	if value == "" {
		return value
	}
	digest := digestHex(salt, rule, value)
	switch rule.Strategy {
	case "deterministic_email":
		return "user_" + digest[:12] + "@example.invalid"
	case "deterministic_phone_id":
		return "081" + digitsFromHex(digest, 9)
	case "deterministic_nik":
		return digitsFromHex(digest, 16)
	case "deterministic_npwp":
		return formatLikeDigits(value, digitsFromHex(digest, countDigits(value)))
	case "deterministic_name_id":
		return fakeName(digest)
	case "deterministic_address_id":
		return "Jl. Masked " + digitsFromHex(digest, 3) + ", Kota Contoh"
	case "date_shift":
		return "1990-01-" + twoDigitDay(digest)
	case "deterministic_digits":
		return formatLikeDigits(value, digitsFromHex(digest, countDigits(value)))
	default:
		return "masked_" + digest[:16]
	}
}

func digestHex(salt []byte, rule rule, value string) string {
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(rule.Type))
	mac.Write([]byte{0x1f})
	mac.Write([]byte(rule.Column))
	mac.Write([]byte{0x1f})
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func digitsFromHex(hexValue string, length int) string {
	if length <= 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(length)
	for b.Len() < length {
		for _, r := range hexValue {
			if b.Len() == length {
				break
			}
			if r >= '0' && r <= '9' {
				b.WriteRune(r)
				continue
			}
			b.WriteByte(byte((r-'a')%10) + '0')
		}
	}
	return b.String()
}

func countDigits(value string) int {
	count := 0
	for _, r := range value {
		if r >= '0' && r <= '9' {
			count++
		}
	}
	return count
}

func formatLikeDigits(original, digits string) string {
	var b strings.Builder
	index := 0
	for _, r := range original {
		if r >= '0' && r <= '9' {
			if index < len(digits) {
				b.WriteByte(digits[index])
				index++
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func fakeName(digest string) string {
	first := []string{"Andi", "Rina", "Dewi", "Bima", "Maya", "Raka", "Nadia", "Fajar"}
	last := []string{"Pratama", "Wijaya", "Lestari", "Saputra", "Utami", "Santoso", "Permata", "Nugraha"}
	return first[int(digest[0])%len(first)] + " " + last[int(digest[1])%len(last)]
}

func twoDigitDay(digest string) string {
	day := int(digest[0])%28 + 1
	if day < 10 {
		return fmt.Sprintf("0%d", day)
	}
	return fmt.Sprintf("%d", day)
}

func CategoryRequiresSalt(category string) bool {
	switch category {
	case detect.CategoryEmail, detect.CategoryPhoneID, detect.CategoryNIK, detect.CategoryNPWP, detect.CategoryName, detect.CategoryAddress, detect.CategoryDateOfBirth, detect.CategoryBankAccount:
		return true
	default:
		return true
	}
}
