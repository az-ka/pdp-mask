package detect

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const (
	CategoryEmail       = "email"
	CategoryPhoneID     = "phone_id"
	CategoryNIK         = "nik"
	CategoryNPWP        = "npwp"
	CategoryName        = "name"
	CategoryAddress     = "address"
	CategoryDateOfBirth = "date_of_birth"
	CategoryBankAccount = "bank_account"
)

type Finding struct {
	Input             string   `json:"input"`
	Table             string   `json:"table,omitempty"`
	Column            string   `json:"column"`
	Category          string   `json:"category"`
	Confidence        float64  `json:"confidence"`
	Band              string   `json:"band"`
	Sampled           int      `json:"sampled"`
	Matches           int      `json:"matches"`
	Evidence          []string `json:"evidence"`
	RecommendedAction string   `json:"recommended_action"`
}

type ColumnStats struct {
	Name     string
	Sampled  int
	Matches  map[string]int
	Evidence map[string][]string
}

func NewColumnStats(name string) ColumnStats {
	return ColumnStats{
		Name:     name,
		Matches:  make(map[string]int),
		Evidence: make(map[string][]string),
	}
}

func ObserveValue(stats *ColumnStats, value string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return
	}
	stats.Sampled++
	for _, match := range matchValue(trimmed) {
		stats.Matches[match.category]++
		addEvidence(stats.Evidence, match.category, match.evidence)
	}
}

func AnalyzeColumn(input, table string, stats ColumnStats) []Finding {
	columnSignals := columnSignals(stats.Name)
	categories := make(map[string]struct{}, len(columnSignals)+len(stats.Matches))
	for category := range columnSignals {
		categories[category] = struct{}{}
	}
	for category := range stats.Matches {
		categories[category] = struct{}{}
	}

	penalty := operationalPenalty(stats.Name)
	findings := make([]Finding, 0, len(categories))
	for category := range categories {
		columnScore, evidence := columnSignals[category].score, append([]string(nil), columnSignals[category].evidence...)
		matches := stats.Matches[category]
		valueScore := valueScore(category, matches, stats.Sampled)
		if matches > 0 {
			evidence = append(evidence, stats.Evidence[category]...)
		}
		score := columnScore + valueScore
		if penalty != 0 && columnScore == 0 && valueScore < 0.85 {
			score += penalty
			evidence = append(evidence, "negative_signal:operational_identifier")
		}
		if score > 0.99 {
			score = 0.99
		}
		if score < 0 {
			score = 0
		}
		band := band(score)
		if band == "low" {
			continue
		}
		findings = append(findings, Finding{
			Input:             input,
			Table:             table,
			Column:            stats.Name,
			Category:          category,
			Confidence:        round2(score),
			Band:              band,
			Sampled:           stats.Sampled,
			Matches:           matches,
			Evidence:          uniqueSorted(evidence),
			RecommendedAction: recommendedAction(band),
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Confidence != findings[j].Confidence {
			return findings[i].Confidence > findings[j].Confidence
		}
		return findings[i].Column < findings[j].Column
	})
	if len(findings) > 1 && findings[0].Band == "high" {
		return findings[:1]
	}
	return findings
}

type signal struct {
	score    float64
	evidence []string
}

type valueMatch struct {
	category string
	evidence string
}

var (
	emailRe = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$`)
	dateRe  = regexp.MustCompile(`^(?:\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4}|\d{2}-\d{2}-\d{4})$`)
)

func columnSignals(name string) map[string]signal {
	tokens := normalizeName(name)
	joined := strings.Join(tokens, "_")
	out := make(map[string]signal)
	add := func(category string, score float64, ev string) {
		current := out[category]
		if score > current.score {
			current.score = score
		}
		current.evidence = append(current.evidence, ev)
		out[category] = current
	}

	if hasAny(tokens, "email", "mail") || strings.Contains(joined, "alamat_email") {
		add(CategoryEmail, 0.62, "column_name:email")
	}
	if hasAny(tokens, "nik", "ktp") || strings.Contains(joined, "no_ktp") || strings.Contains(joined, "nomor_ktp") {
		add(CategoryNIK, 0.62, "column_name:nik")
	}
	if hasAny(tokens, "npwp") || strings.Contains(joined, "tax_id") {
		add(CategoryNPWP, 0.62, "column_name:npwp")
	}
	if hasAny(tokens, "phone", "telepon", "telp", "mobile", "whatsapp", "wa") || strings.Contains(joined, "no_hp") || strings.Contains(joined, "nomor_hp") {
		add(CategoryPhoneID, 0.58, "column_name:phone")
	}
	if hasAny(tokens, "nama", "name", "pemilik") || strings.Contains(joined, "full_name") || strings.Contains(joined, "first_name") || strings.Contains(joined, "last_name") || strings.Contains(joined, "ibu_kandung") {
		add(CategoryName, 0.58, "column_name:name")
	}
	if hasAny(tokens, "alamat", "address", "jalan", "kelurahan", "kecamatan", "kota", "kabupaten", "provinsi", "kodepos") || strings.Contains(joined, "kode_pos") {
		add(CategoryAddress, 0.58, "column_name:address")
	}
	if strings.Contains(joined, "tanggal_lahir") || strings.Contains(joined, "tgl_lahir") || strings.Contains(joined, "birth_date") || hasAny(tokens, "dob") {
		add(CategoryDateOfBirth, 0.62, "column_name:date_of_birth")
	}
	if strings.Contains(joined, "no_rekening") || strings.Contains(joined, "nomor_rekening") || strings.Contains(joined, "bank_account") || hasAny(tokens, "rekening") {
		add(CategoryBankAccount, 0.55, "column_name:bank_account")
	}
	return out
}

func matchValue(value string) []valueMatch {
	matches := make([]valueMatch, 0, 4)
	if emailRe.MatchString(value) {
		matches = append(matches, valueMatch{CategoryEmail, "value_pattern:email"})
	}
	digits := onlyDigits(value)
	if isIndonesianPhone(value, digits) {
		matches = append(matches, valueMatch{CategoryPhoneID, "value_pattern:phone_id"})
	}
	if isPossibleNIK(digits) {
		matches = append(matches, valueMatch{CategoryNIK, "value_pattern:nik"})
	}
	if isPossibleNPWP(digits) {
		matches = append(matches, valueMatch{CategoryNPWP, "value_pattern:npwp"})
	}
	if dateRe.MatchString(value) {
		matches = append(matches, valueMatch{CategoryDateOfBirth, "value_pattern:date"})
	}
	if looksLikeAddress(value) {
		matches = append(matches, valueMatch{CategoryAddress, "value_pattern:address_token"})
	}
	return matches
}

func valueScore(category string, matches, sampled int) float64 {
	if sampled == 0 || matches == 0 {
		return 0
	}
	ratio := float64(matches) / float64(sampled)
	weights := map[string]float64{
		CategoryEmail:       0.85,
		CategoryPhoneID:     0.80,
		CategoryNIK:         0.80,
		CategoryNPWP:        0.78,
		CategoryDateOfBirth: 0.45,
		CategoryAddress:     0.50,
		CategoryBankAccount: 0.50,
	}
	return weights[category] * ratio
}

func isIndonesianPhone(raw, digits string) bool {
	compact := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(raw, " ", ""), "-", ""))
	if strings.HasPrefix(compact, "+62") {
		return len(digits) >= 10 && len(digits) <= 15 && strings.HasPrefix(digits, "62")
	}
	if strings.HasPrefix(digits, "08") {
		return len(digits) >= 10 && len(digits) <= 14
	}
	if strings.HasPrefix(digits, "628") {
		return len(digits) >= 11 && len(digits) <= 15
	}
	return false
}

func isPossibleNIK(digits string) bool {
	if len(digits) != 16 || repeatedDigits(digits) {
		return false
	}
	day := atoi2(digits[6:8])
	month := atoi2(digits[8:10])
	return month >= 1 && month <= 12 && ((day >= 1 && day <= 31) || (day >= 41 && day <= 71))
}

func isPossibleNPWP(digits string) bool {
	if repeatedDigits(digits) {
		return false
	}
	return len(digits) == 15 || len(digits) == 16
}

func looksLikeAddress(value string) bool {
	lower := strings.ToLower(value)
	terms := []string{"jalan ", "jl ", "jl.", " gang ", "gg ", " rt", " rw", " kel", " kec", " kab", " kota ", " provinsi "}
	for _, term := range terms {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

func operationalPenalty(name string) float64 {
	tokens := normalizeName(name)
	joined := strings.Join(tokens, "_")
	if joined == "id" || strings.HasSuffix(joined, "_id") || hasAny(tokens, "count", "total", "amount", "qty", "status", "type", "invoice", "reference", "code", "number") || strings.Contains(joined, "created_at") || strings.Contains(joined, "updated_at") {
		return -0.60
	}
	return 0
}

func normalizeName(name string) []string {
	var b strings.Builder
	var prevLower bool
	for _, r := range name {
		if r == '_' || r == '-' || r == ' ' || r == '.' {
			b.WriteByte(' ')
			prevLower = false
			continue
		}
		if unicode.IsUpper(r) && prevLower {
			b.WriteByte(' ')
		}
		b.WriteRune(unicode.ToLower(r))
		prevLower = unicode.IsLower(r) || unicode.IsDigit(r)
	}
	return strings.Fields(b.String())
}

func hasAny(tokens []string, needles ...string) bool {
	for _, token := range tokens {
		for _, needle := range needles {
			if token == needle {
				return true
			}
		}
	}
	return false
}

func onlyDigits(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func repeatedDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := 1; i < len(value); i++ {
		if value[i] != value[0] {
			return false
		}
	}
	return true
}

func atoi2(value string) int {
	if len(value) != 2 {
		return 0
	}
	return int(value[0]-'0')*10 + int(value[1]-'0')
}

func addEvidence(evidence map[string][]string, category, item string) {
	for _, existing := range evidence[category] {
		if existing == item {
			return
		}
	}
	evidence[category] = append(evidence[category], item)
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := values[:0]
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func band(score float64) string {
	switch {
	case score >= 0.80:
		return "high"
	case score >= 0.50:
		return "medium"
	default:
		return "low"
	}
}

func recommendedAction(band string) string {
	if band == "high" {
		return "mask"
	}
	return "review"
}

func round2(value float64) float64 {
	return float64(int(value*100+0.5)) / 100
}
