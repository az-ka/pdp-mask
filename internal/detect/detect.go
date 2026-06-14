package detect

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"

	"gopkg.in/yaml.v3"
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
	name     string
	category string
	evidence string
}

var (
	emailRe = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$`)
	dateRe  = regexp.MustCompile(`^(?:\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4}|\d{2}-\d{2}-\d{4})$`)
)

type Rule struct {
	Name           string   `yaml:"name"`
	Category       string   `yaml:"category"`
	ColumnPatterns []string `yaml:"column_patterns"`
	ValuePattern   string   `yaml:"value_pattern"`
	ValueWeight    float64  `yaml:"value_weight"`
	ColumnWeight   float64  `yaml:"column_weight"`
}

type Pack struct {
	Version int    `yaml:"version"`
	Name    string `yaml:"pack_name"`
	Rules   []Rule `yaml:"rules"`
}

var ActiveRules = []Rule{
	{
		Name:           "email",
		Category:       CategoryEmail,
		ColumnPatterns: []string{"email", "mail", "alamat_email"},
		ValuePattern:   `^[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$`,
		ValueWeight:    0.85,
		ColumnWeight:   0.62,
	},
	{
		Name:           "phone",
		Category:       CategoryPhoneID,
		ColumnPatterns: []string{"phone", "telepon", "telp", "mobile", "whatsapp", "wa", "no_hp", "nomor_hp"},
		ValuePattern:   `^(?:\+62|62|0)8[0-9]{8,12}$`,
		ValueWeight:    0.80,
		ColumnWeight:   0.58,
	},
	{
		Name:           "nik",
		Category:       CategoryNIK,
		ColumnPatterns: []string{"nik", "ktp", "no_ktp", "nomor_ktp"},
		ValuePattern:   `^[0-9]{16}$`,
		ValueWeight:    0.80,
		ColumnWeight:   0.62,
	},
	{
		Name:           "npwp",
		Category:       CategoryNPWP,
		ColumnPatterns: []string{"npwp", "tax_id"},
		ValuePattern:   `^[0-9]{15,16}$`,
		ValueWeight:    0.78,
		ColumnWeight:   0.62,
	},
	{
		Name:           "name",
		Category:       CategoryName,
		ColumnPatterns: []string{"nama", "name", "pemilik", "full_name", "first_name", "last_name", "ibu_kandung"},
		ColumnWeight:   0.58,
	},
	{
		Name:           "address",
		Category:       CategoryAddress,
		ColumnPatterns: []string{"alamat", "address", "jalan", "kelurahan", "kecamatan", "kota", "kabupaten", "provinsi", "kodepos", "kode_pos"},
		ValuePattern:   `jl`,
		ValueWeight:    0.50,
		ColumnWeight:   0.58,
	},
	{
		Name:           "date_of_birth",
		Category:       CategoryDateOfBirth,
		ColumnPatterns: []string{"tanggal_lahir", "tgl_lahir", "birth_date", "dob"},
		ValuePattern:   `dob`,
		ValueWeight:    0.45,
		ColumnWeight:   0.62,
	},
	{
		Name:           "bank_account",
		Category:       CategoryBankAccount,
		ColumnPatterns: []string{"rekening", "no_rekening", "nomor_rekening", "bank_account", "account_number"},
		ValuePattern:   `rekening`,
		ValueWeight:    0.50,
		ColumnWeight:   0.55,
	},
}

var (
	regexCacheMu sync.RWMutex
	regexCache   = make(map[string]*regexp.Regexp)
)

func getCachedRegex(pattern string) (*regexp.Regexp, error) {
	regexCacheMu.RLock()
	re, ok := regexCache[pattern]
	regexCacheMu.RUnlock()
	if ok {
		return re, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	regexCacheMu.Lock()
	regexCache[pattern] = re
	regexCacheMu.Unlock()
	return re, nil
}

// clearRegexCache drops every compiled pattern from the cache. It must be
// called whenever ActiveRules is replaced, so that patterns tied to retired
// rules cannot leak into later detections. Test-only callers should not rely
// on this; the race-detector test only needs the production path to be safe.
func clearRegexCache() {
	regexCacheMu.Lock()
	regexCache = make(map[string]*regexp.Regexp)
	regexCacheMu.Unlock()
}

func LoadRules(path string) error {
	payload, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read rules: %w", err)
	}
	var pack Pack
	if err := yaml.Unmarshal(payload, &pack); err != nil {
		return fmt.Errorf("parse rules YAML: %w", err)
	}
	if pack.Version != 1 {
		return fmt.Errorf("unsupported rules version %d", pack.Version)
	}
	ruleMap := make(map[string]Rule)
	for _, rule := range ActiveRules {
		ruleMap[rule.Name] = rule
	}
	for _, rule := range pack.Rules {
		if rule.ValuePattern != "" {
			if _, err := regexp.Compile(rule.ValuePattern); err != nil {
				return fmt.Errorf("rule %q has invalid value pattern regex %q: %w", rule.Name, rule.ValuePattern, err)
			}
		}
		ruleMap[rule.Name] = rule
	}
	newRules := make([]Rule, 0, len(ruleMap))
	for _, rule := range ruleMap {
		newRules = append(newRules, rule)
	}
	ActiveRules = newRules
	clearRegexCache()
	return nil
}

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
	for _, rule := range ActiveRules {
		if rule.ColumnWeight <= 0 {
			continue
		}
		matched := false
		for _, pattern := range rule.ColumnPatterns {
			patternTokens := normalizeName(pattern)
			patternJoined := strings.Join(patternTokens, "_")
			if hasAny(tokens, pattern) || strings.Contains(joined, patternJoined) {
				matched = true
				break
			}
		}
		if matched {
			add(rule.Category, rule.ColumnWeight, "column_name:"+rule.Name)
		}
	}
	return out
}

func matchValue(value string) []valueMatch {
	matches := make([]valueMatch, 0, 4)
	digits := onlyDigits(value)
	for _, rule := range ActiveRules {
		if rule.ValuePattern == "" {
			continue
		}
		matched := false
		switch rule.Name {
		case "email":
			matched = emailRe.MatchString(value)
		case "phone":
			matched = isIndonesianPhone(value, digits)
		case "nik":
			matched = isPossibleNIK(digits)
		case "npwp":
			matched = isPossibleNPWP(digits)
		case "date_of_birth":
			matched = dateRe.MatchString(value)
		case "address":
			matched = looksLikeAddress(value)
		default:
			re, err := getCachedRegex(rule.ValuePattern)
			if err == nil && re != nil {
				matched = re.MatchString(value)
			}
		}
		if matched {
			matches = append(matches, valueMatch{
				name:     rule.Name,
				category: rule.Category,
				evidence: "value_pattern:" + rule.Name,
			})
		}
	}
	return matches
}

func valueScore(category string, matches, sampled int) float64 {
	if sampled == 0 || matches == 0 {
		return 0
	}
	ratio := float64(matches) / float64(sampled)
	weight := 0.50
	for _, rule := range ActiveRules {
		if rule.Category == category && rule.ValueWeight > 0 {
			weight = rule.ValueWeight
			break
		}
	}
	return weight * ratio
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
