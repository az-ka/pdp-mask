package detect

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
)

func TestLoadRulesAndDetect(t *testing.T) {
	tempDir := t.TempDir()
	rulesFile := filepath.Join(tempDir, "custom_rules.yml")
	ruleYAML := `version: 1
pack_name: custom
rules:
  - name: "custom_id"
    category: "custom_pii"
    column_patterns: ["my_secret_col"]
    value_pattern: "^SEC-[0-9]{4}$"
    value_weight: 0.90
    column_weight: 0.70
`
	if err := os.WriteFile(rulesFile, []byte(ruleYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	originalRules := append([]Rule(nil), ActiveRules...)
	defer func() {
		ActiveRules = originalRules
	}()

	if err := LoadRules(rulesFile); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	found := false
	for _, rule := range ActiveRules {
		if rule.Name == "custom_id" {
			found = true
			if rule.Category != "custom_pii" || rule.ColumnWeight != 0.70 {
				t.Fatalf("unexpected custom rule values: %+v", rule)
			}
			break
		}
	}
	if !found {
		t.Fatal("custom rule not found in ActiveRules")
	}

	signals := columnSignals("my_secret_col")
	sig, ok := signals["custom_pii"]
	if !ok {
		t.Fatal("missing custom_pii column signal")
	}
	if sig.score != 0.70 {
		t.Fatalf("column score = %f, want 0.70", sig.score)
	}

	matches := matchValue("SEC-1234")
	if len(matches) != 1 || matches[0].category != "custom_pii" {
		t.Fatalf("unexpected value matches: %+v", matches)
	}
}

func TestIsPossibleNIK(t *testing.T) {
	cases := []struct {
		name   string
		digits string
		want   bool
	}{
		{"empty", "", false},
		{"single_digit", "1", false},
		{"all_punctuation", "!@#$%^&*()", false},
		{"fifteen_digits", "320123150890003", false},
		{"seventeen_digits", "320123150890000123", false},
		{"sixteen_digits_repeated", "1111111111111111", false},
		{"sixteen_digits_invalid_month_zero", "3201230011900003", false},
		{"sixteen_digits_invalid_month_13", "3201231513900003", false},
		{"sixteen_digits_invalid_day_32", "3201233208900003", false},
		{"sixteen_digits_invalid_day_40", "3201234008900003", false},
		{"sixteen_digits_invalid_day_72", "3201237208900003", false},
		{"sixteen_digits_valid_male", "3201231508900003", true},
		{"sixteen_digits_valid_female_day_41", "3201234112900003", true},
		{"sixteen_digits_valid_female_day_71", "3201237108900003", true},
		{"sixteen_digits_valid_day_01_month_01", "3201230101900003", true},
		{"sixteen_digits_valid_day_31_month_12", "3201233112900003", true},
		{"unicode_digit_chars_ignored_by_onlyDigits", "\u0661\u0662\u0663", false},
		{"very_long_digits", "32012315089000031111222333444455556666777788889999", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := isPossibleNIK(tc.digits); got != tc.want {
				t.Fatalf("isPossibleNIK(%q) = %v, want %v", tc.digits, got, tc.want)
			}
		})
	}
}

func TestIsPossibleNPWP(t *testing.T) {
	cases := []struct {
		name   string
		digits string
		want   bool
	}{
		{"empty", "", false},
		{"single_digit", "1", false},
		{"fourteen_digits", "12345678901234", false},
		{"fifteen_digits_mixed", "123456789012345", true},
		{"sixteen_digits_mixed", "1234567890123456", true},
		{"fifteen_digits_repeated", "111111111111111", false},
		{"sixteen_digits_repeated", "1111111111111111", false},
		{"seventeen_digits", "12345678901234567", false},
		{"all_punctuation_input", "!@#$%^&*()", false},
		{"very_long_digits", "1234567890123456789012345", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := isPossibleNPWP(tc.digits); got != tc.want {
				t.Fatalf("isPossibleNPWP(%q) = %v, want %v", tc.digits, got, tc.want)
			}
		})
	}
}

func TestIsIndonesianPhone(t *testing.T) {
	cases := []struct {
		name   string
		raw    string
		digits string
		want   bool
	}{
		{"empty_raw", "", "", false},
		{"single_char", "a", "", false},
		{"all_punctuation", "!@#$%^&*()", "", false},
		{"plus62_too_short", "+62812", "62812", false},
		{"plus62_ten_digits", "+6281234567", "6281234567", true},
		{"plus62_eleven_digits", "+62812345678", "62812345678", true},
		{"plus62_fifteen_digits", "+628123456789012", "628123456789012", true},
		{"plus62_sixteen_digits", "+6281234567890123", "6281234567890123", false},
		{"zero8_nine_digits", "081234567", "081234567", false},
		{"zero8_ten_digits", "0812345678", "0812345678", true},
		{"zero8_fourteen_digits", "08123456789012", "08123456789012", true},
		{"zero8_fifteen_digits", "081234567890123", "081234567890123", false},
		{"zero62_eight_to_ten_digits", "6281234567", "6281234567", false},
		{"zero62_eleven_digits", "62812345678", "62812345678", true},
		{"zero62_fifteen_digits", "628123456789012", "628123456789012", true},
		{"zero62_sixteen_digits", "6281234567890123", "6281234567890123", false},
		{"unrelated_prefix", "71234567", "71234567", false},
		{"plus62_with_dashes_and_spaces", "+62 812-345-678", "62812345678", true},
		{"plus62_with_dots_and_dashes", "+62.812.345.678", "62812345678", true},
		{"plus62_with_nbsp_not_stripped", "+62\u00a0812", "62812", false},
		{"plus62_only_no_digits", "+62", "", false},
		{"very_long_digits", "0812345678901234567890", "0812345678901234567890", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := isIndonesianPhone(tc.raw, tc.digits); got != tc.want {
				t.Fatalf("isIndonesianPhone(%q, %q) = %v, want %v", tc.raw, tc.digits, got, tc.want)
			}
		})
	}
}

func TestLooksLikeAddress(t *testing.T) {
	// The function searches for substrings with explicit leading/trailing
	// spaces (" rt", " rw", " kel", " kec", " kab", " kota ", " provinsi ",
	// " gang ", " gg "), so a token at the start of the value (with no
	// preceding space) does NOT match on its own. Test cases below include
	// both matching phrases and explicit near-miss forms.
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"empty", "", false},
		{"single_char", "x", false},
		{"all_punctuation", "!@#$%^&*()", false},
		{"plain_text", "lorem ipsum dolor sit amet", false},
		{"contains_jalan", "Jalan Sudirman No. 1", true},
		{"contains_jl_period", "Jl. Sudirman No. 1", true},
		{"contains_jl_space", "Jl Sudirman Kavling 5", true},
		{"contains_gang_with_spaces", "Jl Gang Mawar No. 3", true},
		{"contains_gg_with_spaces", "Jl GG Mawar 12", true},
		{"contains_rt_with_leading_space", "Jl RT 001 RW 002", true},
		{"rt_alone_no_match", "RT001", false},
		{"rw_alone_no_match", "RW002", false},
		{"kel_within_phrase", "Jl Sukamaju Kel Sukamaju", true},
		{"kec_within_phrase", "Jl Kecamatan Cilandak, Jakarta", true},
		{"kab_within_phrase", "Jl Kabupaten Bogor, Jawa Barat", true},
		{"kota_within_phrase", "Jl Kota Bandung, 40115", true},
		{"kota_alone_no_match", "Kota", false},
		{"provinsi_within_phrase", "Jl Provinsi Jawa Barat", true},
		{"provinsi_alone_no_match", "Provinsi", false},
		{"unicode_address", "Jalan \u00d6nder", true},
		{"postal_code_only", "12345", false},
		{"address_with_postal_code", "Jl. Sudirman No.1, Jakarta 10110", true},
		{"very_long_address", "Jl. Sudirman No.1, Kelurahan Senayan, Kecamatan Tanah Abang, Kota Jakarta Pusat, Provinsi DKI Jakarta, 10110, Indonesia", true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeAddress(tc.value); got != tc.want {
				t.Fatalf("looksLikeAddress(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestOperationalPenalty(t *testing.T) {
	cases := []struct {
		name string
		col  string
		want float64
	}{
		{"empty", "", 0},
		{"plain_pii", "email", 0},
		{"plain_pii_phone", "phone", 0},
		{"name_column", "full_name", 0},
		{"bare_id", "id", -0.60},
		{"suffix_id", "user_id", -0.60},
		{"deep_suffix_id", "org_member_id", -0.60},
		{"count_token", "count", -0.60},
		{"total_token", "total", -0.60},
		{"amount_token", "total_amount", -0.60},
		{"qty_token", "qty", -0.60},
		{"status_token", "status", -0.60},
		{"type_token", "type", -0.60},
		{"invoice_token", "invoice_number", -0.60},
		{"reference_token", "reference", -0.60},
		{"code_token", "code", -0.60},
		{"number_token", "number", -0.60},
		{"created_at_contains", "created_at", -0.60},
		{"created_at_with_suffix", "created_at_ms", -0.60},
		{"updated_at_contains", "updated_at", -0.60},
		{"camelcase_idSuffix", "userId", -0.60},
		{"single_char_non_match", "x", 0},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := operationalPenalty(tc.col); got != tc.want {
				t.Fatalf("operationalPenalty(%q) = %v, want %v", tc.col, got, tc.want)
			}
		})
	}
}

func TestBand(t *testing.T) {
	cases := []struct {
		name  string
		score float64
		want  string
	}{
		{"zero", 0.0, "low"},
		{"just_below_medium", 0.49999, "low"},
		{"medium_floor", 0.50, "medium"},
		{"medium_mid", 0.65, "medium"},
		{"medium_ceiling", 0.7999, "medium"},
		{"high_floor", 0.80, "high"},
		{"high_mid", 0.90, "high"},
		{"high_ceiling", 0.99, "high"},
		{"above_ceiling_clamped_input", 1.5, "high"},
		{"negative_input_clamped", -0.10, "low"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := band(tc.score); got != tc.want {
				t.Fatalf("band(%v) = %q, want %q", tc.score, got, tc.want)
			}
		})
	}
}

func TestValueScore(t *testing.T) {
	originalRules := append([]Rule(nil), ActiveRules...)
	defer func() {
		ActiveRules = originalRules
	}()

	cases := []struct {
		name     string
		category string
		matches  int
		sampled  int
		want     float64
	}{
		{"zero_sampled", "email", 5, 0, 0},
		{"zero_matches", "email", 0, 10, 0},
		{"both_zero", "email", 0, 0, 0},
		{"email_full_ratio", "email", 10, 10, 0.85},
		{"email_half_ratio", "email", 5, 10, 0.425},
		{"phone_full_ratio", "phone_id", 3, 3, 0.80},
		{"nik_full_ratio", "nik", 1, 1, 0.80},
		{"npwp_full_ratio", "npwp", 1, 1, 0.78},
		{"unknown_category_falls_back_to_default_weight", "custom_unknown_category", 1, 1, 0.50},
		{"unknown_category_half_ratio", "custom_unknown_category", 1, 2, 0.25},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := valueScore(tc.category, tc.matches, tc.sampled); got != tc.want {
				t.Fatalf("valueScore(%q, %d, %d) = %v, want %v", tc.category, tc.matches, tc.sampled, got, tc.want)
			}
		})
	}
}

func TestNewColumnStats(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty_name", ""},
		{"typical_email_column", "email"},
		{"unicode_column", "ema\u00edl"},
		{"very_long_column", "some_extremely_long_column_name_with_many_underscores_and_tokens"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			stats := NewColumnStats(tc.input)
			if stats.Name != tc.input {
				t.Fatalf("Name = %q, want %q", stats.Name, tc.input)
			}
			if stats.Sampled != 0 {
				t.Fatalf("Sampled = %d, want 0", stats.Sampled)
			}
			if stats.Matches == nil {
				t.Fatal("Matches map is nil; want initialized empty map")
			}
			if len(stats.Matches) != 0 {
				t.Fatalf("Matches size = %d, want 0", len(stats.Matches))
			}
			if stats.Evidence == nil {
				t.Fatal("Evidence map is nil; want initialized empty map")
			}
			if len(stats.Evidence) != 0 {
				t.Fatalf("Evidence size = %d, want 0", len(stats.Evidence))
			}

			// Verify the maps are usable (no panic on assignment) and that
			// the maps are independent across calls.
			stats.Matches["x"] = 1
			stats.Evidence["x"] = []string{"e"}
			other := NewColumnStats("other")
			if _, exists := other.Matches["x"]; exists {
				t.Fatal("Matches map shared between stats instances")
			}
			if _, exists := other.Evidence["x"]; exists {
				t.Fatal("Evidence map shared between stats instances")
			}
		})
	}
}

func TestObserveValue(t *testing.T) {
	originalRules := append([]Rule(nil), ActiveRules...)
	originalCache := snapshotRegexCache()
	defer func() {
		ActiveRules = originalRules
		restoreRegexCache(originalCache)
	}()

	t.Run("empty_value_does_not_increment_sampled", func(t *testing.T) {
		stats := NewColumnStats("notes")
		ObserveValue(&stats, "")
		if stats.Sampled != 0 {
			t.Fatalf("Sampled = %d, want 0", stats.Sampled)
		}
		if len(stats.Matches) != 0 {
			t.Fatalf("Matches size = %d, want 0", len(stats.Matches))
		}
	})

	t.Run("whitespace_only_value_does_not_increment_sampled", func(t *testing.T) {
		stats := NewColumnStats("notes")
		ObserveValue(&stats, "   \t\n")
		if stats.Sampled != 0 {
			t.Fatalf("Sampled = %d, want 0", stats.Sampled)
		}
	})

	t.Run("email_value_increments_email_match", func(t *testing.T) {
		stats := NewColumnStats("email")
		ObserveValue(&stats, "user@example.com")
		if stats.Sampled != 1 {
			t.Fatalf("Sampled = %d, want 1", stats.Sampled)
		}
		if got := stats.Matches[CategoryEmail]; got != 1 {
			t.Fatalf("Matches[email] = %d, want 1", got)
		}
	})

	t.Run("phone_value_increments_phone_match", func(t *testing.T) {
		stats := NewColumnStats("phone")
		ObserveValue(&stats, "081234567890")
		if stats.Sampled != 1 {
			t.Fatalf("Sampled = %d, want 1", stats.Sampled)
		}
		if got := stats.Matches[CategoryPhoneID]; got != 1 {
			t.Fatalf("Matches[phone_id] = %d, want 1", got)
		}
	})

	t.Run("nik_value_increments_nik_match", func(t *testing.T) {
		stats := NewColumnStats("nik")
		ObserveValue(&stats, "3201231508900003")
		if stats.Sampled != 1 {
			t.Fatalf("Sampled = %d, want 1", stats.Sampled)
		}
		if got := stats.Matches[CategoryNIK]; got != 1 {
			t.Fatalf("Matches[nik] = %d, want 1", got)
		}
	})

	t.Run("npwp_value_increments_npwp_match", func(t *testing.T) {
		stats := NewColumnStats("npwp")
		ObserveValue(&stats, "123456789012345")
		if stats.Sampled != 1 {
			t.Fatalf("Sampled = %d, want 1", stats.Sampled)
		}
		if got := stats.Matches[CategoryNPWP]; got != 1 {
			t.Fatalf("Matches[npwp] = %d, want 1", got)
		}
	})

	t.Run("non_matching_value_increments_sampled_only", func(t *testing.T) {
		stats := NewColumnStats("notes")
		ObserveValue(&stats, "lorem ipsum dolor sit amet")
		if stats.Sampled != 1 {
			t.Fatalf("Sampled = %d, want 1", stats.Sampled)
		}
		if len(stats.Matches) != 0 {
			t.Fatalf("Matches size = %d, want 0", len(stats.Matches))
		}
	})

	t.Run("repeated_calls_accumulate", func(t *testing.T) {
		stats := NewColumnStats("email")
		values := []string{
			"alice@example.com",
			"bob@example.com",
			"not-an-email",
			"carol@example.com",
			"   ",
		}
		for _, v := range values {
			ObserveValue(&stats, v)
		}
		if stats.Sampled != 4 {
			t.Fatalf("Sampled = %d, want 4 (whitespace-only is skipped)", stats.Sampled)
		}
		if got := stats.Matches[CategoryEmail]; got != 3 {
			t.Fatalf("Matches[email] = %d, want 3", got)
		}
	})
}

func TestAnalyzeColumn(t *testing.T) {
	originalRules := append([]Rule(nil), ActiveRules...)
	originalCache := snapshotRegexCache()
	defer func() {
		ActiveRules = originalRules
		restoreRegexCache(originalCache)
	}()

	t.Run("email_column_full_match_yields_high_finding", func(t *testing.T) {
		stats := NewColumnStats("email")
		emails := []string{
			"alice@example.com",
			"bob@example.org",
			"carol@example.net",
			"dave@example.io",
			"eve@example.co.id",
		}
		for _, v := range emails {
			ObserveValue(&stats, v)
		}
		findings := AnalyzeColumn("customers.csv", "customers", stats)
		if len(findings) != 1 {
			t.Fatalf("len(findings) = %d, want 1: %+v", len(findings), findings)
		}
		f := findings[0]
		if f.Category != CategoryEmail {
			t.Fatalf("Category = %q, want %q", f.Category, CategoryEmail)
		}
		if f.Column != "email" {
			t.Fatalf("Column = %q, want %q", f.Column, "email")
		}
		if f.Band != "high" {
			t.Fatalf("Band = %q, want high", f.Band)
		}
		if f.Confidence < 0.80 {
			t.Fatalf("Confidence = %v, want >= 0.80", f.Confidence)
		}
		if f.Sampled != 5 || f.Matches != 5 {
			t.Fatalf("Sampled/Matches = %d/%d, want 5/5", f.Sampled, f.Matches)
		}
		if f.RecommendedAction != "mask" {
			t.Fatalf("RecommendedAction = %q, want mask", f.RecommendedAction)
		}
		if f.Input != "customers.csv" || f.Table != "customers" {
			t.Fatalf("Input/Table = %q/%q, want customers.csv/customers", f.Input, f.Table)
		}
		if len(f.Evidence) == 0 {
			t.Fatal("Evidence is empty; want at least one item")
		}
	})

	t.Run("phone_column_full_match_yields_high_finding", func(t *testing.T) {
		stats := NewColumnStats("phone")
		phones := []string{
			"081234567890",
			"081234567891",
			"081234567892",
		}
		for _, v := range phones {
			ObserveValue(&stats, v)
		}
		findings := AnalyzeColumn("contacts.csv", "contacts", stats)
		if len(findings) != 1 {
			t.Fatalf("len(findings) = %d, want 1: %+v", len(findings), findings)
		}
		f := findings[0]
		if f.Category != CategoryPhoneID {
			t.Fatalf("Category = %q, want %q", f.Category, CategoryPhoneID)
		}
		if f.Band != "high" {
			t.Fatalf("Band = %q, want high", f.Band)
		}
	})

	t.Run("operational_id_column_with_nik_values_is_suppressed", func(t *testing.T) {
		// Column "user_id" triggers operationalPenalty (-0.60). With valueScore
		// < 0.85 the score is reduced below the medium band, so no finding is
		// produced for the NIK category even though every value is a valid NIK.
		stats := NewColumnStats("user_id")
		niks := []string{
			"3201231508900003",
			"3201231508900004",
			"3201231508900005",
			"3201231508900006",
		}
		for _, v := range niks {
			ObserveValue(&stats, v)
		}
		findings := AnalyzeColumn("users.csv", "users", stats)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings due to operational penalty, got %+v", findings)
		}
	})

	t.Run("non_pii_column_yields_no_findings", func(t *testing.T) {
		stats := NewColumnStats("notes")
		values := []string{
			"lorem ipsum dolor sit amet",
			"consectetur adipiscing elit",
			"sed do eiusmod tempor",
		}
		for _, v := range values {
			ObserveValue(&stats, v)
		}
		findings := AnalyzeColumn("misc.csv", "misc", stats)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for non-PII column, got %+v", findings)
		}
	})

	t.Run("high_band_first_finding_truncates_others", func(t *testing.T) {
		// Column "email_phone" matches both email and phone column patterns.
		// With every value being an email, email becomes high band and any
		// additional medium-or-higher finding must be truncated to keep only
		// the top one.
		stats := NewColumnStats("email_phone")
		emails := []string{
			"alice@example.com",
			"bob@example.org",
			"carol@example.net",
			"dave@example.io",
		}
		for _, v := range emails {
			ObserveValue(&stats, v)
		}
		findings := AnalyzeColumn("combined.csv", "combined", stats)
		if len(findings) != 1 {
			t.Fatalf("len(findings) = %d, want 1 due to high-band truncation: %+v", len(findings), findings)
		}
		if findings[0].Category != CategoryEmail {
			t.Fatalf("Category = %q, want %q", findings[0].Category, CategoryEmail)
		}
		if findings[0].Band != "high" {
			t.Fatalf("Band = %q, want high", findings[0].Band)
		}
	})
}

// snapshotRegexCache returns a copy of regexCache contents for restoration.
func snapshotRegexCache() map[string]*regexp.Regexp {
	out := make(map[string]*regexp.Regexp, len(regexCache))
	for k, v := range regexCache {
		out[k] = v
	}
	return out
}

// restoreRegexCache replaces the global regexCache with a snapshot. It is the
// inverse of snapshotRegexCache and is used to keep tests self-contained even
// when prior tests populated the cache via getCachedRegex.
func restoreRegexCache(snap map[string]*regexp.Regexp) {
	regexCache = make(map[string]*regexp.Regexp, len(snap))
	for k, v := range snap {
		regexCache[k] = v
	}
}

// TestDetectRace asserts that concurrent AnalyzeColumn calls over the same
// column do not race on the global regex cache. The test populates the cache
// with a custom rule that goes through the default-branch getCachedRegex path
// and then runs N goroutines that all call AnalyzeColumn for the same column
// using varied values. Run under `go test -race` to catch any unsynchronized
// map access.
func TestDetectRace(t *testing.T) {
	const goroutines = 16

	originalRules := append([]Rule(nil), ActiveRules...)
	originalCache := snapshotRegexCache()
	defer func() {
		ActiveRules = originalRules
		restoreRegexCache(originalCache)
	}()

	// Replace ActiveRules with a single custom rule that exercises the
	// default-branch path (getCachedRegex) for every value. Using a name
	// that is not "email"/"phone"/"nik"/"npwp"/"date_of_birth"/"address"
	// forces matchValue into the cached-regex branch.
	ActiveRules = []Rule{
		{
			Name:           "race_rule",
			Category:       "race_cat",
			ColumnPatterns: []string{"race_col"},
			ValuePattern:   `^R-[0-9]+$`,
			ValueWeight:    0.80,
			ColumnWeight:   0.60,
		},
	}

	values := make([]string, 64)
	for i := range values {
		values[i] = fmt.Sprintf("R-%d", i)
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed int) {
			defer wg.Done()
			stats := NewColumnStats("race_col")
			// Each goroutine processes the full value list, picking a
			// different starting offset to maximize interleaving.
			for i := 0; i < len(values); i++ {
				v := values[(i+seed)%len(values)]
				ObserveValue(&stats, v)
			}
			findings := AnalyzeColumn("race.csv", "race", stats)
			if len(findings) != 1 {
				errs <- fmt.Errorf("goroutine %d: got %d findings, want 1", seed, len(findings))
				return
			}
			if findings[0].Category != "race_cat" {
				errs <- fmt.Errorf("goroutine %d: category = %q, want %q", seed, findings[0].Category, "race_cat")
				return
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestLoadRulesInvalidatesCache asserts that calling LoadRules with a new
// rule set drops any compiled patterns that the previous ActiveRules
// populated through getCachedRegex, so matchValue afterward compiles the
// new rule's pattern instead of returning a stale entry.
func TestLoadRulesInvalidatesCache(t *testing.T) {
	tempDir := t.TempDir()
	rulesFile := filepath.Join(tempDir, "swap_rules.yml")
	ruleYAML := `version: 1
pack_name: swap
rules:
  - name: "newrule"
    category: "new_cat"
    column_patterns: ["new_col"]
    value_pattern: "^OLD-[0-9]+$"
    value_weight: 0.90
    column_weight: 0.70
`
	if err := os.WriteFile(rulesFile, []byte(ruleYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	originalRules := append([]Rule(nil), ActiveRules...)
	originalCache := snapshotRegexCache()
	defer func() {
		ActiveRules = originalRules
		restoreRegexCache(originalCache)
	}()

// Set up the OLD rule directly (no LoadRules yet) and prime the cache
// by calling matchValue once.
ActiveRules = []Rule{
	{
		Name:           "oldrule",
		Category:       "old_cat",
		ColumnPatterns: []string{"old_col"},
		ValuePattern:   `^OLD-[0-9]+$`,
		ValueWeight:    0.80,
		ColumnWeight:   0.60,
	},
}
	matches := matchValue("OLD-1")
	if len(matches) != 1 || matches[0].category != "old_cat" {
		t.Fatalf("pre-swap matchValue: got %+v, want one match with category old_cat", matches)
	}

	// Verify the OLD pattern is in the cache. We use the production cache
	// helper getCachedRegex to peek: it returns the compiled regex without
	// disturbing the cache contents. To make the test runnable both before
	// and after the mutex change, we only read what we wrote — getCachedRegex
	// for the OLD pattern must succeed.
	if _, err := getCachedRegex(`^OLD-[0-9]+$`); err != nil {
		t.Fatalf("getCachedRegex(OLD pattern) failed: %v", err)
	}
	if !cacheHas(`^OLD-[0-9]+$`) {
		t.Fatal("expected OLD pattern to be cached after pre-swap matchValue")
	}

	// LoadRules replaces ActiveRules with the newrule rule set, which uses
	// the same ValuePattern but a different Name and Category. After this
	// call, the cache must no longer contain the OLD pattern. We clear
	// ActiveRules first so LoadRules' merge step does not also retain
	// oldrule; we want a clean swap so we can prove the new rule fires.
	ActiveRules = nil
	if err := LoadRules(rulesFile); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	if cacheHas(`^OLD-[0-9]+$`) {
		t.Fatal("regexCache still contains the OLD pattern after LoadRules; cache was not invalidated")
	}
	if cacheSize() != 0 {
		t.Fatalf("regexCache size = %d after LoadRules, want 0 (full clear)", cacheSize())
	}

	// And matchValue must now dispatch to the new rule, not the old one.
	matches = matchValue("OLD-1")
	if len(matches) != 1 {
		t.Fatalf("post-swap matchValue: got %d matches, want 1", len(matches))
	}
	if matches[0].category != "new_cat" {
		t.Fatalf("post-swap matchValue category = %q, want %q", matches[0].category, "new_cat")
	}
	if matches[0].name != "newrule" {
		t.Fatalf("post-swap matchValue name = %q, want %q", matches[0].name, "newrule")
	}
}

// TestMatchValueDispatchesByRuleName asserts that when two ActiveRules share
// the same ValuePattern but have different Names, matchValue emits a
// separate valueMatch for each, and each carries its own Name. This
// guarantees downstream consumers can tell which rule fired.
func TestMatchValueDispatchesByRuleName(t *testing.T) {
	originalRules := append([]Rule(nil), ActiveRules...)
	originalCache := snapshotRegexCache()
	defer func() {
		ActiveRules = originalRules
		restoreRegexCache(originalCache)
	}()

	sharedPattern := `^X-[0-9]+$`
	ActiveRules = []Rule{
		{
			Name:           "rule_a",
			Category:       "cat_a",
			ColumnPatterns: []string{"col_a"},
			ValuePattern:   sharedPattern,
			ValueWeight:    0.80,
			ColumnWeight:   0.60,
		},
		{
			Name:           "rule_b",
			Category:       "cat_b",
			ColumnPatterns: []string{"col_b"},
			ValuePattern:   sharedPattern,
			ValueWeight:    0.80,
			ColumnWeight:   0.60,
		},
		{
			// Different pattern: must NOT match "X-1" and must NOT appear
			// in the result.
			Name:           "rule_c",
			Category:       "cat_c",
			ColumnPatterns: []string{"col_c"},
			ValuePattern:   `^Y-[0-9]+$`,
			ValueWeight:    0.80,
			ColumnWeight:   0.60,
		},
	}

	matches := matchValue("X-1")
	if len(matches) != 2 {
		t.Fatalf("matchValue: got %d matches, want 2: %+v", len(matches), matches)
	}
	// Order is the order of ActiveRules, so rule_a first, then rule_b.
	if matches[0].name != "rule_a" || matches[0].category != "cat_a" {
		t.Errorf("matches[0] = %+v, want name=rule_a category=cat_a", matches[0])
	}
	if matches[1].name != "rule_b" || matches[1].category != "cat_b" {
		t.Errorf("matches[1] = %+v, want name=rule_b category=cat_b", matches[1])
	}
	// Categories must be distinct so the downstream counter and evidence
	// map do not collapse the two rules into one bucket.
	if matches[0].category == matches[1].category {
		t.Errorf("two rules produced the same category %q; rule dispatch is ambiguous", matches[0].category)
	}
}

// cacheHas reports whether regexCache contains an entry for the given
// pattern. It is a serial test helper; do not call it while other
// goroutines may be mutating regexCache.
func cacheHas(pattern string) bool {
	for k := range regexCache {
		if k == pattern {
			return true
		}
	}
	return false
}

// cacheSize returns the number of entries in regexCache. Serial test
// helper only.
func cacheSize() int {
	return len(regexCache)
}
