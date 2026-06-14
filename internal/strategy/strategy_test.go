package strategy

import (
	"encoding/hex"
	"strings"
	"testing"
)

// ab32 is a 64-char digest that makes DigitsFromHex and the name/day
// selectors easy to verify by hand. 'a' (0x61) maps to '0' under
// (r-'a')%10+'0', and 'b' (0x62) maps to '1'. So ab32 → "01" repeated
// 32 times.
const ab32 = "abababababababababababababababababababababababababababababababab"

func mustDigest(t *testing.T, salt []byte, column, name, value string) string {
	t.Helper()
	got := Digest(salt, column, name, value)
	if len(got) != 64 {
		t.Fatalf("Digest length = %d, want 64 hex chars", len(got))
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("Digest not valid hex: %v", err)
	}
	return got
}

func TestDigestDeterministic(t *testing.T) {
	salt := []byte("0123456789abcdef")
	a := Digest(salt, "email", "deterministic_email", "user@example.com")
	b := Digest(salt, "email", "deterministic_email", "user@example.com")
	if a != b {
		t.Fatalf("Digest not deterministic: %s vs %s", a, b)
	}
}

func TestDigestChangesWithName(t *testing.T) {
	salt := []byte("0123456789abcdef")
	col := "email"
	val := "user@example.com"
	if Digest(salt, col, "deterministic_email", val) ==
		Digest(salt, col, "deterministic_redaction", val) {
		t.Fatal("Digest identical for different names; name must be part of key")
	}
}

func TestDigestChangesWithColumn(t *testing.T) {
	salt := []byte("0123456789abcdef")
	name := "deterministic_email"
	val := "user@example.com"
	if Digest(salt, "email", name, val) ==
		Digest(salt, "primary_email", name, val) {
		t.Fatal("Digest identical for different columns; column must be part of key")
	}
}

func TestDigestChangesWithValue(t *testing.T) {
	salt := []byte("0123456789abcdef")
	if Digest(salt, "email", "deterministic_email", "a@b.com") ==
		Digest(salt, "email", "deterministic_email", "c@d.com") {
		t.Fatal("Digest identical for different values; value must be part of key")
	}
}

func TestDigestChangesWithSalt(t *testing.T) {
	a := Digest([]byte("salt-aaaaaaaaaaaaaa"), "email", "deterministic_email", "x")
	b := Digest([]byte("salt-bbbbbbbbbbbbbb"), "email", "deterministic_email", "x")
	if a == b {
		t.Fatal("Digest identical for different salts; salt must key the HMAC")
	}
}

func TestDigestUnitSeparator(t *testing.T) {
	// The 0x1f separator prevents (name="a", column="bc", value="") from
	// colliding with (name="ab", column="c", value=""). Verify the two
	// inputs produce different digests.
	salt := []byte("0123456789abcdef")
	d1 := Digest(salt, "bc", "a", "")
	d2 := Digest(salt, "c", "ab", "")
	if d1 == d2 {
		t.Fatalf("separator collision: %s == %s", d1, d2)
	}
}

func TestRegisterGetNames(t *testing.T) {
	names := Names()
	if len(names) != 9 {
		t.Fatalf("Names() length = %d, want 9 (got %v)", len(names), names)
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("Names() not sorted: %v", names)
		}
	}
	for _, name := range names {
		s, ok := Get(name)
		if !ok {
			t.Fatalf("Get(%q) missing", name)
		}
		if s.Name() != name {
			t.Fatalf("Get(%q).Name() = %q", name, s.Name())
		}
	}
	if _, ok := Get("does_not_exist"); ok {
		t.Fatal("Get of unknown name returned ok=true")
	}
}

func TestRegisterPanicsOnDuplicate(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate Register, got nil")
		}
	}()
	// emailStrategy is already registered by init(); re-registering
	// must panic.
	Register(emailStrategy{defaultWasChanged})
}

// -----------------------------------------------------------------------------
// Per-strategy table-driven tests
// -----------------------------------------------------------------------------

func TestEmailStrategy(t *testing.T) {
	s := emailStrategy{defaultWasChanged}
	if s.Name() != "deterministic_email" {
		t.Fatalf("Name() = %q", s.Name())
	}
	got := s.Apply(ab32, "alice@example.com")
	want := "user_abababababab@example.invalid"
	if got != want {
		t.Fatalf("Apply = %q, want %q", got, want)
	}
	if !s.Placeholder(got) {
		t.Fatal("Placeholder(masked) = false, want true")
	}
	if s.Placeholder("alice@example.com") {
		t.Fatal("Placeholder(raw) = true, want false")
	}
	if !s.WasChanged("alice@example.com", got) {
		t.Fatal("WasChanged(raw, masked) = false, want true")
	}
	if s.WasChanged("a", "a") {
		t.Fatal("WasChanged(same, same) = true, want false")
	}
}

func TestPhoneIDStrategy(t *testing.T) {
	s := phoneIDStrategy{defaultWasChanged}
	if s.Name() != "deterministic_phone_id" {
		t.Fatalf("Name() = %q", s.Name())
	}
	// ab32 → DigitsFromHex(ab32, 9) → "01" * 5 = "010101010" (9 chars)
	got := s.Apply(ab32, "081234567890")
	want := "081010101010"
	if got != want {
		t.Fatalf("Apply = %q, want %q", got, want)
	}
	if len(got) != 12 {
		t.Fatalf("Apply length = %d, want 12", len(got))
	}
	if !s.Placeholder(got) {
		t.Fatal("Placeholder(masked) = false, want true")
	}
	if s.Placeholder("08123456789") { // wrong length
		t.Fatal("Placeholder(11 chars) = true, want false")
	}
	if s.Placeholder("+6281234567890") { // wrong prefix
		t.Fatal("Placeholder(wrong prefix) = true, want false")
	}
	if !s.WasChanged("081234567890", got) {
		t.Fatal("WasChanged = false, want true")
	}
}

func TestNIKStrategy(t *testing.T) {
	s := nikStrategy{defaultWasChanged}
	if s.Name() != "deterministic_nik" {
		t.Fatalf("Name() = %q", s.Name())
	}
	// ab32 → DigitsFromHex(ab32, 16) → "01" * 8 = "0101010101010101"
	got := s.Apply(ab32, "3201234567890001")
	want := "0101010101010101"
	if got != want {
		t.Fatalf("Apply = %q, want %q", got, want)
	}
	if len(got) != 16 {
		t.Fatalf("Apply length = %d, want 16", len(got))
	}
	if !s.Placeholder(got) {
		t.Fatal("Placeholder(masked) = false, want true")
	}
	if s.Placeholder("1234567890") { // wrong length
		t.Fatal("Placeholder(10 chars) = true, want false")
	}
}

func TestNPWPStrategy(t *testing.T) {
	s := npwpStrategy{defaultWasChanged}
	if s.Name() != "deterministic_npwp" {
		t.Fatalf("Name() = %q", s.Name())
	}
	// original = "12.345.678.9-012" → CountDigits = 12 (used to verify
	// that the digit-slot count in the output matches the input's).
	original := "12.345.678.9-012"
	if got := CountDigits(original); got != 12 {
		t.Fatalf("test setup: CountDigits(%q) = %d, want 12", original, got)
	}
	got := s.Apply(ab32, original)
	// DigitsFromHex(ab32, 12) → "01" * 6 = "010101010101"
	// FormatLikeDigits walks original replacing digits in order:
	//   1,2→0,1 ; 3,4→0,1 ; 5,6→0,1 ; 7,8→0,1 ; 9→0 ; 0,1→1,0 ; 2→1
	want := "01.010.101.0-101"
	if got != want {
		t.Fatalf("Apply = %q, want %q", got, want)
	}
	if c := CountDigits(got); c != 12 {
		t.Fatalf("Apply digit count = %d, want 12 (got %q)", c, got)
	}
	// Use a 15-digit NPWP to also exercise the Placeholder true branch.
	npwp15 := "123456789012345" // 15 digits
	masked15 := s.Apply(ab32, npwp15)
	if !s.Placeholder(masked15) {
		t.Fatalf("Placeholder(15-digit masked %q) = false, want true", masked15)
	}
	masked16 := strings.Repeat("9", 16)
	if !s.Placeholder(masked16) {
		t.Fatal("Placeholder(16-digit) = false, want true")
	}
	if s.Placeholder(strings.Repeat("0", 14)) {
		t.Fatal("Placeholder(14-digit) = true, want false")
	}
}

func TestNameIDStrategy(t *testing.T) {
	s := nameIDStrategy{defaultWasChanged}
	if s.Name() != "deterministic_name_id" {
		t.Fatalf("Name() = %q", s.Name())
	}
	// digest[0] = 'a' = 97, 97%8 = 1 → firstNames[1] = "Rina"
	// digest[1] = 'b' = 98, 98%8 = 2 → lastNames[2] = "Lestari"
	got := s.Apply(ab32, "Budi Santoso")
	want := "Rina Lestari"
	if got != want {
		t.Fatalf("Apply = %q, want %q", got, want)
	}
	if !s.Placeholder(got) {
		t.Fatal("Placeholder(masked) = false, want true")
	}
	if s.Placeholder("Andi") { // single token
		t.Fatal("Placeholder(single token) = true, want false")
	}
	if s.Placeholder("Andi Smith") { // unknown last name
		t.Fatal("Placeholder(unknown last) = true, want false")
	}
	if s.Placeholder("Alice Pratama") { // unknown first name
		t.Fatal("Placeholder(unknown first) = true, want false")
	}
}

func TestAddressIDStrategy(t *testing.T) {
	s := addressIDStrategy{defaultWasChanged}
	if s.Name() != "deterministic_address_id" {
		t.Fatalf("Name() = %q", s.Name())
	}
	// DigitsFromHex(ab32, 3) → "010"
	got := s.Apply(ab32, "Jl. Sudirman No.1, Jakarta")
	want := "Jl. Masked 010, Kota Contoh"
	if got != want {
		t.Fatalf("Apply = %q, want %q", got, want)
	}
	if !s.Placeholder(got) {
		t.Fatal("Placeholder(masked) = false, want true")
	}
	if s.Placeholder("Jl. Sudirman 1, Jakarta") { // wrong prefix
		t.Fatal("Placeholder(wrong prefix) = true, want false")
	}
	if s.Placeholder("Jl. Masked 010 Kota Contoh") { // missing comma suffix
		t.Fatal("Placeholder(missing suffix) = true, want false")
	}
}

func TestDateShiftStrategy(t *testing.T) {
	s := dateShiftStrategy{defaultWasChanged}
	if s.Name() != "date_shift" {
		t.Fatalf("Name() = %q", s.Name())
	}
	// digest[0] = 'a' = 97, 97%28 = 13, +1 = 14 → "14"
	got := s.Apply(ab32, "1990-05-15")
	want := "1990-01-14"
	if got != want {
		t.Fatalf("Apply = %q, want %q", got, want)
	}
	if !s.Placeholder(got) {
		t.Fatal("Placeholder(masked) = false, want true")
	}
	if s.Placeholder("1990-05-15") {
		t.Fatal("Placeholder(raw DOB) = true, want false")
	}

	// Verify TwoDigitDay range: pick a digest whose first byte maps to
	// day 1 (the zero-padded case) and day 10 (the non-padded case).
	cases := []struct {
		digest byte
		want   string
	}{
		{byte('a' - ('a' % 28)), "01"},     // day = 1
		{byte('a' - ('a' % 28) + 9), "10"}, // day = 10
	}
	for _, tc := range cases {
		d := strings.Repeat(string(tc.digest), 64)
		got := s.Apply(d, "x")
		want := "1990-01-" + tc.want
		if got != want {
			t.Fatalf("TwoDigitDay digest[0]=%d → %q, want %q", d[0], got, want)
		}
	}
}

func TestDigitsStrategy(t *testing.T) {
	s := digitsStrategy{defaultWasChanged}
	if s.Name() != "deterministic_digits" {
		t.Fatalf("Name() = %q", s.Name())
	}
	// original = "ABC123XYZ456" → CountDigits = 6
	// DigitsFromHex(ab32, 6) → "010101"
	// FormatLikeDigits → "ABC010XYZ101"
	got := s.Apply(ab32, "ABC123XYZ456")
	want := "ABC010XYZ101"
	if got != want {
		t.Fatalf("Apply = %q, want %q", got, want)
	}
	// Per design doc: all-digit values are placeholders (the legacy
	// isMaskedPlaceholder had no case for deterministic_digits, so the
	// default "masked_" branch fired; we keep that semantic with an
	// all-digit heuristic).
	if !s.Placeholder("123456") {
		t.Fatal("Placeholder(all digits) = false, want true")
	}
	if s.Placeholder("") {
		t.Fatal("Placeholder(empty) = true, want false")
	}
	if s.Placeholder("ABC123") {
		t.Fatal("Placeholder(mixed) = true, want false")
	}
}

func TestRedactionStrategy(t *testing.T) {
	s := redactionStrategy{defaultWasChanged}
	if s.Name() != "deterministic_redaction" {
		t.Fatalf("Name() = %q", s.Name())
	}
	// digest[:16] of ab32 = "abababababababab"
	got := s.Apply(ab32, "some free-form text")
	want := "masked_abababababababab"
	if got != want {
		t.Fatalf("Apply = %q, want %q", got, want)
	}
	if !s.Placeholder(got) {
		t.Fatal("Placeholder(masked) = false, want true")
	}
	if s.Placeholder("some free-form text") {
		t.Fatal("Placeholder(raw) = true, want false")
	}
}

// -----------------------------------------------------------------------------
// Helper unit tests
// -----------------------------------------------------------------------------

func TestDigitsFromHex(t *testing.T) {
	if got := DigitsFromHex("0123456789", 5); got != "01234" {
		t.Fatalf("DigitsFromHex pure digits = %q, want 01234", got)
	}
	// a-f map to 0-5
	if got := DigitsFromHex("abcdef", 6); got != "012345" {
		t.Fatalf("DigitsFromHex a-f = %q, want 012345", got)
	}
	// wraps when input is shorter than requested
	if got := DigitsFromHex("ab", 5); got != "01010" {
		t.Fatalf("DigitsFromHex wrap = %q, want 01010", got)
	}
	// length <= 0 → empty
	if got := DigitsFromHex("0123", 0); got != "" {
		t.Fatalf("DigitsFromHex length 0 = %q, want empty", got)
	}
	if got := DigitsFromHex("0123", -1); got != "" {
		t.Fatalf("DigitsFromHex length -1 = %q, want empty", got)
	}
}

func TestCountDigits(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"abc", 0},
		{"123", 3},
		{"a1b2c3", 3},
		{"12.345.678", 8},
		{"01.010.101.0-101", 12},
	}
	for _, tc := range cases {
		if got := CountDigits(tc.in); got != tc.want {
			t.Fatalf("CountDigits(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestFormatLikeDigits(t *testing.T) {
	if got := FormatLikeDigits("ABC123XYZ", "987"); got != "ABC987XYZ" {
		t.Fatalf("FormatLikeDigits = %q, want ABC987XYZ", got)
	}
	// extra digits in `digits` are ignored
	if got := FormatLikeDigits("AB1", "9876"); got != "AB9" {
		t.Fatalf("FormatLikeDigits extra digits = %q, want AB9", got)
	}
	// non-digit runes pass through unchanged
	if got := FormatLikeDigits("a-1-b-2", "XY"); got != "a-X-b-Y" {
		t.Fatalf("FormatLikeDigits with separators = %q, want a-X-b-Y", got)
	}
	// empty original → empty
	if got := FormatLikeDigits("", "123"); got != "" {
		t.Fatalf("FormatLikeDigits empty original = %q, want empty", got)
	}
}

func TestFakeName(t *testing.T) {
	// digest[0]='a' → 97%8=1 → "Rina"; digest[1]='b' → 98%8=2 → "Lestari"
	if got := FakeName(ab32); got != "Rina Lestari" {
		t.Fatalf("FakeName(ab32) = %q, want Rina Lestari", got)
	}
	// digest[0]='A'=65, 65%8=1 → "Rina"; digest[1]='A'=65%8=1 → "Pratama"
	if got := FakeName("A" + strings.Repeat("x", 63)); got != "Rina Pratama" {
		t.Fatalf("FakeName(Ax...) = %q, want Rina Pratama", got)
	}
	// digest[0]=digest[1]='\x00' → 0%8=0 → "Andi Pratama"
	if got := FakeName("\x00\x00" + strings.Repeat("x", 62)); got != "Andi Pratama" {
		t.Fatalf("FakeName(\\0\\0) = %q, want Andi Pratama", got)
	}
}

func TestTwoDigitDay(t *testing.T) {
	// digest[0]='a'=97 → 97%28=13 → 14
	if got := TwoDigitDay(ab32); got != "14" {
		t.Fatalf("TwoDigitDay(ab32) = %q, want 14", got)
	}
	// digest[0]='A'=65 → 65%28=9 → 10 → "10"
	if got := TwoDigitDay("A" + strings.Repeat("x", 63)); got != "10" {
		t.Fatalf("TwoDigitDay(Ax...) = %q, want 10", got)
	}
	// digest[0]='\x00' → 0%28=0 → 1 → "01"
	if got := TwoDigitDay("\x00" + strings.Repeat("x", 63)); got != "01" {
		t.Fatalf("TwoDigitDay(\\0) = %q, want 01", got)
	}
	// Max is 28: pick a byte that yields day=28.
	// 27%28+1=28. Need x%28=27. '\x1b'=27.
	if got := TwoDigitDay("\x1b" + strings.Repeat("x", 63)); got != "28" {
		t.Fatalf("TwoDigitDay(0x1b) = %q, want 28", got)
	}
}
