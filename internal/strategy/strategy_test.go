package strategy

import (
	"encoding/hex"
	"fmt"
	"os"
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
	// digest[0:2] = "ab" = 0xab = 171, 171 % 64 = 43
	//   → firstNames[43] = "Dedi"
	// digest[2:4] = "ab" = 0xab = 171, 171 % 64 = 43
	//   → lastNames[43] = "Irawan"
	got := s.Apply(ab32, "Budi Santoso")
	want := "Dedi Irawan"
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
	// digest[0:4] = "abab"; digest[4:8] = "abab" — 4 lowercase hex
	// chars each, joined with a dash.
	got := s.Apply(ab32, "Jl. Sudirman No.1, Jakarta")
	want := "Jl. Masked abab-abab, Kota Contoh"
	if got != want {
		t.Fatalf("Apply = %q, want %q", got, want)
	}
	if !s.Placeholder(got) {
		t.Fatal("Placeholder(masked) = false, want true")
	}
	if s.Placeholder("Jl. Sudirman 1, Jakarta") { // wrong prefix
		t.Fatal("Placeholder(wrong prefix) = true, want false")
	}
	if s.Placeholder("Jl. Masked abab-abab Kota Contoh") { // missing comma suffix
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
	// Strict Placeholder: a value with only digits is NOT a
	// placeholder (it could be a raw NIK/phone). The value must
	// contain at least one allowed-punctuation rune to be
	// recognised as masked output. Letters are always rejected.
	if s.Placeholder("123456") {
		t.Fatal("Placeholder(all digits) = true, want false")
	}
	if s.Placeholder("") {
		t.Fatal("Placeholder(empty) = true, want false")
	}
	if s.Placeholder("ABC123") {
		t.Fatal("Placeholder(letters+mixed) = true, want false")
	}
	if !s.Placeholder("01.234.567.8-901") {
		t.Fatal("Placeholder(digit-shaped w/ punct) = false, want true")
	}
	if s.Placeholder("01#234") { // '#' is not in the allowed alphabet
		t.Fatal("Placeholder(disallowed punct) = true, want false")
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
	// digest[0:2]="ab"=0xab=171, 171%64=43 → firstNames[43]="Dedi"
	// digest[2:4]="ab"=0xab=171, 171%64=43 → lastNames[43]="Irawan"
	if got := FakeName(ab32); got != "Dedi Irawan" {
		t.Fatalf("FakeName(ab32) = %q, want Dedi Irawan", got)
	}
	// digest[0:2]="0a"=10, 10%64=10 → firstNames[10]="Sari"
	// digest[2:4]="0b"=11, 11%64=11 → lastNames[11]="Anggraini"
	if got := FakeName("0a0b" + strings.Repeat("c", 60)); got != "Sari Anggraini" {
		t.Fatalf("FakeName(0a0b...) = %q, want Sari Anggraini", got)
	}
	// digest[0:2]="\x00\x00"=0, 0%64=0 → firstNames[0]="Andi"
	// digest[2:4]="\x00\x00"=0, 0%64=0 → lastNames[0]="Pratama"
	if got := FakeName(strings.Repeat("\x00", 64)); got != "Andi Pratama" {
		t.Fatalf("FakeName(\\0*64) = %q, want Andi Pratama", got)
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

// -----------------------------------------------------------------------------
// P1 keyspace pin tests (Chain 2 fixes)
// -----------------------------------------------------------------------------

// TestAddressKeyspaceExceeds10k feeds many distinct salts into the same
// input cell and asserts the strategy produces strictly more than
// 10000 distinct masked addresses. The old keyspace was 3 decimal
// digits = 1000 outputs; this test pins the 65536-entry
// (area=4 hex chars) keyspace.
func TestAddressKeyspaceExceeds10k(t *testing.T) {
	s := addressIDStrategy{defaultWasChanged}
	// 10001 samples gives effectively-zero collision probability in
	// the joint (digest[0:4], digest[4:8]) keyspace of 65536²
	// pairs. We need strictly more than 10000 distinct outputs;
	// the test asserts > 10000.
	const n = 10001
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		salt := []byte(fmt.Sprintf("salt-%010d", i))
		digest := Digest(salt, "address", "deterministic_address_id", "Jl. Sudirman 1")
		seen[s.Apply(digest, "Jl. Sudirman 1")] = struct{}{}
	}
	if got := len(seen); got <= 10000 {
		t.Fatalf("distinct masked addresses = %d, want > 10000", got)
	}
	t.Logf("distinct masked addresses across %d salts = %d", n, len(seen))
}

// TestNameKeyspaceExceeds1000 is the name-side counterpart: 64*64 =
// 4096 distinct pairs, comfortably above the 1000 threshold.
func TestNameKeyspaceExceeds1000(t *testing.T) {
	// With 10000 distinct salts driving distinct digests, the
	// expected distinct first*last pairs is
	// 64*64 * (1 - (1 - 1/(64*64))^10000) ≈ 3964, far above 1000.
	const n = 10000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		salt := []byte(fmt.Sprintf("salt-%010d", i))
		digest := Digest(salt, "name", "deterministic_name_id", "Budi Santoso")
		seen[FakeName(digest)] = struct{}{}
	}
	if got := len(seen); got <= 1000 {
		t.Fatalf("distinct fake names = %d, want > 1000", got)
	}
	t.Logf("distinct fake names across %d salts = %d", n, len(seen))
}

// TestDigitsFormatAware pins the three contract assertions for
// deterministic_digits:
//
//  1. The doc comment in builtins.go explicitly states that the
//     output preserves the input's punctuation layout "verbatim".
//  2. FormatLikeDigits leaves non-digit runes untouched: digits
//     are replaced in order, punctuation is passed through.
//  3. A fixed input/output pair cements the contract for future
//     readers.
//
// The "doc" check reads the source file directly so a drive-by edit
// that drops the keyword fails the test even if the runtime
// behaviour is unchanged.
func TestDigitsFormatAware(t *testing.T) {
	// 1. Doc comment asserts the verbatim layout contract.
	// Tests run with cwd set to the package directory
	// (internal/strategy/), so the source is "builtins.go" relative
	// to the test binary.
	const source = "builtins.go"
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read %s: %v", source, err)
	}
	src := string(data)
	if !strings.Contains(src, "verbatim") {
		t.Fatalf("%s is missing the \"verbatim\" contract keyword for deterministic_digits", source)
	}
	if !strings.Contains(src, "deterministic_digits") {
		t.Fatalf("%s is missing the deterministic_digits section", source)
	}

	// 2. FormatLikeDigits preserves the dash in "12-34" and replaces
	// the four digit positions with the four bytes of "abcd".
	if got := FormatLikeDigits("12-34", "abcd"); got != "ab-cd" {
		t.Fatalf("FormatLikeDigits(\"12-34\", \"abcd\") = %q, want %q", got, "ab-cd")
	}

	// 3. Fixed input/output pin: an NPWP-shaped input keeps its
	// dots and dash, with digit positions filled in order.
	if got := FormatLikeDigits("12.34", "12345678"); got != "12.34" {
		t.Fatalf("FormatLikeDigits(\"12.34\", \"12345678\") = %q, want %q", got, "12.34")
	}
	// And a 4-digit-with-dash shape exercises a non-trivial pass-through.
	if got := FormatLikeDigits("0-0-0-0", "abcd"); got != "a-b-c-d" {
		t.Fatalf("FormatLikeDigits(\"0-0-0-0\", \"abcd\") = %q, want %q", got, "a-b-c-d")
	}
}
