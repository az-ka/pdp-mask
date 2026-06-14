package strategy

import (
	"fmt"
	"strings"
)

// firstNames and lastNames back the deterministic_name_id strategy.
// They are the single source of truth shared by strategy.FakeName
// (used to produce masked output) and nameIDStrategy.Placeholder
// (used by verify to recognise a value as already-masked).
//
// Keyspace contract: with N first names and M last names, the
// distinct-pair count is N*M. digest[0:2] is parsed as a single
// hex byte (0..255) and reduced mod N for the first index; digest[2:4]
// is parsed the same way and reduced mod M for the last index. To
// keep the keyspace comfortably above 1000 the lists below carry
// 64 entries each, giving 64*64 = 4096 distinct pairs.
var (
	firstNames = []string{
		"Andi", "Rina", "Dewi", "Bima", "Maya", "Raka", "Nadia", "Fajar",
		"Putri", "Bagas", "Sari", "Doni", "Lina", "Yoga", "Tari", "Reza",
		"Angga", "Citra", "Dimas", "Eka", "Fitri", "Galih", "Hana", "Indra",
		"Jaka", "Kirana", "Lutfi", "Mega", "Nanda", "Oki", "Putu", "Qori",
		"Rangga", "Sinta", "Tio", "Uli", "Vina", "Wahyu", "Yusuf", "Zara",
		"Asep", "Bayu", "Cahya", "Dedi", "Endah", "Feri", "Gita", "Hari",
		"Ika", "Joko", "Kiki", "Lia", "Made", "Nia", "Omar", "Pandu",
		"Qila", "Rio", "Sasa", "Toni", "Ujang", "Vera", "Wawan", "Yanto",
	}
	lastNames = []string{
		"Pratama", "Wijaya", "Lestari", "Saputra", "Utami", "Santoso", "Permata", "Nugraha",
		"Sukma", "Hidayat", "Maulana", "Anggraini", "Setiawan", "Kusuma", "Prasetya", "Wibowo",
		"Nugroho", "Halim", "Syahputra", "Ramadhan", "Firmansyah", "Haryanto", "Saputro", "Hartono",
		"Suharto", "Susanto", "Suryanto", "Pangestu", "Kurniawan", "Suryani", "Handayani", "Maharani",
		"Putri", "Adiputra", "Wicaksono", "Gunawan", "Budiman", "Chandra", "Dewantara", "Effendi",
		"Fadhil", "Ginting", "Hutapea", "Irawan", "Junaidi", "Kusnadi", "Lubis", "Munandar",
		"Napitupulu", "Ompusunggu", "Pohan", "Qodir", "Rambe", "Sinaga", "Tobing", "Ujung",
		"Verawati", "Waruwu", "Yulianto", "Zebua", "Astuti", "Bachtiar", "Cahyadi", "Damanik",
	}
)

// defaultWasChanged is the shared WasChanged implementation: a value
// changed iff the masked output differs from the original.
var defaultWasChanged = WasChangedFunc(func(original, masked string) bool {
	return original != masked
})

// -----------------------------------------------------------------------------
// 1. deterministic_email
// -----------------------------------------------------------------------------

type emailStrategy struct {
	WasChangedFunc
}

func (emailStrategy) Name() string { return "deterministic_email" }

func (emailStrategy) Apply(digest, original string) string {
	return "user_" + digest[:12] + "@example.invalid"
}

func (emailStrategy) Placeholder(value string) bool {
	return strings.HasPrefix(value, "user_") && strings.HasSuffix(value, "@example.invalid")
}

// -----------------------------------------------------------------------------
// 2. deterministic_phone_id
// -----------------------------------------------------------------------------

type phoneIDStrategy struct {
	WasChangedFunc
}

func (phoneIDStrategy) Name() string { return "deterministic_phone_id" }

func (phoneIDStrategy) Apply(digest, original string) string {
	return "081" + DigitsFromHex(digest, 9)
}

func (phoneIDStrategy) Placeholder(value string) bool {
	return strings.HasPrefix(value, "081") && len(value) == 12
}

// -----------------------------------------------------------------------------
// 3. deterministic_nik
// -----------------------------------------------------------------------------

type nikStrategy struct {
	WasChangedFunc
}

func (nikStrategy) Name() string { return "deterministic_nik" }

func (nikStrategy) Apply(digest, original string) string {
	return DigitsFromHex(digest, 16)
}

func (nikStrategy) Placeholder(value string) bool {
	return len(value) == 16
}

// -----------------------------------------------------------------------------
// 4. deterministic_npwp
// -----------------------------------------------------------------------------

type npwpStrategy struct {
	WasChangedFunc
}

func (npwpStrategy) Name() string { return "deterministic_npwp" }

func (npwpStrategy) Apply(digest, original string) string {
	return FormatLikeDigits(original, DigitsFromHex(digest, CountDigits(original)))
}

func (npwpStrategy) Placeholder(value string) bool {
	return CountDigits(value) == 15 || CountDigits(value) == 16
}

// -----------------------------------------------------------------------------
// 5. deterministic_name_id
// -----------------------------------------------------------------------------

type nameIDStrategy struct {
	WasChangedFunc
}

func (nameIDStrategy) Name() string { return "deterministic_name_id" }

func (nameIDStrategy) Apply(digest, original string) string {
	return FakeName(digest)
}

func (nameIDStrategy) Placeholder(value string) bool {
	parts := strings.Split(value, " ")
	if len(parts) != 2 {
		return false
	}
	first := nameLookup(firstNames)
	last := nameLookup(lastNames)
	return first[parts[0]] && last[parts[1]]
}

func nameLookup(names []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// -----------------------------------------------------------------------------
// 6. deterministic_address_id
//
// Keyspace contract: the area code uses digest[0:4] (4 lowercase hex
// chars = 16 bits = 65536 values) and the street segment uses
// digest[4:8] (another 65536 values), giving 65536 * 65536 potential
// pairs. The Placeholder check looks only at the surrounding
// "Jl. Masked " / ", Kota Contoh" wrapper; it does not try to
// validate the hex body so a value with garbled hex is still
// recognised as masked (verifying digit positions would require the
// original, which Placeholder does not have).
// -----------------------------------------------------------------------------

type addressIDStrategy struct {
	WasChangedFunc
}

func (addressIDStrategy) Name() string { return "deterministic_address_id" }

func (addressIDStrategy) Apply(digest, original string) string {
	return "Jl. Masked " + digest[0:4] + "-" + digest[4:8] + ", Kota Contoh"
}

func (addressIDStrategy) Placeholder(value string) bool {
	return strings.HasPrefix(value, "Jl. Masked ") && strings.HasSuffix(value, ", Kota Contoh")
}

// -----------------------------------------------------------------------------
// 7. date_shift
// -----------------------------------------------------------------------------

type dateShiftStrategy struct {
	WasChangedFunc
}

func (dateShiftStrategy) Name() string { return "date_shift" }

func (dateShiftStrategy) Apply(digest, original string) string {
	return "1990-01-" + TwoDigitDay(digest)
}

func (dateShiftStrategy) Placeholder(value string) bool {
	return strings.HasPrefix(value, "1990-01-")
}

// -----------------------------------------------------------------------------
// 8. deterministic_digits
//
// Format contract: the output preserves the input's punctuation
// layout verbatim; only the digit positions are replaced, in order,
// with bytes derived from the digest (see FormatLikeDigits). The
// non-digit characters (dots, dashes, spaces, etc.) are passed
// through unchanged. This means the masking leaks the *shape* of the
// input (e.g. a 16-digit NIK stays 16 digits, a 12.345.678.9-012
// NPWP keeps its dots and dash) but never the digits themselves.
//
// Placeholder is a strict heuristic: a value is recognised as
// already-masked only if it contains at least one non-digit rune
// from a small punctuation alphabet AND no letters. All-digit
// values are rejected as placeholders because a raw NIK, phone, or
// NPWP would otherwise be misclassified as masked. The strictest
// possible check would compare punctuation against the original,
// but Placeholder does not have access to the original value.
// -----------------------------------------------------------------------------

type digitsStrategy struct {
	WasChangedFunc
}

func (digitsStrategy) Name() string { return "deterministic_digits" }

func (digitsStrategy) Apply(digest, original string) string {
	return FormatLikeDigits(original, DigitsFromHex(digest, CountDigits(original)))
}

// digitsPunctuation is the set of non-digit runes that
// deterministic_digits may pass through verbatim from the original.
// Letters are deliberately excluded: a letter-bearing value
// cannot be the output of this strategy because letters never
// appear in either the input (which is digit-shaped) or the digest
// (which is consumed digit-by-digit only at digit positions).
const digitsPunctuation = " .-,:/"

func (digitsStrategy) Placeholder(value string) bool {
	if value == "" {
		return false
	}
	hasPunct := false
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
			// digit slot: allowed
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			// letters never survive Apply, so this cannot be masked output
			return false
		case strings.ContainsRune(digitsPunctuation, r):
			hasPunct = true
		default:
			return false
		}
	}
	return hasPunct
}

// -----------------------------------------------------------------------------
// 9. deterministic_redaction (default / catch-all)
// -----------------------------------------------------------------------------

type redactionStrategy struct {
	WasChangedFunc
}

func (redactionStrategy) Name() string { return "deterministic_redaction" }

func (redactionStrategy) Apply(digest, original string) string {
	return "masked_" + digest[:16]
}

func (redactionStrategy) Placeholder(value string) bool {
	return strings.HasPrefix(value, "masked_")
}

// -----------------------------------------------------------------------------
// Registration
// -----------------------------------------------------------------------------

func init() {
	Register(emailStrategy{defaultWasChanged})
	Register(phoneIDStrategy{defaultWasChanged})
	Register(nikStrategy{defaultWasChanged})
	Register(npwpStrategy{defaultWasChanged})
	Register(nameIDStrategy{defaultWasChanged})
	Register(addressIDStrategy{defaultWasChanged})
	Register(dateShiftStrategy{defaultWasChanged})
	Register(digitsStrategy{defaultWasChanged})
	Register(redactionStrategy{defaultWasChanged})
}

// -----------------------------------------------------------------------------
// Helpers (exported so apply.go and verify.go can share the same
// transformation math; the strategy package is the single source of truth).

// DigitsFromHex turns a hex digest into `length` decimal digits by
// walking the input and mapping a-f to 0-5. If the input runs out of
// decimal chars it wraps around.
func DigitsFromHex(hexValue string, length int) string {
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

// CountDigits returns the number of ASCII decimal digits in value.
func CountDigits(value string) int {
	count := 0
	for _, r := range value {
		if r >= '0' && r <= '9' {
			count++
		}
	}
	return count
}

// FormatLikeDigits walks `original` and replaces each digit in order
// with the next byte from `digits`. Non-digit runes are passed through
// unchanged. Trailing digits in `original` beyond the length of
// `digits` are dropped.
func FormatLikeDigits(original, digits string) string {
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

// hexPairValue decodes a 2-character hex string into a number in
// 0..255. It is used by FakeName to widen the name keyspace: each
// pair contributes 256 distinct inputs which, reduced modulo the
// 64-entry lists below, covers all 64 indices.
func hexPairValue(s string) int {
	return hexDigit(s[0])*16 + hexDigit(s[1])
}

// hexDigit decodes one ASCII hex character to its numeric value
// (0..15). Both lowercase and uppercase are accepted; anything
// outside the hex alphabet falls back to 0.
func hexDigit(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	}
	return 0
}

// FakeName picks a first and last name deterministically from
// digest[0:2] and digest[2:4] parsed as hex bytes (each 0..255),
// reduced modulo the corresponding list size.
func FakeName(digest string) string {
	first := hexPairValue(digest[0:2]) % len(firstNames)
	last := hexPairValue(digest[2:4]) % len(lastNames)
	return firstNames[first] + " " + lastNames[last]
}

// TwoDigitDay returns a zero-padded day-of-month (01-28) derived
// from the first byte of the digest. 28 keeps every month valid.
func TwoDigitDay(digest string) string {
	day := int(digest[0])%28 + 1
	if day < 10 {
		return fmt.Sprintf("0%d", day)
	}
	return fmt.Sprintf("%d", day)
}
