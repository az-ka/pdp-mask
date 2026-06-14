package strategy

import (
	"fmt"
	"strings"
)

// firstNames and lastNames back the deterministic_name_id strategy.
// They mirror the lists in strategy.FakeName and verify.isMaskedPlaceholder
// and must stay in sync with both.
var (
	firstNames = []string{"Andi", "Rina", "Dewi", "Bima", "Maya", "Raka", "Nadia", "Fajar"}
	lastNames  = []string{"Pratama", "Wijaya", "Lestari", "Saputra", "Utami", "Santoso", "Permata", "Nugraha"}
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
// -----------------------------------------------------------------------------

type addressIDStrategy struct {
	WasChangedFunc
}

func (addressIDStrategy) Name() string { return "deterministic_address_id" }

func (addressIDStrategy) Apply(digest, original string) string {
	return "Jl. Masked " + DigitsFromHex(digest, 3) + ", Kota Contoh"
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
// -----------------------------------------------------------------------------

type digitsStrategy struct {
	WasChangedFunc
}

func (digitsStrategy) Name() string { return "deterministic_digits" }

func (digitsStrategy) Apply(digest, original string) string {
	return FormatLikeDigits(original, DigitsFromHex(digest, CountDigits(original)))
}

// Placeholder is a heuristic: the legacy isMaskedPlaceholder switch had
// no "deterministic_digits" case and fell through to the default
// "masked_" branch. The design doc says to keep that behavior, so we
// treat all-digit values as placeholders.
func (digitsStrategy) Placeholder(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
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

// FakeName picks a first and last name deterministically from the
// first two bytes of the digest.
func FakeName(digest string) string {
	return firstNames[int(digest[0])%len(firstNames)] + " " + lastNames[int(digest[1])%len(lastNames)]
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
