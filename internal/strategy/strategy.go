// Package strategy defines the masking contract used by apply and verify.
//
// A Strategy owns one transformation (e.g. email, phone, NIK) and is
// registered globally by name. apply.go and verify.go call into the
// registry instead of the previous per-package switch statements so
// that the two paths cannot drift.
package strategy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// Strategy is the interface every masking strategy implements.
//
// Apply receives a deterministic digest of (column, value) and the
// original value, and returns the masked representation. Placeholder
// reports whether a value looks like output produced by this strategy
// (used by verify to detect leakage of raw PII). WasChanged reports
// whether Apply actually altered the input — strategies that collapse
// to the input (e.g. empty strings) can override the default.
type Strategy interface {
	Name() string
	Apply(digest, original string) string
	Placeholder(value string) bool
	WasChanged(original, masked string) bool
}

// WasChangedFunc adapts a simple equality check into a WasChanged
// implementation. The default contract is: a value changed iff the
// masked output differs from the original.
type WasChangedFunc func(original, masked string) bool

// WasChanged implements Strategy.
func (f WasChangedFunc) WasChanged(original, masked string) bool { return f(original, masked) }

// registry holds the globally registered strategies, keyed by Name().
// Registration happens in package init() functions in builtins.go.
var registry = map[string]Strategy{}

// Register makes s available by name. It panics on duplicate
// registration because that indicates a programming error in the
// builtins, not a runtime condition callers should handle.
func Register(s Strategy) {
	if _, exists := registry[s.Name()]; exists {
		panic("strategy: duplicate registration for " + s.Name())
	}
	registry[s.Name()] = s
}

// Get looks up a strategy by name.
func Get(name string) (Strategy, bool) {
	s, ok := registry[name]
	return s, ok
}

// Names returns the registered strategy names in lexicographic order.
// The order is part of the observable contract: plan.go, docs, and
// CLI listings all rely on a stable, sorted view.
func Names() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Digest computes the HMAC-SHA256 of (name, column, value) keyed by
// salt. The keying is deliberately different from the legacy
// apply.digestHex which used (Type, Column, Value): keying on Name
// keeps the digest stable when categories are reclassified and stops
// a single salt leak from collapsing two semantically different
// columns whose Type happens to match.
//
// name is the strategy Name() (e.g. "deterministic_email").
// column is the CSV column header.
// value is the raw cell value.
func Digest(salt []byte, column, name, value string) string {
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(name))
	mac.Write([]byte{0x1f})
	mac.Write([]byte(column))
	mac.Write([]byte{0x1f})
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}
