// Copyright 2026 AxonOps Limited.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"regexp"
)

// hmacSaltVersionPattern constrains HMACSalt.Version to a character set that
// is safe across JSON, CEF, and syslog wire formats without any escape
// ambiguity (issue #473). The allowed set covers typical operational
// version identifiers ("v1", "2026-Q1", "salt_v2.1", "key-rotation-12")
// while eliminating log-injection vectors via control characters.
var hmacSaltVersionPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

// maxHMACSaltVersionLen bounds HMACSalt.Version length. Longer values inflate
// every emitted event without operational benefit.
const maxHMACSaltVersionLen = 64

// MinSaltLength is the minimum salt length in bytes for HMAC
// computation, per NIST SP 800-224 (minimum key length: 128 bits).
const MinSaltLength = 16

// HMACConfig holds per-output HMAC configuration. When Enabled is
// true, every event delivered to the output has an HMAC appended.
// The HMAC is computed over the final serialised payload (after
// field stripping and event_category append).
//
// The Go shape mirrors the YAML shape under outputs.<name>.hmac:
//
//	hmac:
//	  enabled: true
//	  salt:
//	    version: "2026-Q1"
//	    value:   "${HMAC_SALT}"
//	  algorithm: "HMAC-SHA-256"
type HMACConfig struct { //nolint:govet // readability over alignment
	// Enabled controls whether HMAC is computed for this output.
	// Default: false. Must be explicitly true.
	Enabled bool

	// Salt carries the salt identifier and the raw salt bytes. See
	// [HMACSalt] for field-level documentation.
	Salt HMACSalt

	// Algorithm is the HMAC hash algorithm. Must be one of the
	// NIST-approved values: HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512,
	// HMAC-SHA3-256, HMAC-SHA3-384, HMAC-SHA3-512.
	Algorithm string
}

// HMACSalt groups the salt identifier and salt bytes for an
// [HMACConfig]. The grouping matches the nested YAML shape under
// outputs.<name>.hmac.salt, so a consumer reading the library's
// godoc and writing YAML sees the same structure in both places.
//
// HMACSalt implements [fmt.Stringer] and [fmt.GoStringer] to redact
// the raw Value from %v, %+v, and %#v format verbs. Consumers
// SHOULD still treat Value as secret and avoid passing it to any
// unbounded writer.
type HMACSalt struct {
	// Version is a user-defined identifier for the salt, emitted in
	// the output alongside the HMAC digest. Supports salt rotation —
	// consumers use this to look up the correct salt for
	// verification. Required when [HMACConfig.Enabled] is true. Must
	// match `^[A-Za-z0-9._:-]+$` (for unambiguous authenticated-byte
	// representation on the wire — see #473) and be at most 64
	// characters.
	Version string

	// Value is the raw salt bytes. MUST be at least [MinSaltLength]
	// (16 bytes / 128 bits). The built-in [HMACSalt.String] and
	// [HMACSalt.GoString] methods redact this value; consumers
	// implementing their own formatting MUST NOT log or include it in
	// error messages.
	Value []byte
}

// String returns a safe representation that never includes the salt
// Value bytes.
func (s HMACSalt) String() string {
	return fmt.Sprintf("HMACSalt{Version: %q, ValueLen: %d}", s.Version, len(s.Value))
}

// GoString implements [fmt.GoStringer] to prevent salt leakage via %#v.
func (s HMACSalt) GoString() string {
	return s.String()
}

// String returns a safe representation that never includes the salt value.
func (c HMACConfig) String() string {
	if !c.Enabled {
		return "HMACConfig{Enabled: false}"
	}
	return fmt.Sprintf("HMACConfig{Enabled: true, Salt.Version: %q, Algorithm: %q, Salt.Len: %d}",
		c.Salt.Version, c.Algorithm, len(c.Salt.Value))
}

// GoString implements [fmt.GoStringer] to prevent salt leakage via %#v.
func (c HMACConfig) GoString() string {
	return c.String()
}

// hmacHashFunc returns the hash constructor for the given algorithm name.
// Only NIST SP 800-224 approved algorithms are included.
// SHA-1 and MD5 are explicitly excluded. Returns nil for unknown names.
func hmacHashFunc(name string) func() hash.Hash {
	switch name {
	case "HMAC-SHA-256":
		return sha256.New
	case "HMAC-SHA-384":
		return sha512.New384
	case "HMAC-SHA-512":
		return sha512.New
	case "HMAC-SHA3-256":
		return func() hash.Hash { return sha3.New256() }
	case "HMAC-SHA3-384":
		return func() hash.Hash { return sha3.New384() }
	case "HMAC-SHA3-512":
		return func() hash.Hash { return sha3.New512() }
	default:
		return nil
	}
}

// SupportedHMACAlgorithms returns the list of supported HMAC algorithm
// names for use in documentation and error messages.
func SupportedHMACAlgorithms() []string {
	return []string{
		"HMAC-SHA-256", "HMAC-SHA-384", "HMAC-SHA-512",
		"HMAC-SHA3-256", "HMAC-SHA3-384", "HMAC-SHA3-512",
	}
}

// ValidateHMACConfig checks that an HMACConfig is valid. Returns an
// error wrapping [ErrConfigInvalid] if the config is enabled but has
// missing or invalid fields. Salt values are never included in error
// messages.
func ValidateHMACConfig(cfg *HMACConfig) error {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	if cfg.Salt.Version == "" {
		return fmt.Errorf("%w: hmac salt.version is required when hmac is enabled", ErrConfigInvalid)
	}
	if len(cfg.Salt.Version) > maxHMACSaltVersionLen {
		return fmt.Errorf("%w: hmac salt.version length %d exceeds maximum %d",
			ErrConfigInvalid, len(cfg.Salt.Version), maxHMACSaltVersionLen)
	}
	if !hmacSaltVersionPattern.MatchString(cfg.Salt.Version) {
		return fmt.Errorf("%w: hmac salt.version %q contains characters outside the allowed set [A-Za-z0-9._:-] (required so the version can be authenticated unambiguously on the wire — see issue #473)",
			ErrConfigInvalid, cfg.Salt.Version)
	}
	if len(cfg.Salt.Value) == 0 {
		return fmt.Errorf("%w: hmac salt.value is required when hmac is enabled", ErrConfigInvalid)
	}
	if len(cfg.Salt.Value) < MinSaltLength {
		return fmt.Errorf("%w: hmac salt.value must be at least %d bytes", ErrConfigInvalid, MinSaltLength)
	}
	if cfg.Algorithm == "" {
		return fmt.Errorf("%w: hmac algorithm is required when hmac is enabled", ErrConfigInvalid)
	}
	if hmacHashFunc(cfg.Algorithm) == nil {
		return fmt.Errorf("%w: unknown hmac algorithm %q (supported: %v)", ErrConfigInvalid, cfg.Algorithm, SupportedHMACAlgorithms())
	}
	return nil
}

// newHMACState creates a pre-constructed hmacState for drain-loop reuse.
// Called once at auditor construction per HMAC-enabled output.
func newHMACState(cfg *HMACConfig) *hmacState {
	hashFunc := hmacHashFunc(cfg.Algorithm)
	if hashFunc == nil {
		return nil // unreachable: ValidateHMACConfig rejects unknown algorithms during New
	}
	mac := hmac.New(hashFunc, cfg.Salt.Value)
	return &hmacState{
		mac:     mac,
		hashLen: mac.Size(),
	}
}

// computeHMACFast computes the HMAC using pre-allocated state, returning
// the hex-encoded result as a byte slice from the state's buffer.
// The returned slice is valid only until the next call. Single-goroutine
// use only (drain loop).
func (s *hmacState) computeHMACFast(payload []byte) []byte {
	s.mac.Reset()
	s.mac.Write(payload)
	sum := s.mac.Sum(s.sumBuf[:0])
	hex.Encode(s.hexBuf[:], sum)
	return s.hexBuf[:s.hashLen*2]
}

// ComputeHMAC computes the HMAC for the given payload and returns the
// lowercase hex-encoded result. The algorithm must be one of the
// supported NIST-approved values (see [SupportedHMACAlgorithms]).
//
// ComputeHMAC returns a non-nil error in three cases:
//
//   - len(payload) == 0 — the empty payload is rejected to prevent
//     "empty event was signed" ambiguity.
//   - len(salt) == 0 — the empty salt is rejected because an HMAC
//     with empty key collapses to a plain hash (no authentication).
//   - algorithm not in [SupportedHMACAlgorithms] — unknown algorithms
//     are rejected rather than silently falling back.
//
// The returned string is always lowercase hex, matching what
// [VerifyHMAC] accepts on the receiving side.
func ComputeHMAC(payload, salt []byte, algorithm string) (string, error) {
	if len(payload) == 0 {
		return "", fmt.Errorf("%w: hmac payload must not be empty", ErrValidation)
	}
	if len(salt) == 0 {
		return "", fmt.Errorf("%w: hmac salt must not be empty", ErrValidation)
	}
	hashFunc := hmacHashFunc(algorithm)
	if hashFunc == nil {
		return "", fmt.Errorf("audit: unknown hmac algorithm %q: %w", algorithm, ErrValidation)
	}
	mac := hmac.New(hashFunc, salt)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyHMAC verifies that the HMAC value matches the payload.
// The hmacValue MUST be lowercase hex-encoded (as produced by
// [ComputeHMAC]); uppercase hex is rejected to avoid the
// two-valid-encodings footgun.
//
// Returns (true, nil) for a valid match, (false, nil) for a valid-
// format-but-wrong-digest, (false, err) for parameter or input
// errors. Structural rejects (empty, wrong length, non-hex) wrap
// both [ErrValidation] and [ErrHMACMalformed] and happen BEFORE
// the constant-time compare — malformed inputs are pre-
// authentication and not timing-sensitive (#483).
func VerifyHMAC(payload []byte, hmacValue string, salt []byte, algorithm string) (bool, error) {
	// Compute the expected HMAC first — ComputeHMAC validates the
	// payload, salt, and algorithm and produces the hex length we
	// need to compare hmacValue against.
	computed, err := ComputeHMAC(payload, salt, algorithm)
	if err != nil {
		return false, err
	}

	// Structural validation of hmacValue — length + hex charset.
	// These run BEFORE hmac.Equal because malformed inputs are
	// not secrets and do not need timing-safe handling.
	if len(hmacValue) != len(computed) {
		return false, errors.Join(ErrValidation, fmt.Errorf(
			"%w: hmac value length %d does not match expected %d for algorithm %q",
			ErrHMACMalformed, len(hmacValue), len(computed), algorithm))
	}
	for i := 0; i < len(hmacValue); i++ {
		c := hmacValue[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false, errors.Join(ErrValidation, fmt.Errorf(
				"%w: hmac value contains non-lowercase-hex byte 0x%02x at offset %d",
				ErrHMACMalformed, c, i))
		}
	}

	// Happy path — constant-time compare on equally-sized,
	// validated inputs.
	return hmac.Equal([]byte(computed), []byte(hmacValue)), nil
}
