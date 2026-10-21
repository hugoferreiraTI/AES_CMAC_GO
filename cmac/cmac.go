// Package cmac implements AES-128 CMAC with full 128-bit tags, as specified
// in RFC 4493. CMAC provides authenticity and integrity, not confidentiality.
// Keys and received tags are hexadecimal; messages use the string's bytes
// directly (UTF-8 for UTF-8 text), without normalization or hexadecimal decoding.
package cmac

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// Generate returns the full CMAC of message as 32 lowercase hexadecimal
// characters. keyHex must encode exactly 16 bytes (32 hexadecimal characters),
// with no prefix or whitespace. Invalid keys return an error and an empty tag.
func Generate(keyHex, message string) (string, error) {
	key, err := decodeKey(keyHex)
	if err != nil {
		return "", err
	}
	tag, err := sum(key, []byte(message))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(tag[:]), nil
}

// Verify recomputes the CMAC and compares the decoded 16-byte tags in constant
// time, following RFC 4493, section 2.5. keyHex and tagHex accept either hex case.
// Malformed keys or tags return false and an error; a well-formed tag that does
// not match returns false, nil. Truncated tags are rejected.
// The timing of AES itself depends on crypto/aes and the platform.
func Verify(keyHex, message, tagHex string) (bool, error) {
	key, err := decodeKey(keyHex)
	if err != nil {
		return false, err
	}
	// Reject invalid lengths before decoding, bounding the decoder's work.
	if len(tagHex) != 32 {
		return false, fmt.Errorf("cmac: MAC must be exactly 32 hexadecimal characters (16 bytes)")
	}
	received, err := hex.DecodeString(tagHex)
	if err != nil {
		return false, fmt.Errorf("cmac: MAC must be valid hexadecimal")
	}
	expected, err := sum(key, []byte(message))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(expected[:], received) == 1, nil
}

func decodeKey(keyHex string) ([]byte, error) {
	// Length is measured in bytes: valid hexadecimal contains only ASCII.
	// This check must precede decoding, including for oversized inputs.
	if len(keyHex) != 32 {
		return nil, fmt.Errorf("cmac: AES-128 key must be exactly 32 hexadecimal characters (16 bytes)")
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		// Do not propagate the decoder error: it can include key material.
		return nil, fmt.Errorf("cmac: key must be valid hexadecimal")
	}
	return key, nil
}
