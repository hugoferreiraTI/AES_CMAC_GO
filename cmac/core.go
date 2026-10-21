package cmac

import (
	"crypto/aes"
	"fmt"
)

// sum implements RFC 4493, section 2.4, over raw message bytes. It does not
// modify either input. Only AES-128 keys are accepted, even though crypto/aes
// also supports other key sizes.
func sum(key, message []byte) ([aes.BlockSize]byte, error) {
	if len(key) != 16 {
		return [aes.BlockSize]byte{}, fmt.Errorf("cmac: AES-128 key must be exactly 16 bytes; got %d bytes", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return [aes.BlockSize]byte{}, fmt.Errorf("cmac: initialize AES-128: %w", err)
	}
	k1, k2 := generateSubkeys(block)

	// Process all but the last block, starting from the all-zero state.
	var state [aes.BlockSize]byte
	for len(message) > aes.BlockSize {
		xorBlock(&state, state[:], message[:aes.BlockSize])
		block.Encrypt(state[:], state[:])
		message = message[aes.BlockSize:]
	}

	var last [aes.BlockSize]byte
	copy(last[:], message)
	if len(message) == aes.BlockSize {
		xorBlock(&last, last[:], k1[:])
	} else {
		// Includes an empty message: append one '1' bit, then zero bits.
		last[len(message)] = 0x80
		xorBlock(&last, last[:], k2[:])
	}
	xorBlock(&state, state[:], last[:])
	block.Encrypt(state[:], state[:])
	return state, nil
}

// xorBlock implements the XOR operation in RFC 4493, section 2.1.
// Both inputs must contain a full block; dst may alias either input exactly.
func xorBlock(dst *[aes.BlockSize]byte, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}
