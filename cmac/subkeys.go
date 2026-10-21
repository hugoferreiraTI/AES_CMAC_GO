package cmac

import (
	"crypto/aes"
	"crypto/cipher"
)

// generateSubkeys implements RFC 4493, section 2.3. block is the AES-128
// cipher created by sum, using Go's standard cipher.Block interface.
func generateSubkeys(block cipher.Block) (k1, k2 [aes.BlockSize]byte) {
	var l [aes.BlockSize]byte
	block.Encrypt(l[:], l[:]) // L = AES-128(K, 0^128).
	k1 = doubleBlock(l)
	k2 = doubleBlock(k1)
	return k1, k2
}

func doubleBlock(input [aes.BlockSize]byte) [aes.BlockSize]byte {
	shifted := leftShiftOneBit(input)
	// Rb = 0^120 || 0x87. The mask applies Rb only when MSB(input) = 1,
	// without branching on the secret-derived input.
	mask := byte(0) - (input[0] >> 7)
	shifted[aes.BlockSize-1] ^= 0x87 & mask
	return shifted
}

// leftShiftOneBit shifts the full 128-bit string, most-significant byte first,
// discarding its highest bit (RFC 4493, section 2.1).
func leftShiftOneBit(input [aes.BlockSize]byte) (shifted [aes.BlockSize]byte) {
	var carry byte
	for i := aes.BlockSize - 1; i >= 0; i-- {
		shifted[i] = input[i]<<1 | carry
		carry = input[i] >> 7
	}
	return shifted
}
