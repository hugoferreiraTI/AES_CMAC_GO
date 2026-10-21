package cmac

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"testing"
)

// Public test key from RFC 4493, section 4; never a production secret.
const rfcKeyHex = "2b7e151628aed2a6abf7158809cf4f3c"

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("invalid hexadecimal test fixture: %v", err)
	}
	return decoded
}

func TestRFC4493Vectors(t *testing.T) {
	tests := []struct {
		name       string
		messageHex string
		want       string
	}{
		{"Example1_Empty", "", "bb1d6929e95937287fa37d129b756746"},
		{"Example2_16Bytes", "6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
		{"Example3_40Bytes", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "dfa66747de9ae63030ca32611497c827"},
		{"Example4_64Bytes", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "51f0bebf7e3b9d92fc49741779363cfe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := mustDecodeHex(t, rfcKeyHex)
			// RFC messages are raw bytes, not the ASCII hexadecimal text.
			message := mustDecodeHex(t, tt.messageHex)
			keyBefore, messageBefore := bytes.Clone(key), bytes.Clone(message)
			tag, err := sum(key, message)
			if err != nil {
				t.Fatal(err)
			}
			got := hex.EncodeToString(tag[:])
			t.Logf("%s\nmessage bytes: %d\ngot:  %s\nwant: %s", tt.name, len(message), got, tt.want)
			if got != tt.want {
				t.Fatalf("sum = %s, want %s", got, tt.want)
			}
			if !bytes.Equal(key, keyBefore) || !bytes.Equal(message, messageBefore) {
				t.Fatal("sum modified an input")
			}
		})
	}
}

func TestRFC4493Subkeys(t *testing.T) {
	block, err := aes.NewCipher(mustDecodeHex(t, rfcKeyHex))
	if err != nil {
		t.Fatal(err)
	}
	var l [aes.BlockSize]byte
	block.Encrypt(l[:], l[:])
	k1, k2 := generateSubkeys(block)
	for _, tt := range []struct {
		name string
		got  [aes.BlockSize]byte
		want string
	}{
		{"L", l, "7df76b0c1ab899b33e42f047b91b546f"},
		{"K1", k1, "fbeed618357133667c85e08f7236a8de"},
		{"K2", k2, "f7ddac306ae266ccf90bc11ee46d513b"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := hex.EncodeToString(tt.got[:])
			t.Logf("%s\ngot:  %s\nwant: %s", tt.name, got, tt.want)
			if got != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestBlockBoundaries(t *testing.T) {
	// Independent known-answer fixtures from OpenSSL 3.0.13, using CMAC with
	// AES-128-CBC and the RFC key. No OpenSSL dependency is needed to run tests.
	// Each message contains the consecutive bytes 0, 1, ..., length-1.
	tests := []struct {
		length int
		want   string
	}{
		{1, "2beceaa81bbd0f09a26bc4ad28b7dd18"},
		{15, "ca408858080e7bd3b33d01bacf371965"},
		{17, "039b5275a5bb111e9d2daf0c79442ea1"},
		{31, "d4798230bf11307900db0f0266145ab9"},
		{32, "e9085e5b1ceb861cd00b0bf72ff5111b"},
		{33, "5e869465d92a47f17838b252495e3834"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%dBytes", tt.length), func(t *testing.T) {
			message := make([]byte, tt.length)
			for i := range message {
				message[i] = byte(i)
			}
			tag, err := sum(mustDecodeHex(t, rfcKeyHex), message)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(tag[:]); got != tt.want {
				t.Fatalf("sum = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestSumNilMessage(t *testing.T) {
	tag, err := sum(mustDecodeHex(t, rfcKeyHex), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(tag[:]); got != "bb1d6929e95937287fa37d129b756746" {
		t.Fatalf("sum(nil) = %s", got)
	}
}

func TestSumRejectsNonAES128Keys(t *testing.T) {
	for _, length := range []int{0, 1, 15, 17, 24, 32} {
		t.Run(fmt.Sprintf("%dBytes", length), func(t *testing.T) {
			tag, err := sum(make([]byte, length), []byte("message"))
			if err == nil || tag != [aes.BlockSize]byte{} {
				t.Fatal("expected an error and a zero result")
			}
		})
	}
}

func TestDoubleBlockReduction(t *testing.T) {
	for _, tt := range []struct {
		name, input, want string
	}{
		{"Zero", "00000000000000000000000000000000", "00000000000000000000000000000000"},
		{"CarryBetweenBytes", "00800000000000000000000000000000", "01000000000000000000000000000000"},
		{"HighBitReduction", "80000000000000000000000000000000", "00000000000000000000000000000087"},
		{"AllBitsSet", "ffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffff79"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var input [aes.BlockSize]byte
			copy(input[:], mustDecodeHex(t, tt.input))
			got := doubleBlock(input)
			if hex.EncodeToString(got[:]) != tt.want {
				t.Fatalf("doubleBlock = %x, want %s", got, tt.want)
			}
		})
	}
}
