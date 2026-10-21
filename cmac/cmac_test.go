package cmac_test

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/hugoferreiraTI/AES_CMAC_Go/cmac"
)

// Public RFC 4493 test key, not a production secret.
const testKey = "2b7e151628aed2a6abf7158809cf4f3c"
const emptyTag = "bb1d6929e95937287fa37d129b756746"

func TestGenerateStrings(t *testing.T) {
	for _, tt := range []struct {
		name, message, want string
	}{
		{"Empty", "", emptyTag},
		// Additional known answers independently checked with OpenSSL.
		{"UTF8", "Olá, 世界! 👋", "3c5c12c4320c15e21f4af946892bb70d"},
		{"EmbeddedNUL", "A\x00B", "ba91df00b48807dada17ad7009363171"},
		{"SurroundingWhitespace", " \tOlá, 世界! 👋\n ", "a8f7512e95075f0bba17660a858b9dd3"},
		{"LineBreaks", "linha 1\r\nlinha 2\n", "fface320cc537dfdf641bf45ade30e05"},
		{"HexadecimalText", "6bc1bee22e409f96e93d7e117393172a", "c7ee89826806cddb18c4f07d115ba0e6"},
		{"DecomposedUTF8", "Ola\u0301, 世界! 👋", "52539a1f3b521d1f94207372a3e55ab6"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cmac.Generate(testKey, tt.message)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("Generate = %s, want %s", got, tt.want)
			}
			if len(got) != 32 || got != strings.ToLower(got) {
				t.Fatalf("tag must be 32 lowercase hexadecimal characters; got %q", got)
			}
			decoded, err := hex.DecodeString(got)
			if err != nil || len(decoded) != 16 {
				t.Fatalf("tag must decode to 16 bytes; got %d bytes, error %v", len(decoded), err)
			}
			again, err := cmac.Generate(testKey, tt.message)
			if err != nil || again != got {
				t.Fatalf("second Generate = %s, %v; want %s, nil", again, err, got)
			}
			valid, err := cmac.Verify(testKey, tt.message, got)
			if err != nil || !valid {
				t.Fatalf("Verify = %v, %v; want true, nil", valid, err)
			}
		})
	}
}

func TestRFC4493VectorsPublicAPI(t *testing.T) {
	// These are the official byte vectors, exercised through the public API
	// in addition to the existing internal RFC tests.
	for _, tt := range []struct {
		name, messageHex, want string
	}{
		{"Example1_Empty", "", "bb1d6929e95937287fa37d129b756746"},
		{"Example2_16Bytes", "6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
		{"Example3_40Bytes", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "dfa66747de9ae63030ca32611497c827"},
		{"Example4_64Bytes", "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "51f0bebf7e3b9d92fc49741779363cfe"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			messageBytes, err := hex.DecodeString(tt.messageHex)
			if err != nil {
				t.Fatalf("invalid RFC message fixture: %v", err)
			}
			// A Go string preserves every byte, even when it is not valid UTF-8.
			message := string(messageBytes)
			got, err := cmac.Generate(testKey, message)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s\nmessage bytes: %d\ngot:  %s\nwant: %s", tt.name, len(messageBytes), got, tt.want)
			if got != tt.want {
				t.Fatalf("Generate = %s, want %s", got, tt.want)
			}
			valid, err := cmac.Verify(testKey, message, tt.want)
			if err != nil || !valid {
				t.Fatalf("Verify = %v, %v; want true, nil", valid, err)
			}
		})
	}
}

func TestVerifyMismatch(t *testing.T) {
	const message = "Olá, 世界! 👋"
	const tag = "3c5c12c4320c15e21f4af946892bb70d"
	for _, tt := range []struct {
		name, key, message, tag string
	}{
		{"OneMessageByteChanged", testKey, "olá, 世界! 👋", tag},
		{"DifferentKey", "2a7e151628aed2a6abf7158809cf4f3c", message, tag},
		{"DifferentMessageLength", testKey, message + "!", tag},
	} {
		t.Run(tt.name, func(t *testing.T) {
			changedTag, err := cmac.Generate(tt.key, tt.message)
			if err != nil {
				t.Fatal(err)
			}
			if changedTag == tag {
				t.Fatal("the changed key or message must produce a different tag for this fixture")
			}
			valid, err := cmac.Verify(tt.key, tt.message, tt.tag)
			if err != nil || valid {
				t.Fatalf("Verify = %v, %v; want false, nil", valid, err)
			}
		})
	}

	// Change one low-nibble bit in each received tag byte, preserving the
	// hexadecimal format and checking that every byte participates.
	for i := 0; i < 16; i++ {
		t.Run(fmt.Sprintf("TagByte%dChanged", i), func(t *testing.T) {
			received, err := hex.DecodeString(tag)
			if err != nil {
				t.Fatal(err)
			}
			received[i] ^= 1
			valid, err := cmac.Verify(testKey, message, hex.EncodeToString(received))
			if err != nil || valid {
				t.Fatalf("Verify = %v, %v; want false, nil", valid, err)
			}
		})
	}
}

func TestHexCase(t *testing.T) {
	tag, err := cmac.Generate(strings.ToUpper(testKey), "")
	if err != nil || tag != emptyTag {
		t.Fatalf("Generate with uppercase key = %s, %v", tag, err)
	}
	valid, err := cmac.Verify(strings.ToUpper(testKey), "", strings.ToUpper(emptyTag))
	if err != nil || !valid {
		t.Fatalf("Verify with uppercase hex = %v, %v", valid, err)
	}
}

func TestInvalidKeys(t *testing.T) {
	const lengthError = "exactly 32 hexadecimal characters"
	for _, tt := range []struct {
		name, key, errorText string
	}{
		{"Empty", "", lengthError},
		{"NonHex", strings.Repeat("z", 32), "valid hexadecimal"},
		{"InvalidLastCharacter", testKey[:31] + "z", "valid hexadecimal"},
		{"OddLength", testKey[:31], lengthError},
		{"15Bytes", strings.Repeat("00", 15), lengthError},
		{"17Bytes", strings.Repeat("00", 17), lengthError},
		{"AES192", strings.Repeat("00", 24), lengthError},
		{"AES256", strings.Repeat("00", 32), lengthError},
		{"MoreThan32Bytes", strings.Repeat("ab", 33), lengthError},
		{"Prefix", "0x" + testKey, lengthError},
		{"PrefixWith32Characters", "0x" + testKey[:30], "valid hexadecimal"},
		{"Whitespace", " " + testKey + " ", lengthError},
		{"WhitespaceWith32Characters", testKey[:31] + " ", "valid hexadecimal"},
		{"ExcessivelyLargeHex", strings.Repeat("a", 1<<20), lengthError},
		// The length error must take precedence over hexadecimal validation.
		{"ExcessivelyLargeNonHex", strings.Repeat("z", 1<<20), lengthError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tag, genErr := cmac.Generate(tt.key, "message")
			valid, verifyErr := cmac.Verify(tt.key, "message", emptyTag)
			if tag != "" || valid {
				t.Fatal("invalid key produced a tag or successful verification")
			}
			for _, err := range []error{genErr, verifyErr} {
				if err == nil || !strings.Contains(err.Error(), tt.errorText) {
					t.Fatalf("error = %v; want text %q", err, tt.errorText)
				}
				if tt.key != "" && strings.Contains(err.Error(), tt.key) {
					t.Fatal("error exposed the key")
				}
				if len(tt.key) >= 8 && strings.Contains(err.Error(), tt.key[:8]) {
					t.Fatal("error exposed a key fragment")
				}
				if strings.Contains(err.Error(), "U+") {
					t.Fatal("error exposed a character from the key decoder")
				}
			}
		})
	}
}

func TestInvalidMACs(t *testing.T) {
	const lengthError = "exactly 32 hexadecimal characters"
	for _, tt := range []struct {
		name, tag, errorText string
	}{
		{"Empty", "", lengthError},
		{"NonHex", strings.Repeat("g", 32), "valid hexadecimal"},
		{"OddLength", emptyTag[:31], lengthError},
		{"Truncated", emptyTag[:16], lengthError},
		{"15Bytes", emptyTag[:30], lengthError},
		{"17Bytes", emptyTag + "00", lengthError},
		{"Prefix", "0x" + emptyTag, lengthError},
		{"PrefixWith32Characters", "0x" + emptyTag[:30], "valid hexadecimal"},
		{"Whitespace", " " + emptyTag + " ", lengthError},
		{"WhitespaceWith32Characters", emptyTag[:31] + " ", "valid hexadecimal"},
		{"ExcessivelyLargeHex", strings.Repeat("a", 1<<20), lengthError},
		{"ExcessivelyLargeNonHex", strings.Repeat("g", 1<<20), lengthError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := cmac.Verify(testKey, "", tt.tag)
			if valid || err == nil || !strings.Contains(err.Error(), tt.errorText) {
				t.Fatalf("Verify = %v, %v; want false and error containing %q", valid, err, tt.errorText)
			}
			if strings.Contains(err.Error(), testKey) || strings.Contains(err.Error(), testKey[:8]) {
				t.Fatal("error exposed key material")
			}
		})
	}
}

func ExampleGenerate() {
	tag, err := cmac.Generate(testKey, "")
	if err != nil {
		panic(err)
	}
	fmt.Println(tag)
	// Output: bb1d6929e95937287fa37d129b756746
}

func ExampleVerify() {
	valid, err := cmac.Verify(testKey, "", emptyTag)
	if err != nil {
		panic(err)
	}
	fmt.Println(valid)
	// Output: true
}
