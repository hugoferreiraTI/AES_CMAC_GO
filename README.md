English | [Português](README.pt-BR.md)

# AES-128 CMAC for Go

A small, reusable library for generating and verifying **AES-128 CMAC according
to [RFC 4493](https://www.rfc-editor.org/rfc/rfc4493.html)**. CMAC is a message
authentication code based on a symmetric block cipher, specified in
[NIST SP 800-38B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf).
It provides authenticity and integrity, **not confidentiality**: it does not
encrypt or hide the message. Anyone who knows the shared key can generate valid
MACs.

## Requirements and scope

- Go 1.22 or later. Use a Go version with applicable security fixes in production.
- AES-128 only: a 16-byte key and a full 16-byte MAC, without truncation.
- The `cmac/` library uses only the Go standard library, including `crypto/aes`.
  The example CLI additionally uses `github.com/joho/godotenv` to load its local
  configuration; the library does not depend on this configuration loader.
- The library does not read environment variables, files, or `.env` files. The
  consuming application obtains the key and passes it to the API.

## Public API

Import `github.com/hugoferreiraTI/AES_CMAC_Go/cmac`:

```go
func Generate(keyHex, message string) (string, error)
func Verify(keyHex, message, tagHex string) (bool, error)
```

| Value | Format |
| --- | --- |
| Key | Exactly 32 hexadecimal characters representing a 16-byte AES-128 key |
| Message | A Go string; its exact bytes are authenticated |
| Generated MAC | 32 lowercase hexadecimal characters representing 16 bytes |
| Received MAC | Exactly 32 hexadecimal characters representing 16 bytes |

Keys and received MACs accept uppercase and lowercase hex. Prefixes such as
`0x`, whitespace, invalid characters, AES-192/AES-256 keys, and truncated MACs
are rejected. AES-128-only support and full-length MACs are deliberate scope
choices.

`Generate` returns an empty string and an error for an invalid key. `Verify`
returns `false` and an error for a malformed key or MAC, `false, nil` for a
well-formed MAC that does not match, and `true, nil` for a valid MAC. Key and MAC
lengths are checked before hexadecimal decoding, bounding the decoder's work.
Errors do not include the key or characters from the key decoder.

## Exact message bytes

The API uses `[]byte(message)` without normalization, trimming, character
conversion, or automatic hexadecimal decoding. UTF-8 text uses its UTF-8 bytes,
but a Go string may also contain arbitrary binary bytes, which are preserved.
Spaces, NUL bytes, accents, and line endings all participate in the MAC.
`\n` differs from `\r\n`; composed and decomposed Unicode forms retain their
own bytes.

For example, `"6bc1bee22e409f96e93d7e117393172a"` is a 32-byte text message. It is
different from the 16 bytes represented by that hex string. To authenticate the
represented bytes, the application must call `hex.DecodeString`, handle its
error, and pass `string(decoded)` to the API.

## Installation

The configured module path is `github.com/hugoferreiraTI/AES_CMAC_Go`. Once the
repository content is available at that address, add the package to your
consuming module with:

```sh
go get github.com/hugoferreiraTI/AES_CMAC_Go/cmac
```

Remote availability has not been verified in this preparation. This command
documents the configured address without assuming any published tag or release.

### Working with a local checkout

To test unpublished local changes, add the import to the consuming application's
code and run these commands from its module. Adjust `../AES_go` to the checkout:

```sh
go mod edit -replace=github.com/hugoferreiraTI/AES_CMAC_Go=../AES_go
go mod tidy
```

The `replace` applies only to that consumer. To restore remote resolution:

```sh
go mod edit -dropreplace=github.com/hugoferreiraTI/AES_CMAC_Go
go mod tidy
```

## Generate and Verify example

This example belongs to the consuming application. It gets the key from an
environment variable, calls `Generate`, and calls `Verify`, handling both errors
and a validly formatted MAC that fails verification. In an integration, use the
actual received message and MAC.

```go
package main

import (
    "fmt"
    "os"

    "github.com/hugoferreiraTI/AES_CMAC_Go/cmac"
)

func main() {
    keyHex := os.Getenv("AES_CMAC_KEY")
    message := "Hello, world!"

    tagHex, err := cmac.Generate(keyHex, message)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    fmt.Println("MAC:", tagHex)

    // In a real application, replace this with the received MAC.
    receivedTagHex := tagHex
    valid, err := cmac.Verify(keyHex, message, receivedTagHex)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    if !valid {
        fmt.Fprintln(os.Stderr, "Invalid MAC")
        os.Exit(1)
    }
    fmt.Println("MAC valid")
}
```

## Environment and CLI

For local demonstrations, set an **example-only** key:

```sh
# Public example key only. Never use this value as a production secret.
export AES_CMAC_KEY=00112233445566778899aabbccddeeff
```

Keep real AES keys out of logs and version control. In production, obtain the
key from environment variables, secret-management systems, or equivalent
configuration. Use `.env` files only for local development.

The CLI entry point is `main()` in `cmd/cmac/main.go`. The current CLI requires
`config/.env` to exist and loads it with `godotenv.Load`; already-set environment
variables take precedence. From the repository root, create the file only if it
does not exist, then run the example:

```sh
test -f config/.env || cp config/.env.example config/.env
go run ./cmd/cmac -message "Hello, world!"
```

The template contains a deliberately public example key, never a production
secret. The CLI prints the hexadecimal MAC and then the verification result.
The `-message` flag authenticates the exact bytes of the supplied string. Its
default example message is `Payment 2590|sale=42`. The library is independent of
this CLI and its file-loading requirement. See [configuration details](config/README.md).

## Project structure and RFC mapping

```text
AES_go/
├── cmd/cmac/main.go        # CLI entry point: main()
├── cmac/
│   ├── cmac.go             # Public API: Generate and Verify
│   ├── core.go             # Internal byte-oriented CMAC core
│   ├── subkeys.go          # K1 and K2 generation
│   ├── cmac_test.go        # External public API tests
│   └── core_test.go        # RFC vectors and internal tests
├── config/
│   ├── .env.example        # Public example configuration
│   └── README.md           # CLI configuration instructions
├── .gitignore
├── go.mod
├── go.sum
├── LICENSE
├── README.md               # English documentation
└── README.pt-BR.md          # Brazilian Portuguese documentation
```

| File | Responsibility | RFC 4493 section |
| --- | --- | --- |
| `cmac/cmac.go` | String/hex API, validation, and MAC verification | 2.5 |
| `cmac/core.go` | Byte-oriented core, XOR, padding, and chaining | 2.1 and 2.4 |
| `cmac/subkeys.go` | `L = AES(K, 0)`, shifts, and K1/K2 using Rb `0x87` | 2.1 and 2.3 |
| `cmac/core_test.go` | Official vectors, subkeys, and block boundaries | 4 |
| `cmac/cmac_test.go` | Public API, input validation, and exact-byte behavior | 2.5 and 4 |

The core uses 16-byte blocks with an initially zero state. A complete last block
is XORed with K1. An incomplete last block, including an empty message, receives
`0x80` followed by zeros and is XORed with K2. The result is a full 128-bit MAC.
No custom interfaces or CMAC structs are required; subkey generation uses the
standard `cipher.Block` interface.

## Security notes

- CMAC authenticates data; it does not encrypt it or provide confidentiality.
  Anyone with the key can generate valid MACs.
- Provision 16-byte keys in the consuming application using
  [`crypto/rand.Read`](https://pkg.go.dev/crypto/rand#Read), handling errors. Keep
  keys and subkeys secret and use a key exclusively for CMAC, as described in
  [NIST SP 800-38B, sections 5.2 and 5.3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf#page=10).
  Never log or commit real keys. Do not use passwords directly as keys or reuse
  public test/example keys as production secrets.
- Plan key rotation for the application's usage volume and security requirements,
  counting use across all instances. See [NIST SP 800-38B, appendix B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf#page=18).
  This library does not impose a universal usage limit or track key usage.
- CMAC does not automatically prevent replay. Include a counter or nonce **in
  the authenticated message** and track reuse when accepting messages. See
  [NIST SP 800-38B, appendix C](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf#page=19).
- Limit message sizes, request volume, and failed verification attempts in the
  consuming application. Early rejection of oversized keys/MACs does not replace
  those limits.
- Prefer environment variables or secret-management systems in production.
  Local `.env` files are development configuration, not a requirement of the
  library. Keep them out of version control.

`Verify` compares the two decoded 16-byte MACs with
[`crypto/subtle.ConstantTimeCompare`](https://pkg.go.dev/crypto/subtle#ConstantTimeCompare),
whose timing does not depend on their contents for equal lengths. This does not
make the entire operation universally constant-time: AES timing depends on the
implementation and platform, as documented by [`crypto/aes`](https://pkg.go.dev/crypto/aes).

## Testing

Run from the repository root:

```sh
go test -v ./...
go test -race -cover ./...
go vet ./...
go test -v -run TestRFC4493 ./...
```

All four official RFC 4493 vectors are tested through both the internal core and
the public API. Hex-encoded vector messages are decoded into bytes first, then
converted to strings for public API tests. Verbose RFC tests use `t.Logf` to show
the case, message length, calculated MAC, and expected MAC. Subkey tests also show
L, K1, and K2.

| Official vector | Message bytes | Expected MAC |
| --- | ---: | --- |
| 1 | 0 | `bb1d6929e95937287fa37d129b756746` |
| 2 | 16 | `070a16b46b4d4144f79bdd9dd04a287c` |
| 3 | 40 | `dfa66747de9ae63030ca32611497c827` |
| 4 | 64 | `51f0bebf7e3b9d92fc49741779363cfe` |

Additional tests cover block boundaries, output format, determinism, composed
and decomposed UTF-8, NUL, spaces, line endings, hexadecimal text as a message,
invalid keys/MACs, AES-192/AES-256 rejection, truncation, and oversized 1 MiB
inputs. They also check changes to one message/key byte and one nibble in every
MAC byte. Non-English text in test messages is intentional byte-preservation
data; those fixtures and their expected values are unchanged.

Additional known-answer messages were checked with OpenSSL 3.0.13. Running tests
does not require OpenSSL. The external `cmac_test` package uses only the public
API. If the development tool `govulncheck` is installed, run `govulncheck ./...`;
distinguish reachable vulnerabilities from alerts without a call path. A missing
tool does not mean a vulnerability scan has been completed.

## License

This project is available under the [MIT license](LICENSE).
Copyright (c) 2026 Hugo Ferreira Ferro.

Passing vectors and tests demonstrates tested behavior; it does not constitute
NIST/FIPS certification or validation.

## References

- [RFC 4493 — The AES-CMAC Algorithm](https://www.rfc-editor.org/rfc/rfc4493.html)
- [NIST SP 800-38B — The CMAC Mode for Authentication](https://csrc.nist.gov/pubs/sp/800/38/b/upd1/final)
  ([official PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf))
- [FIPS 197 — Advanced Encryption Standard](https://csrc.nist.gov/pubs/fips/197/final)
