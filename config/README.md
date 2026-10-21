# Example configuration

This directory contains the configuration template for the example in
`cmd/cmac`. The library in `cmac/` accepts the key as an argument and does not
read environment variables or files.

| Variable | Required | Format |
| --- | --- | --- |
| `AES_CMAC_KEY` | Yes, for the CLI example | 32 hexadecimal characters representing 16 bytes |

From the project root, create the local file only if it does not already exist:

```sh
test -f config/.env || cp config/.env.example config/.env
go run ./cmd/cmac -message "Hello, world!"
```

The template contains a deliberately public example key. Never reuse it as a
production secret. Real keys must never be logged or committed. `config/.env`
and other local environment files are ignored by Git; `.env.example` templates
remain versionable.

The CLI currently requires `config/.env` to exist and loads it with
`godotenv.Load`. It then reads `AES_CMAC_KEY` from the process environment,
generates a MAC, verifies it, and prints the hexadecimal MAC followed by the
verification result. Already-set environment variables take precedence over
the values in this local file.

The `-message` flag accepts a message string. Without the flag, the example
uses `Payment 2590|sale=42`. The exact string bytes are authenticated, without
normalization or hexadecimal decoding.

`.env` files are for local development. In production applications, prefer
environment variables or secret-management systems and pass the key directly
to `cmac.Generate` or `cmac.Verify`. The library does not require this CLI's
configuration loader.

See the [English README](../README.md) or the
[Brazilian Portuguese README](../README.pt-BR.md) for API, security, and testing
details. `go.mod` stays at the project root to define the Go module.
