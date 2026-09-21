![Coverage](https://raw.githubusercontent.com/nao1215/octocovs-central-repo/main/badges/nao1215/jose/coverage.svg)
![Test Execution Time](https://raw.githubusercontent.com/nao1215/octocovs-central-repo/main/badges/nao1215/jose/time.svg)
[![reviewdog](https://github.com/nao1215/jose/actions/workflows/reviewdog.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/reviewdog.yml)
[![LinuxUnitTest](https://github.com/nao1215/jose/actions/workflows/linux_test.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/linux_test.yml)
[![MacUnitTest](https://github.com/nao1215/jose/actions/workflows/mac_test.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/mac_test.yml)
[![WindowsUnitTest](https://github.com/nao1215/jose/actions/workflows/windows.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/windows.yml)
[![E2E](https://github.com/nao1215/jose/actions/workflows/e2e_test.yml/badge.svg)](https://github.com/nao1215/jose/actions/workflows/e2e_test.yml)
[![tested with atago](https://img.shields.io/badge/tested%20with-atago-7c3aed?logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI%2BPHBhdGggZmlsbD0iI2ZmZiIgZD0iTTMuNiA0LjIgMTEuOSAxMmwtOC4zIDcuOC0xLjktMi4yTDcuOSAxMiAxLjcgNi40eiIvPjxyZWN0IGZpbGw9IiNmZmYiIHg9IjEyLjYiIHk9IjE3LjIiIHdpZHRoPSI5LjciIGhlaWdodD0iMi44IiByeD0iMS40Ii8%2BPC9zdmc%2B&logoColor=white)](https://github.com/nao1215/atago)
[![measured with himorime](https://img.shields.io/badge/measured%20with-himorime-d9480f?logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCI%2BPHBhdGggZmlsbD0ibm9uZSIgc3Ryb2tlPSIjZmZmIiBzdHJva2Utd2lkdGg9IjIuNCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBkPSJNNC4yIDE4LjVBOSA5IDAgMSAxIDE5LjggMTguNSIvPjxwYXRoIGZpbGw9Im5vbmUiIHN0cm9rZT0iI2ZmIiBzdHJva2Utd2lkdGg9IjIuNCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBkPSJNMTIgMTQuNSAxNi41IDkiLz48Y2lyY2xlIGZpbGw9IiNmZmYiIGN4PSIxMiIgY3k9IjE0LjUiIHI9IjIuMiIvPjwvc3ZnPg==&logoColor=white)](https://github.com/nao1215/himorime)
[![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/nao1215/jose/total)](https://github.com/nao1215/jose/releases)

# jose

jose is a command line tool for JSON Object Signing and Encryption (JOSE). It
generates keys (JWK), publishes key sets (JWKS), signs and verifies messages
(JWS), and encrypts and decrypts messages (JWE) from the shell, so you can work
with JOSE without writing a program. It is built on
[github.com/lestrrat-go/jwx](https://github.com/lestrrat-go/jwx) (MIT license,
by lestrrat).

Documentation: https://nao1215.github.io/jose/ ([cookbook](https://nao1215.github.io/jose/cookbook/), [reference](https://nao1215.github.io/jose/reference/))

![demo](./doc/img/demo.gif)

## Install

```shell
brew install nao1215/tap/jose
```

Or build from source with Go 1.26 or later. jwx v4 uses `encoding/json/v2`,
which Go 1.26 still keeps behind `GOEXPERIMENT=jsonv2`:

```shell
GOEXPERIMENT=jsonv2 go install github.com/nao1215/jose@latest
```

Prebuilt binaries and .deb/.rpm/.apk packages are on the
[release page](https://github.com/nao1215/jose/releases). jose is tested on
Linux (the main target), macOS, and Windows.

## Quick start

Generate a key, sign a payload, and verify it back:

```shell
jose jwk generate --type EC --curve P-256 --output ec.jwk
echo '{"sub":"alice"}' | jose jws sign --algorithm ES256 --key ec.jwk > token.jws
jose jws verify --algorithm ES256 --key ec.jwk token.jws
```

Every command reads a pipe too, and `jws parse` and `jws verify` take a token
inline:

![pipe](./doc/img/pipe.gif)

Make an ES256 key with a key ID, and print the JWKS a verifier would fetch:

```shell
jose jwk generate --type EC --curve P-256 --kid key-1 --alg ES256 --use sig --output key.jwk
jose jwk public --set key.jwk
```

Those two commands are also what a Bluesky / AT Protocol OAuth confidential
client needs for `private_key_jwt`. The cookbook recipe
[atproto OAuth: keys for a confidential client](https://nao1215.github.io/jose/cookbook/#atproto-oauth-keys-for-a-confidential-client)
covers the client metadata, a hand-signed client assertion, and key rotation.

## What jose does

| You want to | Run |
|:--|:--|
| Generate an RSA, EC, OKP, or oct key, optionally with `kid`, `alg`, and `use` | `jose jwk generate` |
| Turn private keys (JWK or PEM) into a publishable JWKS | `jose jwk public` |
| Sign a payload or a JWT | `jose jws sign` |
| Verify against a key or a JWKS, by algorithm or by `kid` | `jose jws verify` |
| Decode a token without a key | `jose jws parse` |
| Encrypt and decrypt | `jose jwe encrypt`, `jose jwe decrypt` |
| List the algorithm names jose accepts | `jose jwa` |

Every command reads a file, `-`, or a pipe, and writes to standard output or
`--output`; errors go to standard error with exit status 1. The
[reference](https://nao1215.github.io/jose/reference/) lists every flag.

The shell blocks in this README, on the website, and in the cookbook are run
word for word by the end-to-end suite ([atago](https://github.com/nao1215/atago)
specs under `e2e/atago/`), and `cmd/docs_test.go` fails when a block is not.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md) for the
development setup and the local commands that mirror CI (`make test`,
`make e2e`, `make test-fuzz`, `make lint`, `make website`). Security reports are
described in [SECURITY.md](./SECURITY.md), and notable changes are tracked in
[CHANGELOG.md](./CHANGELOG.md).

A GitHub Star motivates continued development.

[![Star History Chart](https://api.star-history.com/svg?repos=nao1215/jose&type=Date)](https://star-history.com/#nao1215/jose&Date)

## Contact

To report a bug or request a feature, open a [GitHub Issue](https://github.com/nao1215/jose/issues),
or run `jose bug-report`.

## License

The jose project is licensed under the [MIT LICENSE](./LICENSE).
