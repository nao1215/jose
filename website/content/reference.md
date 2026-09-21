---
title: Reference
description: Every jose command and flag, how input and output work, the exit status, and the checks jose applies to keys and algorithms.
toc: true
---

## Conventions

Input. Every command that reads a message or a key file accepts a file path, or
`-` for standard input. With no argument, it reads standard input when that is a
pipe or a redirect. `jose jws parse` and `jose jws verify` also accept a compact
JWS token as the argument itself: a value with three dot-separated base64url
segments is a token, anything else is a file path, so a mistyped file name
reports "failed to open file" rather than a parse error.

Output. Results go to standard output, or to a file with `--output`; `-` means
standard output. Files that `--output` creates are readable by their owner
only. Errors go to standard error.

Exit status. 0 on success, 1 on any failure: a bad flag, a key that does not
fit, a signature that does not verify, a message that does not decrypt.

Keys. `--key` takes a single JWK or a JWK Set. `--key-format pem` reads PEM
instead: PKCS #8, SEC 1 (`EC PRIVATE KEY`), PKCS #1 (`RSA PRIVATE KEY`), or a
public key.

## jose jwk generate

Generates a key and writes the private JWK, or the public one with
`--public-key`.

```shell
jose jwk generate --type EC --curve P-256 --kid key-1 --alg ES256 --use sig --output key.jwk
```

| Flag | Meaning |
|:--|:--|
| `--type`, `-t` | Key type: RSA, EC, OKP, or oct. Required. |
| `--curve`, `-c` | Curve. EC: P-256, P-384, P-521. OKP: Ed25519, X25519. Required for EC and OKP. |
| `--size`, `-s` | Size in bits for RSA and oct keys; a multiple of 8, at least 256. Default 2048. EC and OKP ignore it. |
| `--kid` | Key ID to record in the key. |
| `--alg` | Algorithm to record in the key. It must fit the key; see [Algorithms and keys](#algorithms-and-keys). |
| `--use` | Public key use to record: `sig` or `enc`. It must agree with `--alg`. |
| `--set` | Write a JWK Set (`{"keys":[...]}`) instead of a bare key. |
| `--public-key`, `-p` | Write the public key instead of the private key. Not for oct keys, which have no public half. |
| `--output-format`, `-O` | `json` (default) or `pem`. PEM is available for RSA, EC, and OKP Ed25519 keys; EC keys come out as SEC 1, RSA and Ed25519 keys as PKCS #8. PEM cannot carry `--kid`, `--alg`, `--use`, or `--set`, so those are rejected with it. |
| `--output`, `-o` | Output file. Default standard output. |

## jose jwk public

Reads private keys and writes their public halves. `kid`, `alg`, and `use` are
kept. Several files are merged into one set, in order; two keys with the same
`kid` are rejected. oct keys are rejected, since they have no public half.

```shell
jose jwk public --set key.jwk
```

| Flag | Meaning |
|:--|:--|
| `--set` | Always write a JWK Set, even for one key. Several keys are always written as a set. |
| `--kid` | Key ID to record. Needs exactly one input key. |
| `--alg` | Algorithm to record. Needs exactly one input key, and it must fit the key. |
| `--use` | Public key use to record: `sig` or `enc`. Needs exactly one input key. |
| `--key-format`, `-F` | Format of the input keys: `json` (default) or `pem`. |
| `--output`, `-o` | Output file. Default standard output. |

`--kid`, `--alg`, and `--use` label a key that has no such parameters yet, such
as a PEM key made by openssl. They may replace what the key already carries,
but the result must be consistent: `--alg ES256` on a key that says
`"use":"enc"` is rejected.

## jose jws sign

Signs a payload into a compact JWS. When the key has a `kid`, it is copied into
the protected header.

| Flag | Meaning |
|:--|:--|
| `--algorithm`, `-a` | Signature algorithm. Required; jose never picks one for you. |
| `--key`, `-k` | Key file. It must hold exactly one key. |
| `--key-format`, `-F` | `json` (default) or `pem`. |
| `--header`, `-H` | A JSON object of extra protected header fields, for example `'{"typ":"JWT"}'`. |
| `--output`, `-o` | Output file. Default standard output. |

## jose jws verify

Verifies a JWS and prints its payload. With a JWK Set, every key is tried and
one match is enough. A private key works too: jose derives the public key.

| Flag | Meaning |
|:--|:--|
| `--algorithm`, `-a` | The algorithm to verify with. Required unless `--match-kid` is set. jose never trusts the `alg` in the message, which is what algorithm-confusion attacks exploit. |
| `--match-kid`, `-m` | Verify only with the key whose `kid` matches the message's. That key must carry both `kid` and `alg`. |
| `--key`, `-k` | Key file: a JWK or a JWK Set. |
| `--key-format`, `-F` | `json` (default) or `pem`. |
| `--output`, `-o` | Output file. Default standard output. |

jose checks the signature only. Claims such as `exp`, `nbf`, and `aud` are left
to the caller.

## jose jws parse

Decodes a JWS without verifying it. Use it to read a token, never to trust one.

```shell
echo '{"sub":"alice"}' | jose jws sign --algorithm ES256 --key key.jwk > token.jws
jose jws parse --all token.jws
```

| Flag | Meaning |
|:--|:--|
| `--all`, `-a` | Print the headers and the signature as well as the payload. |

## jose jwe encrypt

Encrypts a payload into a compact JWE. With an asymmetric algorithm, the public
key is enough.

| Flag | Meaning |
|:--|:--|
| `--key`, `-k` | Key file. |
| `--key-encryption`, `-K` | How the content key is wrapped, for example `RSA-OAEP-256`, `ECDH-ES+A256KW`, or `A256KW`. |
| `--content-encryption`, `-c` | How the payload is encrypted: A128CBC-HS256, A128GCM, A192CBC-HS384, A192GCM, A256CBC-HS512, or A256GCM. |
| `--compress`, `-z` | Deflate the payload before encrypting it. |
| `--key-format`, `-F` | `json` (default) or `pem`. |
| `--output`, `-o` | Output file. Default standard output. |

## jose jwe decrypt

Decrypts a JWE and prints the payload.

| Flag | Meaning |
|:--|:--|
| `--key`, `-k` | Key file with the private (or shared) key. |
| `--key-encryption`, `-K` | The key encryption algorithm. When omitted, it is read from the message header. |
| `--key-format`, `-F` | `json` (default) or `pem`. |
| `--output`, `-o` | Output file. Default standard output. |

## jose jwa

Prints the algorithm names jose accepts, one per line. Every value it prints is
one the other commands take; names the jwx library knows but jose cannot use
(the X448 curve, the `none` signature, RSA-OAEP-384) are left out.

```shell
jose jwa --signature
```

| Flag | Meaning |
|:--|:--|
| `--key-type`, `-k` | Key types. |
| `--elliptic-curve`, `-e` | Curves. |
| `--signature`, `-s` | JWS signature algorithms. |
| `--key-encryption`, `-K` | JWE key encryption algorithms. |
| `--content-encryption`, `-c` | JWE content encryption algorithms. |

## Algorithms and keys

`--alg` on `jose jwk generate` and `jose jwk public` accepts an algorithm only
for a key it can serve, following RFC 7518. ES256 means P-256, so ES256 on a
P-384 key is rejected, and an HMAC key must be at least as long as its hash.
The full table is in the cookbook:
[Pick an algorithm for a key](/cookbook/#pick-an-algorithm-for-a-key).

## Other commands

- `jose version` (or `jose --version`, `jose -v`) prints the version.
- `jose completion` prints a completion script for bash, zsh, or fish to
  standard output. It never edits your shell configuration.
- `jose man` installs man pages under `/usr/share/man/man1` and needs root.
- `jose bug-report` opens a pre-filled GitHub issue in your browser, with your
  jose version and runtime.

## Limitations

- OKP keys are Ed25519 and X25519 only; Ed448 and X448 are not supported.
- `jose jws sign` signs with one key at a time, and writes compact
  serialization only.
- `jose jwk generate` makes oct keys of 256 bits or more, so A128KW, A192KW, and
  their GCM forms need a key made elsewhere.
- secp256k1 (ES256K) is not supported.
