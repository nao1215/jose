#!/bin/sh
# shellcheck shell=sh
#
# jwk generate: key types, the curve matrix, the bit-sized oct key, and the
# overwrite regression that left garbage trailing a shorter key.

Describe 'jose jwk generate'
  Include "$SHELLSPEC_SPECDIR/spec_helper.sh"

  BeforeEach 'make_workdir'
  AfterEach 'remove_workdir'

  It 'generates an RSA key as JSON'
    When run jose jwk generate --type RSA --size 2048
    The status should be success
    The output should include '"kty"'
    The output should include 'RSA'
  End

  It 'generates an EC key in PEM format'
    When run jose jwk generate --type EC --curve P-256 --output-format pem
    The status should be success
    The output should include 'BEGIN'
    The output should include 'PRIVATE KEY'
  End

  It 'generates an OKP Ed25519 key'
    When run jose jwk generate --type OKP --curve Ed25519
    The status should be success
    The output should include 'OKP'
  End

  It 'generates an oct key'
    When run jose jwk generate --type oct --size 256
    The status should be success
    The output should include 'oct'
  End

  It 'emits a public key without private fields'
    When run jose jwk generate --type EC --curve P-256 --public-key
    The status should be success
    The output should include '"kty"'
    The output should not include '"d"'
  End

  Describe 'curve matrix'
    It 'rejects the unsupported OKP X448 curve'
      When run jose jwk generate --type OKP --curve X448
      The status should be failure
      The stderr should include 'OKP supports'
    End

    It 'rejects the unsupported OKP Ed448 curve'
      When run jose jwk generate --type OKP --curve Ed448
      The status should be failure
      The stderr should include 'OKP supports'
    End

    It 'requires a curve for EC keys'
      When run jose jwk generate --type EC
      The status should be failure
      The stderr should include 'require --curve'
    End
  End

  Describe 'oct option combinations'
    It 'rejects PEM output for oct keys'
      When run jose jwk generate --type oct --size 256 --output-format pem
      The status should be failure
      The stderr should include 'oct'
      The stderr should include 'json'
    End

    It 'rejects --public-key for oct keys'
      When run jose jwk generate --type oct --size 256 --public-key
      The status should be failure
      The stderr should include 'public key'
    End
  End

  Describe 'overwrite regression'
    # Writing a short EC key over a long RSA key must leave a single parseable
    # key, not RSA bytes trailing the EC JSON. Signing with the file proves it
    # parses, because jwk.ReadFile rejects trailing garbage.
    overwrite_then_sign() {
      jose jwk generate --type RSA --size 4096 --output key.jwk
      jose jwk generate --type EC --curve P-256 --output key.jwk
      printf 'hello' > "$WORK/msg.txt"
      jose jws sign --algorithm ES256 --key key.jwk msg.txt
    }

    It 'leaves a parseable EC key after overwriting a longer RSA key'
      When call overwrite_then_sign
      The status should be success
      The output should be present
    End
  End
End
