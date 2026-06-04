#!/bin/sh
# shellcheck shell=sh
#
# jws sign / verify / parse end to end, including the input-path equivalence
# (file, stdin, argument) and the required-algorithm behavior.

Describe 'jose jws'
  Include "$SHELLSPEC_SPECDIR/spec_helper.sh"

  BeforeEach 'setup'
  AfterEach 'remove_workdir'

  setup() {
    make_workdir
    seed_ec_key
    jose jws sign --algorithm ES256 --key ec.jwk payload.json > "$WORK/token.jws"
  }

  Describe 'sign'
    It 'requires an algorithm'
      When run jose jws sign --key ec.jwk payload.json
      The status should be failure
      The stderr should include 'signature algorithm'
    End

    It 'signs a payload into a compact JWS'
      When run jose jws sign --algorithm ES256 --key ec.jwk payload.json
      The status should be success
      # Compact JWS has two dots.
      The output should include '.'
    End

    It 'signs a payload read from stdin via a pipe'
      sign_pipe() {
        cat "$WORK/payload.json" | jose jws sign --algorithm ES256 --key ec.jwk
      }
      When call sign_pipe
      The status should be success
      The output should include '.'
    End
  End

  Describe 'verify'
    It 'verifies and prints the payload'
      When run jose jws verify --algorithm ES256 --key ec.jwk token.jws
      The status should be success
      The output should equal '{"sub":"alice"}'
    End

    It 'verifies a token passed directly as an argument'
      token="$(cat "$WORK/token.jws")"
      When run jose jws verify --algorithm ES256 --key ec.jwk "$token"
      The status should be success
      The output should equal '{"sub":"alice"}'
    End

    It 'verifies a token read from stdin via a pipe'
      verify_pipe() {
        cat "$WORK/token.jws" | jose jws verify --algorithm ES256 --key ec.jwk
      }
      When call verify_pipe
      The status should be success
      The output should equal '{"sub":"alice"}'
    End

    It 'reports a missing file instead of a parse error'
      When run jose jws verify --algorithm ES256 --key ec.jwk does-not-exist.jws
      The status should be failure
      The stderr should include 'failed to open file'
    End

    It 'fails with the wrong key'
      jose jwk generate --type EC --curve P-256 --output other.jwk >/dev/null
      When run jose jws verify --algorithm ES256 --key other.jwk token.jws
      The status should be failure
      The stderr should include 'verify'
    End
  End

  Describe 'parse'
    It 'prints the payload from a file'
      When run jose jws parse token.jws
      The status should be success
      The output should equal '{"sub":"alice"}'
    End

    It 'prints the payload from an inline token argument'
      token="$(cat "$WORK/token.jws")"
      When run jose jws parse "$token"
      The status should be success
      The output should equal '{"sub":"alice"}'
    End

    It 'prints the payload from stdin'
      token="$(cat "$WORK/token.jws")"
      Data "$token"
      When run jose jws parse -
      The status should be success
      The output should equal '{"sub":"alice"}'
    End

    It 'prints all parts with --all'
      When run jose jws parse --all token.jws
      The status should be success
      The output should include 'Payload:'
      The output should include 'Signature 0:'
    End

    It 'reports a missing file instead of a parse error'
      When run jose jws parse does-not-exist.jws
      The status should be failure
      The stderr should include 'failed to open file'
    End
  End
End
