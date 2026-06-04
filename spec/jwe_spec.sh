#!/bin/sh
# shellcheck shell=sh
#
# jwe encrypt / decrypt round trip, including --compress and the missing-key
# error.

Describe 'jose jwe'
  Include "$SHELLSPEC_SPECDIR/spec_helper.sh"

  BeforeEach 'setup'
  AfterEach 'remove_workdir'

  setup() {
    make_workdir
    seed_ec_key
  }

  It 'round-trips a payload through encrypt and decrypt'
    roundtrip() {
      jose jwe encrypt --key ec.jwk --key-encryption ECDH-ES \
        --content-encryption A256GCM payload.json > "$WORK/secret.jwe"
      jose jwe decrypt --key ec.jwk secret.jwe
    }
    When call roundtrip
    The status should be success
    The output should equal '{"sub":"alice"}'
  End

  It 'round-trips with compression enabled'
    roundtrip_z() {
      jose jwe encrypt --key ec.jwk --key-encryption ECDH-ES \
        --content-encryption A256GCM --compress payload.json > "$WORK/secret.jwe"
      jose jwe decrypt --key ec.jwk secret.jwe
    }
    When call roundtrip_z
    The status should be success
    The output should equal '{"sub":"alice"}'
  End

  It 'fails to encrypt without a key'
    When run jose jwe encrypt --key-encryption ECDH-ES --content-encryption A256GCM payload.json
    The status should be failure
    The stderr should include 'key file required'
  End

  It 'fails to encrypt with an invalid content encryption'
    When run jose jwe encrypt --key ec.jwk --key-encryption ECDH-ES --content-encryption BOGUS payload.json
    The status should be failure
    The stderr should include 'content encryption'
  End
End
