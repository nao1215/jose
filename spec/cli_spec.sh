#!/bin/sh
# shellcheck shell=sh
#
# CLI surface: help text, version, and unknown commands. These do not need any
# files, so they run the binary directly.

Describe 'jose CLI surface'
  Include "$SHELLSPEC_SPECDIR/spec_helper.sh"

  BeforeEach 'make_workdir'
  AfterEach 'remove_workdir'

  Describe 'root help'
    It 'prints usage with no arguments'
      When run jose
      The status should be success
      The output should include 'JSON Object Signing and Encryption'
      The output should include 'Available Commands:'
      The output should include 'jwk'
      The output should include 'jws'
      The output should include 'jwe'
    End

    It 'prints usage with --help'
      When run jose --help
      The status should be success
      The output should include 'Usage:'
      The output should include 'jwa'
    End
  End

  Describe 'version'
    It 'prints the version'
      When run jose version
      The status should be success
      The output should include 'jose version'
      The output should include 'MIT LICENSE'
    End
  End

  Describe 'unknown command'
    It 'fails and reports the unknown command'
      When run jose frobnicate
      The status should be failure
      The stderr should include 'unknown command'
    End
  End

  Describe 'jwa lists algorithms'
    It 'lists the key types'
      When run jose jwa --key-type
      The status should be success
      The output should include 'RSA'
      The output should include 'oct'
    End

    It 'fails when no option is given'
      When run jose jwa
      The status should be failure
      The stderr should be present
    End
  End
End
