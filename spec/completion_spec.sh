#!/bin/sh
# shellcheck shell=sh
#
# completion must write a script to stdout for an explicit shell and must not
# create files or edit shell configuration. An unknown shell is an error.

Describe 'jose completion'
  Include "$SHELLSPEC_SPECDIR/spec_helper.sh"

  BeforeEach 'make_workdir'
  AfterEach 'remove_workdir'

  It 'writes a bash completion script to stdout'
    When run jose completion bash
    The status should be success
    The output should include 'bash completion'
  End

  It 'writes a zsh completion script to stdout'
    When run jose completion zsh
    The status should be success
    The output should include 'compdef'
  End

  It 'writes a fish completion script to stdout'
    When run jose completion fish
    The status should be success
    The output should include 'fish'
  End

  It 'requires a shell argument'
    When run jose completion
    The status should be failure
    The stderr should be present
  End

  It 'rejects an unknown shell'
    When run jose completion powershell
    The status should be failure
    The stderr should be present
  End

  It 'does not create files in the working directory'
    jose completion zsh > /dev/null
    When call ls -A "$WORK"
    The status should be success
    The output should equal ''
  End
End
