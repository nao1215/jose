#!/bin/sh
# shellcheck shell=sh
#
# shellspec helper for jose end-to-end tests. These drive the built binary the
# way a user does (subcommands, flags, exit codes, files on disk) so they catch
# regressions the Go unit tests cannot. Each test runs inside a throwaway
# directory created with mktemp, so nothing touches the repository.

set -eu

PROJECT_ROOT="$(cd "$SHELLSPEC_SPECDIR/.." && pwd)"
export PROJECT_ROOT

# JOSE_BIN points at the binary built by `make build`. Override to test another
# build.
JOSE_BIN="${JOSE_BIN:-$PROJECT_ROOT/jose}"
export JOSE_BIN

# jose runs the built binary inside the current working directory ($WORK) so
# that relative key and payload paths resolve there.
jose() {
  ( cd "$WORK" && "$JOSE_BIN" "$@" )
}

# make_workdir creates a fresh, empty working directory and exports WORK.
make_workdir() {
  WORK="$(mktemp -d)"
  export WORK
}

remove_workdir() {
  if [ -n "${WORK:-}" ]; then
    rm -rf "$WORK"
  fi
}

# seed_ec_key generates an EC P-256 key named ec.jwk and a payload.json in the
# working directory. It is the common starting point for the sign/verify and
# encrypt/decrypt flows.
seed_ec_key() {
  printf '{"sub":"alice"}' > "$WORK/payload.json"
  jose jwk generate --type EC --curve P-256 --output ec.jwk >/dev/null
}
