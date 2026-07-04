#!/usr/bin/env bash
#
# run.sh builds jose from this checkout (jwx v4 needs GOEXPERIMENT=jsonv2) and
# runs the atago end-to-end suite (e2e/atago/*.atago.yaml) against the real
# binary.
#
# The test DEFINITIONS are atago YAML — this script is only the environment
# bootstrap (a plain shell program, not a test framework). The specs are fully
# hermetic: each scenario generates its own keys and payloads inside its
# isolated ${workdir}, so no external fixtures are needed.
#
# Usage: e2e/run.sh [atago args...]        (e.g. e2e/run.sh --filter jws)
#
# Coverage mode (used by `make coverage`, NOT by `make e2e`): set COVER=1 to
# build jose with `go build -cover` instead of a plain build, so the binary the
# specs exercise emits Go runtime coverage. The caller must also export
# GOCOVERDIR to a pre-created directory; atago passes the environment through to
# the jose child process (no spec uses clear_env), so each jose invocation
# writes its own covdata there. The DEFAULT (COVER unset) path is unchanged.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

if ! command -v atago >/dev/null 2>&1; then
	echo "e2e: atago is not installed. Install it from https://github.com/nao1215/atago" >&2
	echo "e2e: e.g. 'go install github.com/nao1215/atago@latest' (CI uses nao1215/setup-atago)" >&2
	exit 127
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/jose-e2e.XXXXXX")"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
mkdir -p "$TMP/bin"

if [ "${COVER:-}" = "1" ]; then
	echo "e2e: building coverage-instrumented jose (GOEXPERIMENT=jsonv2, -cover)..."
	(cd "$REPO_ROOT" && env GOEXPERIMENT=jsonv2 CGO_ENABLED=0 \
		go build -cover -covermode=atomic -coverpkg=./... -o "$TMP/bin/jose" main.go)
else
	echo "e2e: building jose (GOEXPERIMENT=jsonv2)..."
	(cd "$REPO_ROOT" && env GOEXPERIMENT=jsonv2 CGO_ENABLED=0 go build -o "$TMP/bin/jose" main.go)
fi

# Put the e2e-built jose first on PATH so the specs exercise that binary.
export PATH="$TMP/bin:$PATH"

echo "e2e: jose $("$TMP/bin/jose" version | head -1)"
# Extra args (e.g. --filter X) go before the path so the flag parser sees them.
atago run "$@" "$SCRIPT_DIR/atago"
