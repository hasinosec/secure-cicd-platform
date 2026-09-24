#!/usr/bin/env bash
# Build the insecure test fixture that the scanners are asserted against.
#
# Why this script exists:
#   GitHub push protection correctly refuses any commit containing something
#   shaped like an AWS key -- including a fake one planted as a test fixture.
#   Allowlisting the secret would have "fixed" the push by teaching the
#   repository to ignore exactly the class of finding this pipeline exists to
#   catch. So the repository stores a placeholder, and the fixture is built
#   here, at scan time, into a file that is never committed.
#
# The generated values are random, throwaway, and have never been valid
# anywhere. They exist only so gitleaks has a genuine pattern to detect.
set -euo pipefail

SRC="${1:-Dockerfile.weak}"
OUT="${2:-Dockerfile.weak.scan}"

# No pipes here on purpose: `tr -dc ... </dev/urandom | head -c N` makes head
# close the pipe, tr dies on SIGPIPE, and under `set -o pipefail` the whole
# script aborts with no output. Bash's own RANDOM avoids the problem entirely.
rand() {
	local set="$1" n="$2" out="" i
	for ((i = 0; i < n; i++)); do out+="${set:RANDOM % ${#set}:1}"; done
	printf '%s' "$out"
}

UPPER_NUM="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
ALPHANUM="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

# Assembled from fragments so no credential-shaped literal appears in source.
KEY_ID="AKI""A$(rand "$UPPER_NUM" 16)"
KEY_SECRET="$(rand "$ALPHANUM" 40)"

sed -e "s|__TEST_AWS_ACCESS_KEY_ID__|${KEY_ID}|" \
	-e "s|__TEST_AWS_SECRET_ACCESS_KEY__|${KEY_SECRET}|" \
	"$SRC" >"$OUT"

echo "wrote $OUT with a synthetic throwaway credential pair"
