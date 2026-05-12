#!/usr/bin/env bash
#
# verify-attacks.sh — asserts that a hostile-fixture run blocked every
# attack defined in fixtures/ATTACKS.md.
#
# Usage:  verify-attacks.sh <log-file>
#
# Fails (exit 1) if:
#   - Any "PWNED:" line appears in the log.
#   - Any attack ID from $ATTACK_IDS is missing a "SAFE: <id>" line.
#
# Designed to be called from every ecosystem-* job in test-cli.yml.

set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <log-file>" >&2
    exit 2
fi
log=$1

if [ ! -s "$log" ]; then
    echo "FAIL: $log is empty or missing" >&2
    exit 1
fi

# Default attack matrix — overridden via $ATTACK_IDS env if the caller
# wants a subset.
default_ids="ssh-read aws-read gcloud-read gh-token-read env-read \
bashrc-write authorized-keys-write sudo-exec pkexec-exec curl-evil"
ids=${ATTACK_IDS:-$default_ids}

echo "------ verify-attacks.sh: scanning $log ------"
echo "expected attack IDs: $ids"

# Lines may be prefixed by the build tool (cargo wraps `cargo:warning=`,
# npm prepends timestamps, mix routes through stderr). We match `SAFE:`
# / `PWNED:` anywhere in the line, with a single space after the tag and
# the attack id immediately following.

# 1. No PWNED lines.
if grep -E "(^|[^[:alnum:]])PWNED:" "$log"; then
    echo "FAIL: at least one attack succeeded under sbe — see PWNED: lines above" >&2
    exit 1
fi

# 2. SAFE: line present for every expected attack.
missing=()
for id in $ids; do
    if ! grep -qE "(^|[^[:alnum:]])SAFE: $id " "$log"; then
        missing+=("$id")
    fi
done

if [ ${#missing[@]} -gt 0 ]; then
    echo "FAIL: missing SAFE: line(s) for: ${missing[*]}" >&2
    echo "------ log tail ------" >&2
    tail -80 "$log" >&2
    exit 1
fi

echo "OK: all ${ids// /,} attacks were blocked"
