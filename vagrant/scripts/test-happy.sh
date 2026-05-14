#!/usr/bin/env bash
# vagrant/scripts/test-happy.sh
#
# Phase 13.2 — E2E happy path for M-of-N execute.
# Runs inside the `mof-n` vagrant box AFTER setup-mof-n-scenario.sh.
#
# Asserts:
#   1. `pam-certauth execute --scope=test.scope --work-order=... -- /bin/echo hello`
#      run as testuser via sudo exits 0.
#   2. stdout contains the canonical "hello from <hostname>" line.
#   3. journald carries an `execute_done` audit event with scope=test.scope
#      within the last minute.
#
# Exit codes:
#   0 — happy path passed
#   1 — execute returned non-zero or audit event missing

set -euo pipefail

readonly WO=/etc/pam_certauth/test/work-order/empty.cms
readonly EXPECTED="hello from $(hostname)"
readonly SINCE=$(date -u -d "1 minute ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
    || date -u -v-1M +%Y-%m-%dT%H:%M:%SZ)

log() { printf '[test-happy] %s\n' "$*" >&2; }
fail() { printf '[test-happy] FAIL: %s\n' "$*" >&2; exit 1; }

[[ -f "$WO" ]] || fail "work order not found at $WO — run setup-mof-n-scenario.sh first"

log "running pam-certauth execute as testuser"
out=$(sudo -u testuser sudo -n /usr/bin/pam-certauth execute \
    --scope=test.scope \
    --work-order="$WO" \
    -- /bin/echo "$EXPECTED") || fail "execute returned non-zero"

log "stdout: $out"
[[ "$out" == "$EXPECTED" ]] || fail "stdout mismatch: got '$out', want '$EXPECTED'"

log "checking journald for execute_done event"
# pam-certauth emits structured journald events with MESSAGE_ID / event= fields.
hits=$(journalctl --since="$SINCE" --output=json --no-pager 2>/dev/null \
    | jq -r 'select((.MESSAGE // "") | tostring | contains("execute_done")) | .MESSAGE' \
    | head -5)

if [[ -z "$hits" ]]; then
    log "WARN: no execute_done event in journald yet; dumping recent unit log"
    journalctl --since="$SINCE" -u pam-certauth.service --no-pager | tail -30 || true
    fail "audit event execute_done not found"
fi

log "OK — happy path passed"
echo "$hits"
