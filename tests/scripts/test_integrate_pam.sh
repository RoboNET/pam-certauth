#!/usr/bin/env bash
# Test harness for dist/scripts/integrate-pam.sh.
# Builds a fake /etc/pam.d/sudo in $TMPDIR, runs the helper twice, and
# verifies idempotence + backup creation.

set -euo pipefail

HELPER="$(cd "$(dirname "$0")/../.." && pwd)/dist/scripts/integrate-pam.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/integrate-pam-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/sudo" <<'EOF'
auth       required   pam_unix.so
account    required   pam_unix.so
session    required   pam_unix.so
EOF

# First run: inserts @include and creates backup.
"$HELPER" "$WORK/sudo"
ls "$WORK"/sudo.bak.* >/dev/null 2>&1 || { echo "FAIL: no backup created" >&2; exit 1; }
grep -q '^@include certauth$' "$WORK/sudo" || { echo "FAIL: @include not added" >&2; exit 1; }

# Capture state.
SHA_AFTER_FIRST=$(shasum -a 256 "$WORK/sudo" | awk '{print $1}')

# Second run: must be no-op (already integrated). No new backup.
BACKUPS_BEFORE=$(find "$WORK" -maxdepth 1 -name 'sudo.bak.*' | wc -l | tr -d ' ')
"$HELPER" "$WORK/sudo"
BACKUPS_AFTER=$(find "$WORK" -maxdepth 1 -name 'sudo.bak.*' | wc -l | tr -d ' ')
test "$BACKUPS_BEFORE" = "$BACKUPS_AFTER" || { echo "FAIL: idempotence — extra backup" >&2; exit 1; }

SHA_AFTER_SECOND=$(shasum -a 256 "$WORK/sudo" | awk '{print $1}')
test "$SHA_AFTER_FIRST" = "$SHA_AFTER_SECOND" || { echo "FAIL: idempotence — file changed" >&2; exit 1; }

# Verify @include lands BEFORE the first auth line, not after.
first_match=$(grep -nE '^(auth[[:space:]]|@include certauth$)' "$WORK/sudo" | head -1 | awk -F: '{print $2}')
test "$first_match" = "@include certauth" || { echo "FAIL: @include not before first auth: $first_match" >&2; exit 1; }

echo "ok: integrate-pam.sh handles idempotence and backups"

# --unintegrate round-trip (P1-M).
"$HELPER" --unintegrate "$WORK/sudo"
if grep -qE '^@include certauth(-optional)?$' "$WORK/sudo"; then
    echo "FAIL: --unintegrate did not remove the line" >&2
    exit 1
fi

# Second --unintegrate: must be no-op.
SHA_AFTER_UNINT=$(shasum -a 256 "$WORK/sudo" | awk '{print $1}')
"$HELPER" --unintegrate "$WORK/sudo"
SHA_AFTER_UNINT2=$(shasum -a 256 "$WORK/sudo" | awk '{print $1}')
test "$SHA_AFTER_UNINT" = "$SHA_AFTER_UNINT2" \
    || { echo "FAIL: --unintegrate not idempotent" >&2; exit 1; }

# Re-integrate the optional flavour, then unintegrate it.
"$HELPER" --optional "$WORK/sudo"
grep -q '^@include certauth-optional$' "$WORK/sudo" \
    || { echo "FAIL: --optional did not add line" >&2; exit 1; }
"$HELPER" --unintegrate "$WORK/sudo"
if grep -qE '^@include certauth(-optional)?$' "$WORK/sudo"; then
    echo "FAIL: --unintegrate did not remove --optional line" >&2
    exit 1
fi

# --unintegrate on a missing file is a no-op (exit 0).
"$HELPER" --unintegrate "$WORK/nonexistent" \
    || { echo "FAIL: --unintegrate on missing file should be no-op" >&2; exit 1; }

echo "ok: integrate-pam.sh --unintegrate round-trip"
