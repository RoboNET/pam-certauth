#!/usr/bin/env bash
# integrate-pam.sh — insert "@include certauth" (or "@include certauth-optional"
# with --optional) into a PAM service file.
#
# Usage:
#   sudo integrate-pam.sh /etc/pam.d/sudo
#   sudo integrate-pam.sh --optional /etc/pam.d/sudo
#
# Behaviour:
#   1. Refuses to run if the target file does not exist.
#   2. If "@include <snippet>" is already present, exits 0 (no-op).
#   3. Otherwise: copies target to <target>.bak.<UTC-timestamp>, then inserts
#      "@include <snippet>" immediately before the first non-comment "auth"
#      line. Atomic via temp file + mv.

set -euo pipefail

snippet="certauth"
mode="integrate"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --optional)
            snippet="certauth-optional"
            shift
            ;;
        --strict)
            snippet="certauth"
            shift
            ;;
        --unintegrate)
            mode="unintegrate"
            shift
            ;;
        --)
            shift
            break
            ;;
        --*)
            echo "error: unknown flag: $1" >&2
            exit 64
            ;;
        *)
            break
            ;;
    esac
done

if [[ $# -ne 1 ]]; then
    echo "usage: $0 [--optional|--strict|--unintegrate] <pam.d-file>" >&2
    exit 64
fi

target="$1"
include_line="@include ${snippet}"

# P1-M: --unintegrate removes any "@include certauth" / "@include certauth-optional"
# line from <target>. Idempotent: missing file or missing line ⇒ exit 0.
if [[ "$mode" == "unintegrate" ]]; then
    if [[ ! -f "$target" ]]; then
        echo "info: $target does not exist (no-op)"
        exit 0
    fi
    # Match either flavour regardless of which one was requested.
    if ! grep -qE '^[[:space:]]*@include[[:space:]]+certauth(-optional)?[[:space:]]*$' "$target"; then
        echo "info: $target has no certauth @include line (no-op)"
        exit 0
    fi
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    backup="${target}.bak.${ts}"
    cp -p "$target" "$backup"
    echo "info: backup written to $backup"
    tmpfile="$(mktemp "${target}.XXXXXX")"
    sed -E '/^[[:space:]]*@include[[:space:]]+certauth(-optional)?[[:space:]]*$/d' \
        "$target" > "$tmpfile"
    if chmod --reference="$target" "$tmpfile" 2>/dev/null; then
        :
    else
        perms="$(stat -c '%a' "$target" 2>/dev/null || stat -f '%Lp' "$target" 2>/dev/null || echo 644)"
        chmod "$perms" "$tmpfile"
    fi
    chown --reference="$target" "$tmpfile" 2>/dev/null || true
    mv "$tmpfile" "$target"
    echo "info: $target updated (certauth @include removed)"
    exit 0
fi

if [[ ! -f "$target" ]]; then
    echo "error: $target does not exist" >&2
    exit 66
fi

if grep -qxF "$include_line" "$target"; then
    echo "info: $target already includes ${snippet} (no-op)"
    exit 0
fi

ts="$(date -u +%Y%m%dT%H%M%SZ)"
backup="${target}.bak.${ts}"
cp -p "$target" "$backup"
echo "info: backup written to $backup"

tmpfile="$(mktemp "${target}.XXXXXX")"
inserted=0
while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ $inserted -eq 0 && "$line" =~ ^[[:space:]]*auth[[:space:]] ]]; then
        printf '%s\n' "$include_line" >> "$tmpfile"
        inserted=1
    fi
    printf '%s\n' "$line" >> "$tmpfile"
done < "$target"

if [[ $inserted -eq 0 ]]; then
    # No `auth` line present — append at end.
    printf '%s\n' "$include_line" >> "$tmpfile"
fi

# Preserve mode/owner. `chmod --reference` and `chown --reference` are GNU
# coreutils features; on BSD/macOS dev hosts they're absent and the script
# is intended to run on Linux targets only.
if chmod --reference="$target" "$tmpfile" 2>/dev/null; then
    :
else
    # Fall back to a perms read on systems without --reference.
    perms="$(stat -c '%a' "$target" 2>/dev/null || stat -f '%Lp' "$target" 2>/dev/null || echo 644)"
    chmod "$perms" "$tmpfile"
fi
chown --reference="$target" "$tmpfile" 2>/dev/null || true

mv "$tmpfile" "$target"
echo "info: $target updated (${snippet})"
