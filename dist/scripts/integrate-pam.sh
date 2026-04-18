#!/usr/bin/env bash
# integrate-pam.sh — insert "@include <snippet>" + session-line into a PAM service.
#
# Usage:
#   sudo integrate-pam.sh [--mode=2fa|optional|cert-only]
#                         [--enable-greeter-messages|--no-greeter-messages]
#                         <pam.d-file>
#   sudo integrate-pam.sh --unintegrate <pam.d-file>
#
# Modes (canonical interface, --mode=...):
#   2fa        snippet=certauth          (default; cert + password, classic 2FA)
#   optional   snippet=certauth-optional (cert OR password; phased rollout)
#   cert-only  snippet=certauth-only     (cert is sole factor — LOCKOUT-STRICT)
#
# fly-dm greeter tweak (display manager targets only):
#   When the target is /etc/pam.d/fly-dm or /etc/pam.d/fly-dm-np, this script
#   also patches /etc/X11/fly-dm/fly-dmrc so that fly-dm forwards
#   PAM_TEXT_INFO (host_id banner, p12 wrong-pin diagnostic) to the greeter
#   UI by setting `greeter-show-messages = true` under `[greeter]`.
#   * --enable-greeter-messages — explicit opt-in (default ON for fly-dm*).
#   * --no-greeter-messages     — disable (CI / non-interactive deploys).
#   The tweak is idempotent and never reverted on --unintegrate.
#
# Deprecated aliases (still accepted for BC, emit deprecation note on stderr):
#   --strict     ≡ --mode=2fa
#   --optional   ≡ --mode=optional
#
# Behaviour (two-include pattern, 0.3.12+):
#   1. Refuses to run if the target file does not exist.
#   2. Inserts "@include <snippet>" (auth + account phases) into the auth
#      block. Placement:
#        - if file contains `auth ... pam_parsec_mac.so` → AFTER it
#          (avoids success=done jump skipping pam_parsec_mac, which
#          breaks account-phase on Astra SE with МКЦ enabled);
#        - else → BEFORE the first `auth` line.
#      Idempotent: line already present ⇒ skipped.
#   3. Additionally inserts `session required pam_certauth.so` AFTER
#      `@include common-session` (or after the last session-phase line
#      if common-session is absent), so our session-phase runs AFTER
#      `pam_systemd.so` has populated `XDG_SESSION_ID` in the PAM
#      environment. Without this, monitord cannot bind USB-removal
#      actions (Lock/Logout) to the user's logind session.
#      Idempotent: line already present ⇒ skipped.
#   4. Backs up to <target>.bak.<UTC-timestamp> before any edit (single
#      backup per invocation even if both insertions run).
#
# --unintegrate:
#   * Removes both `@include certauth*` and the explicit
#     `session required pam_certauth.so` line. Idempotent.

set -euo pipefail

snippet="certauth"
mode_op="integrate"
# greeter_messages: "" (auto = ON for fly-dm targets), "on", "off".
greeter_messages=""

mode_to_snippet() {
    case "$1" in
        2fa)        echo "certauth" ;;
        optional)   echo "certauth-optional" ;;
        cert-only)  echo "certauth-only" ;;
        *)
            echo "error: unknown --mode value: $1 (expected 2fa|optional|cert-only)" >&2
            exit 64
            ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode=*)
            snippet="$(mode_to_snippet "${1#--mode=}")"
            shift
            ;;
        --mode)
            if [[ $# -lt 2 ]]; then
                echo "error: --mode requires an argument (2fa|optional|cert-only)" >&2
                exit 64
            fi
            snippet="$(mode_to_snippet "$2")"
            shift 2
            ;;
        --optional)
            echo "warning: --optional is deprecated, use --mode=optional" >&2
            snippet="certauth-optional"
            shift
            ;;
        --strict)
            echo "warning: --strict is deprecated, use --mode=2fa" >&2
            snippet="certauth"
            shift
            ;;
        --unintegrate)
            mode_op="unintegrate"
            shift
            ;;
        --enable-greeter-messages)
            greeter_messages="on"
            shift
            ;;
        --no-greeter-messages)
            greeter_messages="off"
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
    echo "usage: $0 [--mode=2fa|optional|cert-only] [--enable-greeter-messages|--no-greeter-messages] [--unintegrate] <pam.d-file>" >&2
    echo "       --mode=cert-only is the lockout-strict mode (no password fallback)" >&2
    exit 64
fi

target="$1"

# Regex for the session-phase certauth line we manage. Lenient on whitespace,
# strict on module name; matches lines like:
#   session  required  pam_certauth.so
#   session required pam_certauth.so
SESSION_LINE_RE='^[[:space:]]*session[[:space:]]+required[[:space:]]+pam_certauth\.so[[:space:]]*$'
SESSION_LINE_CANONICAL='session    required   pam_certauth.so'

# Copy permissions+owner from a reference file to a tmpfile.
preserve_attrs() {
    local ref="$1"
    local tmp="$2"
    if chmod --reference="$ref" "$tmp" 2>/dev/null; then
        :
    else
        local perms
        perms="$(stat -c '%a' "$ref" 2>/dev/null || stat -f '%Lp' "$ref" 2>/dev/null || echo 644)"
        chmod "$perms" "$tmp"
    fi
    chown --reference="$ref" "$tmp" 2>/dev/null || true
}

# -----------------------------------------------------------------------------
# --unintegrate: strip both @include certauth* and session required pam_certauth.
# -----------------------------------------------------------------------------
if [[ "$mode_op" == "unintegrate" ]]; then
    if [[ ! -f "$target" ]]; then
        echo "info: $target does not exist (no-op)"
        exit 0
    fi
    has_include=0
    has_session=0
    if grep -qE '^[[:space:]]*@include[[:space:]]+certauth(-optional|-only)?[[:space:]]*$' "$target"; then
        has_include=1
    fi
    if grep -qE "$SESSION_LINE_RE" "$target"; then
        has_session=1
    fi
    if [[ $has_include -eq 0 && $has_session -eq 0 ]]; then
        echo "info: $target has no certauth lines (no-op)"
        exit 0
    fi
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    backup="${target}.bak.${ts}"
    cp -p "$target" "$backup"
    echo "info: backup written to $backup"
    tmpfile="$(mktemp "${target}.XXXXXX")"
    sed -E \
        -e '/^[[:space:]]*@include[[:space:]]+certauth(-optional|-only)?[[:space:]]*$/d' \
        -e '/^[[:space:]]*session[[:space:]]+required[[:space:]]+pam_certauth\.so[[:space:]]*$/d' \
        "$target" > "$tmpfile"
    preserve_attrs "$target" "$tmpfile"
    mv "$tmpfile" "$target"
    echo "info: $target updated (certauth lines removed)"
    exit 0
fi

if [[ ! -f "$target" ]]; then
    echo "error: $target does not exist" >&2
    exit 66
fi

include_line="@include ${snippet}"

# Decide which actions are still needed (for idempotence + backup-skip).
need_include=1
if grep -qxF "$include_line" "$target"; then
    need_include=0
fi
need_session=1
if grep -qE "$SESSION_LINE_RE" "$target"; then
    need_session=0
fi

if [[ $need_include -eq 0 && $need_session -eq 0 ]]; then
    echo "info: $target already integrated (no-op)"
    exit 0
fi

ts="$(date -u +%Y%m%dT%H%M%SZ)"
backup="${target}.bak.${ts}"
cp -p "$target" "$backup"
echo "info: backup written to $backup"

tmpfile="$(mktemp "${target}.XXXXXX")"

# -----------------------------------------------------------------------------
# Pass 1: insert @include for auth/account, if needed.
# -----------------------------------------------------------------------------
if [[ $need_include -eq 1 ]]; then
    if grep -qE '^[[:space:]]*auth[[:space:]].*pam_parsec_mac\.so' "$target"; then
        insert_mode="after-parsec-mac"
    else
        insert_mode="before-first-auth"
    fi

    inserted=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ $inserted -eq 0 && "$insert_mode" == "before-first-auth" \
              && "$line" =~ ^[[:space:]]*auth[[:space:]] ]]; then
            printf '%s\n' "$include_line" >> "$tmpfile"
            inserted=1
        fi
        printf '%s\n' "$line" >> "$tmpfile"
        if [[ $inserted -eq 0 && "$insert_mode" == "after-parsec-mac" \
              && "$line" =~ ^[[:space:]]*auth[[:space:]].*pam_parsec_mac\.so ]]; then
            printf '%s\n' "$include_line" >> "$tmpfile"
            inserted=1
        fi
    done < "$target"

    if [[ $inserted -eq 0 ]]; then
        # No anchor line present — append at end. (Rare: file with no
        # `auth` phase at all.)
        printf '%s\n' "$include_line" >> "$tmpfile"
    fi
else
    cp "$target" "$tmpfile"
fi

# -----------------------------------------------------------------------------
# Pass 2: insert `session required pam_certauth.so` after @include common-session
# (or after the last session-phase line if common-session is absent).
#
# Anchor priority:
#   1. last line matching `^[[:space:]]*@include[[:space:]]+common-session`
#   2. last line matching `^[[:space:]]*session[[:space:]]` (any module)
#   3. append at EOF
# -----------------------------------------------------------------------------
if [[ $need_session -eq 1 ]]; then
    tmpfile2="$(mktemp "${target}.XXXXXX")"

    # Find anchor line number (1-based). Use grep -n to be deterministic.
    anchor_line=""
    if anchor_line=$(grep -nE '^[[:space:]]*@include[[:space:]]+common-session([[:space:]]|$)' \
                        "$tmpfile" | tail -1 | cut -d: -f1) && [[ -n "$anchor_line" ]]; then
        :
    elif anchor_line=$(grep -nE '^[[:space:]]*session[[:space:]]' \
                        "$tmpfile" | tail -1 | cut -d: -f1) && [[ -n "$anchor_line" ]]; then
        :
    else
        anchor_line=""
    fi

    if [[ -n "$anchor_line" ]]; then
        current=0
        while IFS= read -r line || [[ -n "$line" ]]; do
            current=$((current + 1))
            printf '%s\n' "$line" >> "$tmpfile2"
            if [[ "$current" -eq "$anchor_line" ]]; then
                printf '%s\n' "$SESSION_LINE_CANONICAL" >> "$tmpfile2"
            fi
        done < "$tmpfile"
    else
        cp "$tmpfile" "$tmpfile2"
        printf '%s\n' "$SESSION_LINE_CANONICAL" >> "$tmpfile2"
    fi

    mv "$tmpfile2" "$tmpfile"
fi

preserve_attrs "$target" "$tmpfile"
mv "$tmpfile" "$target"

msg_parts=()
[[ $need_include -eq 1 ]] && msg_parts+=("${snippet}")
[[ $need_session -eq 1 ]] && msg_parts+=("session-line")
echo "info: $target updated (${msg_parts[*]})"

# -----------------------------------------------------------------------------
# Optional: patch /etc/X11/fly-dm/fly-dmrc so PAM_TEXT_INFO surfaces in the
# fly-dm greeter UI. Only runs when target is fly-dm or fly-dm-np.
# -----------------------------------------------------------------------------
FLYDM_CONFIG="/etc/X11/fly-dm/fly-dmrc"

patch_fly_dmrc() {
    local cfg="$1"
    if [[ ! -f "$cfg" ]]; then
        echo "info: $cfg not found, skipping greeter-messages tweak"
        return 1
    fi

    # Idempotence: option already true under [greeter]?
    if awk '
        BEGIN { in_g = 0; found = 0 }
        /^[[:space:]]*\[/ {
            line = $0
            sub(/^[[:space:]]*\[/, "", line); sub(/\].*$/, "", line)
            gsub(/[[:space:]]/, "", line)
            in_g = (tolower(line) == "greeter") ? 1 : 0
            next
        }
        in_g && /^[[:space:]]*[Gg][Rr][Ee][Ee][Tt][Ee][Rr]-[Ss][Hh][Oo][Ww]-[Mm][Ee][Ss][Ss][Aa][Gg][Ee][Ss][[:space:]]*=/ {
            v = $0
            sub(/^[^=]*=[[:space:]]*/, "", v)
            sub(/[[:space:]#;].*$/, "", v)
            if (tolower(v) == "true" || tolower(v) == "yes" || v == "1") { found = 1 }
            exit
        }
        END { exit (found ? 0 : 1) }
    ' "$cfg"; then
        echo "info: $cfg already has greeter-show-messages = true (no-op)"
        return 1
    fi

    local ts_local
    ts_local="$(date -u +%Y%m%dT%H%M%SZ)"
    local backup_local="${cfg}.bak.${ts_local}"
    cp -p "$cfg" "$backup_local"
    echo "info: backup written to $backup_local"

    local tmp_cfg
    tmp_cfg="$(mktemp "${cfg}.XXXXXX")"

    # First, classify: does [greeter] section exist? does the option already exist?
    local scan
    scan="$(awk '
        BEGIN { in_g = 0; have_greeter = 0; have_opt = 0 }
        /^[[:space:]]*\[/ {
            sname = $0
            sub(/^[[:space:]]*\[/, "", sname); sub(/\].*$/, "", sname)
            gsub(/[[:space:]]/, "", sname)
            if (tolower(sname) == "greeter") { in_g = 1; have_greeter = 1 } else { in_g = 0 }
            next
        }
        in_g && /^[[:space:]]*[Gg][Rr][Ee][Ee][Tt][Ee][Rr]-[Ss][Hh][Oo][Ww]-[Mm][Ee][Ss][Ss][Aa][Gg][Ee][Ss][[:space:]]*=/ {
            have_opt = 1
        }
        END { print have_greeter "," have_opt }
    ' "$cfg")"
    local have_greeter="${scan%,*}"
    local have_opt="${scan#*,}"

    if [[ "$have_opt" == "1" ]]; then
        # Replace in-place inside [greeter] section.
        awk '
            BEGIN { in_g = 0 }
            /^[[:space:]]*\[/ {
                sname = $0
                sub(/^[[:space:]]*\[/, "", sname); sub(/\].*$/, "", sname)
                gsub(/[[:space:]]/, "", sname)
                if (tolower(sname) == "greeter") { in_g = 1 } else { in_g = 0 }
                print
                next
            }
            in_g && /^[[:space:]]*[Gg][Rr][Ee][Ee][Tt][Ee][Rr]-[Ss][Hh][Oo][Ww]-[Mm][Ee][Ss][Ss][Aa][Gg][Ee][Ss][[:space:]]*=/ {
                print "greeter-show-messages = true"
                next
            }
            { print }
        ' "$cfg" > "$tmp_cfg"
    elif [[ "$have_greeter" == "1" ]]; then
        # Insert immediately after the [greeter] header.
        awk '
            BEGIN { inserted = 0 }
            {
                print
                if (inserted == 0) {
                    line = $0
                    sname = line
                    sub(/^[[:space:]]*\[/, "", sname); sub(/\].*$/, "", sname)
                    gsub(/[[:space:]]/, "", sname)
                    if (line ~ /^[[:space:]]*\[/ && tolower(sname) == "greeter") {
                        print "greeter-show-messages = true"
                        inserted = 1
                    }
                }
            }
        ' "$cfg" > "$tmp_cfg"
    else
        # No section at all: append.
        cp "$cfg" "$tmp_cfg"
        # Ensure newline separation before new section.
        if [[ -s "$tmp_cfg" ]] && [[ "$(tail -c1 "$tmp_cfg" | od -An -c | tr -d ' ')" != '\n' ]]; then
            printf '\n' >> "$tmp_cfg"
        fi
        printf '\n[greeter]\ngreeter-show-messages = true\n' >> "$tmp_cfg"
    fi

    preserve_attrs "$cfg" "$tmp_cfg"
    mv "$tmp_cfg" "$cfg"
    echo "info: $cfg updated (greeter-show-messages=true)"
    return 0
}

target_basename="$(basename -- "$target")"
if [[ "$target_basename" == "fly-dm" || "$target_basename" == "fly-dm-np" ]]; then
    case "$greeter_messages" in
        off)
            : # explicit opt-out
            ;;
        on|"")
            # default ON for fly-dm/fly-dm-np
            if patch_fly_dmrc "$FLYDM_CONFIG"; then
                echo "info: restart fly-dm to apply greeter changes: systemctl restart fly-dm"
            fi
            ;;
    esac
fi
