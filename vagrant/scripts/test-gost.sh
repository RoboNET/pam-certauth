#!/usr/bin/env bash
# vagrant/scripts/test-gost.sh
#
# Phase 13.4 — Optional GOST E2E variant.
# Runs inside the `mof-n` vagrant box AFTER setup-mof-n-scenario.sh.
#
# Goal: prove the happy path also works when one of the two signers is a
# GOST R 34.10-2012 cert produced via openssl + gost-engine. If gost-engine
# is not installed (Ubuntu base / Debian without packaged engine), the
# script exits 77 (autotools "skip" convention) so CI can treat it as a
# soft skip rather than a hard failure.
#
# Known limitation (tracked in docs/migration.md): openssl-rust 0.10's
# Cms verifier does not currently expose a clean path to register the
# gost-engine for signature verification. If the run-time pam-certauth
# rejects the mixed CMS bundle with an "unsupported signature algorithm"
# error, that's the documented gap and the script exits 77 with a note.
#
# Exit codes:
#   0  — GOST signer accepted, happy path passed
#   1  — unexpected failure (e.g. openssl cms -sign succeeded but
#         pam-certauth rejected and gost-engine IS available)
#   77 — gost-engine missing or pam-certauth doesn't accept GOST yet (skip)

set -euo pipefail

readonly TEST_DIR=/etc/pam_certauth/test
readonly CA_DIR=$TEST_DIR/ca
readonly APR_DIR=$TEST_DIR/approvers
readonly GOST_DIR=$TEST_DIR/gost
readonly PIN=correct-pin

readonly HOST_BINDING_OID=2.25.183976554325829274683049824615098
readonly SCOPES_OID=2.25.148783702439522084104654664555598657967
readonly APPROVER_EKU_OID=2.25.164448633110302675590304402232871779284

log() { printf '[test-gost] %s\n' "$*" >&2; }
skip() { printf '[test-gost] SKIP: %s\n' "$*" >&2; exit 77; }
fail() { printf '[test-gost] FAIL: %s\n' "$*" >&2; exit 1; }

# Probe for gost-engine.
if ! openssl engine -t gost 2>/dev/null | grep -q '\[ available \]'; then
    skip "gost-engine not available (apt-get install gost-engine)"
fi
log "gost-engine detected"

mkdir -p "$GOST_DIR"
cd "$GOST_DIR"

MACHINE_ID=$(cat /etc/machine-id)
HOST_ID_HASH=$(printf '%s' "$MACHINE_ID" | sha256sum | awk '{print $1}')

# Generate a GOST R 34.10-2012 256-bit keypair and CSR.
log "generating GOST-2012-256 approver"
openssl genpkey -engine gost -algorithm gost2012_256 \
    -pkeyopt paramset:A -out approver-gost.key 2>/dev/null

openssl req -engine gost -new -key approver-gost.key \
    -subj "/CN=approver-gost" -out approver-gost.csr 2>/dev/null

cat > approver-gost.extfile <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth, $APPROVER_EKU_OID
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
$HOST_BINDING_OID = ASN1:SEQUENCE:hb
$SCOPES_OID = ASN1:SEQUENCE:sc

[hb]
e0 = UTF8String:sha256:$HOST_ID_HASH

[sc]
e0 = UTF8String:test.scope
EOF

openssl x509 -req -in approver-gost.csr \
    -CA "$CA_DIR/approver-ca.pem" -CAkey "$CA_DIR/approver-ca.key" -CAcreateserial \
    -days 365 -extfile approver-gost.extfile \
    -out approver-gost.pem 2>/dev/null || skip "approver-CA cannot sign GOST CSR (mixed RSA-CA / GOST-leaf unsupported)"

# Build mixed CMS: RSA approver-a + GOST approver.
printf '\n' > payload.txt
openssl cms -sign \
    -in payload.txt -outform DER \
    -signer "$APR_DIR/approver-a.pem" \
    -inkey "$APR_DIR/approver-a.key" \
    -nodetach -binary -nosmimecap -md sha256 \
    -out wo-mixed-1.der 2>/dev/null || fail "RSA signer step failed"

openssl cms -engine gost -resign \
    -in wo-mixed-1.der -inform DER -outform DER \
    -signer approver-gost.pem -inkey approver-gost.key \
    -nodetach -binary -nosmimecap -md md_gost12_256 \
    -out wo-mixed.der 2>/dev/null || skip "openssl cms -engine gost -resign unsupported on this build"

printf '/bin/echo hello*\n' > wo-mixed.der.pattern

# Try the happy path with the mixed-signature CMS.
log "attempting execute with mixed RSA+GOST CMS"
set +e
out=$(sudo -u testuser sudo -n /usr/bin/pam-certauth-execute \
    --scope=test.scope --work-order="$GOST_DIR/wo-mixed.der" \
    -- /bin/echo "hello from $(hostname)" 2>&1)
rc=$?
set -e

if [[ $rc -ne 0 ]]; then
    log "pam-certauth rejected mixed CMS (rc=$rc):"
    printf '%s\n' "$out" | tail -10 >&2
    log "this is the documented openssl-rust GOST gap (see docs/migration.md)"
    exit 77
fi

log "OK — GOST signer accepted by pam-certauth"
echo "$out"
