#!/usr/bin/env bash
# vagrant/scripts/test-negative.sh
#
# Phase 13.3 — E2E negative scenarios for M-of-N execute.
# Runs inside the `mof-n` vagrant box AFTER setup-mof-n-scenario.sh.
#
# Each scenario:
#   1. Builds a tampered work order (or runs the binary with bad args).
#   2. Asserts `pam-certauth execute …` exits non-zero (expected: 2 = denied).
#   3. Asserts an `audit_denied` (or equivalent reject event) lands in
#      journald within the test window.
#
# Scenarios:
#   N1. single signer with m_of_n=2 — undersigned work order.
#   N2. forbid_self_approval — engineer SKI also signs work order.
#   N3. expired signer cert — issued backdated, notAfter in the past.
#   N4. argv_pattern mismatch — signed pattern in CMS encap doesn't match argv.
#   N5. wrong host_id_hash — work order built against a fake host id (the
#       cert's host_binding refers to a different host).
#
# This script REBUILDS some scenario artefacts under
# /etc/pam_certauth/test/negative/. It does not touch the canonical scenario.

set -euo pipefail

readonly TEST_DIR=/etc/pam_certauth/test
readonly NEG_DIR=$TEST_DIR/negative
readonly CA_DIR=$TEST_DIR/ca
readonly ENG_DIR=$TEST_DIR/engineer
readonly APR_DIR=$TEST_DIR/approvers
readonly PIN=correct-pin

readonly HOST_BINDING_OID=2.25.183976554325829274683049824615098
readonly USER_BINDING_OID=2.25.215438916728501023845629178354627
readonly SCOPES_OID=2.25.148783702439522084104654664555598657967
readonly APPROVER_EKU_OID=2.25.164448633110302675590304402232871779284

failures=0
log()  { printf '[test-negative] %s\n' "$*" >&2; }
ok()   { printf '[test-negative] PASS: %s\n' "$*" >&2; }
miss() { printf '[test-negative] FAIL: %s\n' "$*" >&2; failures=$((failures + 1)); }

mkdir -p "$NEG_DIR"
cd "$NEG_DIR"

run_denied() {
    # $1 = scenario tag, $2... = command + args
    local tag=$1; shift
    local since
    since=$(date -u -d "30 sec ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-30S +%Y-%m-%dT%H:%M:%SZ)
    log "[$tag] running: $*"
    set +e
    "$@" >/tmp/neg.stdout 2>/tmp/neg.stderr
    local rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
        miss "[$tag] expected non-zero exit, got 0; stdout=$(cat /tmp/neg.stdout)"
        return
    fi
    log "[$tag] exit=$rc (expected non-zero, ideally 2)"
    # Look for any deny / reject audit event from pam-certauth.
    if journalctl --since="$since" --output=cat --no-pager 2>/dev/null \
        | grep -Eqi 'audit_denied|execute_denied|denied=|reject'; then
        ok "[$tag] denial audit event present"
    else
        log "[$tag] WARN: deny event not seen in journald; stderr was:"
        cat /tmp/neg.stderr >&2
        miss "[$tag] missing audit_denied event"
    fi
}

# -----------------------------------------------------------------------------
# N1 — single signer with m_of_n=2
# -----------------------------------------------------------------------------
log "N1: building single-signer work order"
cat > payload.toml <<'EOF'
argv_pattern = "/bin/echo hello*"
EOF
openssl cms -sign \
    -in payload.toml -outform DER \
    -signer "$APR_DIR/approver-a.pem" \
    -inkey "$APR_DIR/approver-a.key" \
    -nodetach -binary -nosmimecap -md sha256 \
    -out wo-single.der 2>/dev/null

run_denied N1-single-signer \
    sudo -u testuser sudo -n /usr/bin/pam-certauth execute \
        --scope=test.scope --work-order="$NEG_DIR/wo-single.der" \
        -- /bin/echo "hello from $(hostname)"

# -----------------------------------------------------------------------------
# N2 — forbid_self_approval (engineer SKI also signs)
# -----------------------------------------------------------------------------
log "N2: engineer signs the work order (self-approval)"
# Engineer leaf was issued against engineer-CA; we use that key to sign as
# if the engineer "approved" themselves. Even if both approver-a and the
# engineer sign, forbid_self_approval = true must reject.
openssl cms -sign \
    -in payload.toml -outform DER \
    -signer "$APR_DIR/approver-a.pem" \
    -inkey "$APR_DIR/approver-a.key" \
    -nodetach -binary -nosmimecap -md sha256 \
    -out wo-self-1.der 2>/dev/null
openssl cms -resign \
    -in wo-self-1.der -inform DER -outform DER \
    -signer "$ENG_DIR/testuser.pem" \
    -inkey "$ENG_DIR/testuser.key" \
    -nodetach -binary -nosmimecap -md sha256 \
    -out wo-self.der 2>/dev/null

run_denied N2-self-approval \
    sudo -u testuser sudo -n /usr/bin/pam-certauth execute \
        --scope=test.scope --work-order="$NEG_DIR/wo-self.der" \
        -- /bin/echo "hello from $(hostname)"

# -----------------------------------------------------------------------------
# N3 — expired signer cert
# -----------------------------------------------------------------------------
log "N3: issuing expired approver and signing with it"
MACHINE_ID=$(cat /etc/machine-id)
HOST_ID_HASH=$(printf '%s' "$MACHINE_ID" | sha256sum | awk '{print $1}')

openssl genrsa -out approver-expired.key 2048 2>/dev/null
openssl req -new -key approver-expired.key \
    -subj "/CN=approver-expired" -out approver-expired.csr 2>/dev/null

cat > approver-expired.cnf <<EOF
[ ca ]
default_ca = test_ca

[ test_ca ]
database = exp_db/index.txt
serial = exp_db/serial
new_certs_dir = exp_db/newcerts
default_md = sha256
policy = policy_any
x509_extensions = v3_leaf

[ policy_any ]
commonName = supplied

[ v3_leaf ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth, $APPROVER_EKU_OID
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
$HOST_BINDING_OID = ASN1:SEQUENCE:hb
$SCOPES_OID = ASN1:SEQUENCE:sc

[ hb ]
e0 = UTF8String:sha256:$HOST_ID_HASH
[ sc ]
e0 = UTF8String:test.scope
EOF
rm -rf exp_db
mkdir -p exp_db/newcerts
: > exp_db/index.txt
echo 5000 > exp_db/serial
openssl ca -config approver-expired.cnf -in approver-expired.csr \
    -keyfile "$CA_DIR/approver-ca.key" -cert "$CA_DIR/approver-ca.pem" \
    -startdate 200101000000Z -enddate 200601000000Z \
    -out approver-expired.pem -batch -notext 2>/dev/null

# Sign work order: approver-a (valid) + approver-expired.
openssl cms -sign \
    -in payload.toml -outform DER \
    -signer "$APR_DIR/approver-a.pem" \
    -inkey "$APR_DIR/approver-a.key" \
    -nodetach -binary -nosmimecap -md sha256 \
    -out wo-exp-1.der 2>/dev/null
openssl cms -resign \
    -in wo-exp-1.der -inform DER -outform DER \
    -signer approver-expired.pem -inkey approver-expired.key \
    -nodetach -binary -nosmimecap -md sha256 \
    -out wo-expired.der 2>/dev/null

run_denied N3-expired-signer \
    sudo -u testuser sudo -n /usr/bin/pam-certauth execute \
        --scope=test.scope --work-order="$NEG_DIR/wo-expired.der" \
        -- /bin/echo "hello from $(hostname)"

# -----------------------------------------------------------------------------
# N4 — argv_pattern mismatch
# -----------------------------------------------------------------------------
# Build a fresh 2-of-2 work order whose embedded argv_pattern targets
# `/usr/bin/whoami*` while we invoke `/bin/echo`. The verifier must reject
# on argv_pattern mismatch (since 0.2.1 pattern lives in the signed eContent).
log "N4: pattern mismatch"
cat > payload-pattern.toml <<'EOF'
argv_pattern = "/usr/bin/whoami*"
EOF
openssl cms -sign \
    -in payload-pattern.toml -outform DER \
    -signer "$APR_DIR/approver-a.pem" \
    -inkey "$APR_DIR/approver-a.key" \
    -nodetach -binary -nosmimecap -md sha256 \
    -out wo-pattern-1.der 2>/dev/null
openssl cms -resign \
    -in wo-pattern-1.der -inform DER -outform DER \
    -signer "$APR_DIR/approver-b.pem" \
    -inkey "$APR_DIR/approver-b.key" \
    -nodetach -binary -nosmimecap -md sha256 \
    -out wo-pattern.der 2>/dev/null

run_denied N4-pattern-mismatch \
    sudo -u testuser sudo -n /usr/bin/pam-certauth execute \
        --scope=test.scope --work-order="$NEG_DIR/wo-pattern.der" \
        -- /bin/echo "hello from $(hostname)"

# -----------------------------------------------------------------------------
# N5 — wrong host_id_hash
# -----------------------------------------------------------------------------
log "N5: issuing approver bound to a fake host_id_hash"
FAKE_HOST_HASH=$(printf 'not-this-host' | sha256sum | awk '{print $1}')
openssl genrsa -out approver-wronghost.key 2048 2>/dev/null
openssl req -new -key approver-wronghost.key \
    -subj "/CN=approver-wronghost" -out approver-wronghost.csr 2>/dev/null
cat > approver-wronghost.extfile <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth, $APPROVER_EKU_OID
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
$HOST_BINDING_OID = ASN1:SEQUENCE:hb
$SCOPES_OID = ASN1:SEQUENCE:sc

[hb]
e0 = UTF8String:sha256:$FAKE_HOST_HASH

[sc]
e0 = UTF8String:test.scope
EOF
openssl x509 -req -in approver-wronghost.csr \
    -CA "$CA_DIR/approver-ca.pem" -CAkey "$CA_DIR/approver-ca.key" -CAcreateserial \
    -days 365 -sha256 -extfile approver-wronghost.extfile \
    -out approver-wronghost.pem 2>/dev/null

openssl cms -sign \
    -in payload.toml -outform DER \
    -signer "$APR_DIR/approver-a.pem" \
    -inkey "$APR_DIR/approver-a.key" \
    -nodetach -binary -nosmimecap -md sha256 \
    -out wo-host-1.der 2>/dev/null
openssl cms -resign \
    -in wo-host-1.der -inform DER -outform DER \
    -signer approver-wronghost.pem -inkey approver-wronghost.key \
    -nodetach -binary -nosmimecap -md sha256 \
    -out wo-wronghost.der 2>/dev/null

run_denied N5-wrong-host \
    sudo -u testuser sudo -n /usr/bin/pam-certauth execute \
        --scope=test.scope --work-order="$NEG_DIR/wo-wronghost.der" \
        -- /bin/echo "hello from $(hostname)"

# -----------------------------------------------------------------------------
if (( failures > 0 )); then
    log "$failures scenario(s) FAILED"
    exit 1
fi
log "all negative scenarios passed"
