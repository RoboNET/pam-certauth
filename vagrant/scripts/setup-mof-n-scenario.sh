#!/usr/bin/env bash
# vagrant/scripts/setup-mof-n-scenario.sh
#
# Phase 13 E2E scenario provisioner. Runs INSIDE the `mof-n` vagrant box.
# Builds a self-contained M-of-N test rig:
#
#   1. Install runtime deps + pam-certauth .deb shipped via /srv/source.
#   2. Generate two CA hierarchies — engineer-CA and approver-CA — both
#      rooted at independent self-signed roots.
#   3. Issue one engineer leaf cert (PKCS#12, passphrase = correct-pin)
#      with pam_cert_scopes={"test.scope"}, host_binding=host_id_hash(VM),
#      user_binding={"testuser"}.
#   4. Issue two approver leaf certs (PKCS#12, passphrase = correct-pin)
#      with pam_cert_scopes={"test.scope"}, host_binding=host_id_hash(VM),
#      EKU containing APPROVER_EKU_OID. Engineer SKI is intentionally
#      different from both approvers (forbid_self_approval = true).
#   5. Sign an empty CMS payload twice (one signer per approver) to form
#      a valid 2-of-2 work order.
#   6. Drop /etc/pam_certauth/config.toml with [trust] / [approver_trust]
#      pointing at the two roots, and /etc/pam_certauth/policy.toml with
#      a single scope "test.scope" requiring m_of_n=2.
#   7. Configure sudoers and create the testuser account.
#   8. Start pam-certauth.service.
#
# NOTE: Since 0.2.1 the argv_pattern lives in the *signed* CMS encapContent
#       (TOML body with `argv_pattern = "..."`). The legacy `.pattern` sidecar
#       is no longer consulted by the verifier — do not rely on it.
#
# The script is idempotent: if the CA already exists it skips regen unless
# REGEN=1 is passed.
#
# Output artefacts (committed to the VM under /etc/pam_certauth/test/):
#   ca/engineer-ca.pem               trust anchor for engineer chain
#   ca/approver-ca.pem               trust anchor for approver chain
#   engineer/testuser.p12            engineer cert (PIN: correct-pin)
#   approvers/approver-a.p12         approver A cert
#   approvers/approver-b.p12         approver B cert
#   work-order/empty.cms             CMS SignedData, 2 signers, scope=test.scope,
#                                    encapContent TOML carries argv_pattern
#
# Exit codes:
#   0  success
#   1  fatal error (deb missing, OpenSSL failure, etc.)
#
# This script must run as root (vagrant provisioning does so by default).

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

readonly TEST_DIR=/etc/pam_certauth/test
readonly CA_DIR=$TEST_DIR/ca
readonly ENG_DIR=$TEST_DIR/engineer
readonly APR_DIR=$TEST_DIR/approvers
readonly WO_DIR=$TEST_DIR/work-order
readonly WORK=$TEST_DIR/work
readonly PIN=correct-pin

readonly HOST_BINDING_OID=2.25.183976554325829274683049824615098
readonly USER_BINDING_OID=2.25.215438916728501023845629178354627
readonly SCOPES_OID=2.25.148783702439522084104654664555598657967
readonly APPROVER_EKU_OID=2.25.164448633110302675590304402232871779284

log() { printf '[setup-mof-n] %s\n' "$*" >&2; }
die() { printf '[setup-mof-n] FATAL: %s\n' "$*" >&2; exit 1; }

# -----------------------------------------------------------------------------
# Step 1 — runtime deps + .deb install
# -----------------------------------------------------------------------------
log "installing runtime deps"
apt-get update -qq
apt-get install -y -qq \
    libssl3 libpam0g libudev1 libdbus-1-3 libsystemd0 \
    openssl jq sudo

DEB=$(ls /srv/source/target/release/pam-certauth_*.deb 2>/dev/null | head -n1 || true)
if [[ -z "$DEB" ]]; then
    die "no pam-certauth .deb under /srv/source/target/release/ — build via scripts/build-deb.sh on the host first"
fi
log "installing $DEB"
dpkg -i "$DEB" || apt-get install -f -y -qq

# -----------------------------------------------------------------------------
# Step 2 — host_id_hash
# -----------------------------------------------------------------------------
# Compute the host_id_hash the same way pam_certauth_core::host_identity does:
# sha256 over the first non-empty source. Default config below uses
# sources=["machine_id"] so the hash is sha256(machine_id).
MACHINE_ID=$(cat /etc/machine-id)
HOST_ID_HASH=$(printf '%s' "$MACHINE_ID" | sha256sum | awk '{print $1}')
log "host_id_hash = sha256:$HOST_ID_HASH"

# -----------------------------------------------------------------------------
# Step 3 — directory layout
# -----------------------------------------------------------------------------
mkdir -p "$CA_DIR" "$ENG_DIR" "$APR_DIR" "$WO_DIR" "$WORK"
cd "$WORK"

if [[ -f "$CA_DIR/engineer-ca.pem" && "${REGEN:-0}" != "1" ]]; then
    log "CA already present, skipping regen (set REGEN=1 to force)"
else
    log "generating engineer CA"
    openssl genrsa -out engineer-ca.key 3072 2>/dev/null
    openssl req -x509 -new -key engineer-ca.key -sha256 -days 1825 \
        -subj "/CN=pam_certauth Engineer Test CA" \
        -extensions v3_ca -config <(cat <<EOF
[req]
distinguished_name = dn
[dn]
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
) -out engineer-ca.pem

    log "generating approver CA"
    openssl genrsa -out approver-ca.key 3072 2>/dev/null
    openssl req -x509 -new -key approver-ca.key -sha256 -days 1825 \
        -subj "/CN=pam_certauth Approver Test CA" \
        -extensions v3_ca -config <(cat <<EOF
[req]
distinguished_name = dn
[dn]
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
) -out approver-ca.pem

    install -m 0644 engineer-ca.pem "$CA_DIR/engineer-ca.pem"
    install -m 0644 approver-ca.pem "$CA_DIR/approver-ca.pem"
    install -m 0600 engineer-ca.key "$CA_DIR/engineer-ca.key"
    install -m 0600 approver-ca.key "$CA_DIR/approver-ca.key"
fi

# Helper: build an extfile for a leaf cert.
# Args: $1=outfile $2=is_approver(0|1)
write_leaf_extfile() {
    local outfile=$1 is_approver=$2
    local eku_line=""
    if [[ "$is_approver" == "1" ]]; then
        # emailProtection is required by OpenSSL's CMS_verify cert-purpose
        # check; without it CMS_verify rejects signers with "unsuitable
        # certificate purpose". Documented in docs/work-order.md.
        eku_line="extendedKeyUsage = clientAuth, emailProtection, $APPROVER_EKU_OID"
    else
        eku_line="extendedKeyUsage = clientAuth"
    fi
    cat > "$outfile" <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
$eku_line
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = email:testuser@example.org

# pam_cert_host_binding
$HOST_BINDING_OID = ASN1:SEQUENCE:hb
# pam_cert_user_binding
$USER_BINDING_OID = ASN1:SEQUENCE:ub
# pam_cert_scopes
$SCOPES_OID = ASN1:SEQUENCE:sc

[hb]
e0 = UTF8String:sha256:$HOST_ID_HASH

[ub]
e0 = UTF8String:testuser

[sc]
e0 = UTF8String:test.scope
EOF
}

# -----------------------------------------------------------------------------
# Step 4 — engineer cert
# -----------------------------------------------------------------------------
log "issuing engineer leaf"
openssl genrsa -out engineer.key 2048 2>/dev/null
openssl req -new -key engineer.key \
    -subj "/CN=testuser/emailAddress=testuser@example.org" \
    -out engineer.csr 2>/dev/null
write_leaf_extfile engineer.extfile 0
openssl x509 -req -in engineer.csr \
    -CA "$CA_DIR/engineer-ca.pem" -CAkey "$CA_DIR/engineer-ca.key" -CAcreateserial \
    -days 365 -sha256 -extfile engineer.extfile \
    -out engineer.pem 2>/dev/null
openssl pkcs12 -export \
    -inkey engineer.key -in engineer.pem \
    -name "testuser" \
    -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 \
    -passout pass:$PIN \
    -out "$ENG_DIR/testuser.p12"
install -m 0644 engineer.pem "$ENG_DIR/testuser.pem"
install -m 0600 engineer.key "$ENG_DIR/testuser.key"

# -----------------------------------------------------------------------------
# Step 5 — approver certs (two)
# -----------------------------------------------------------------------------
issue_approver() {
    local name=$1
    log "issuing approver $name"
    openssl genrsa -out "${name}.key" 2048 2>/dev/null
    openssl req -new -key "${name}.key" \
        -subj "/CN=${name}/emailAddress=${name}@example.org" \
        -out "${name}.csr" 2>/dev/null
    write_leaf_extfile "${name}.extfile" 1
    openssl x509 -req -in "${name}.csr" \
        -CA "$CA_DIR/approver-ca.pem" -CAkey "$CA_DIR/approver-ca.key" -CAcreateserial \
        -days 365 -sha256 -extfile "${name}.extfile" \
        -out "${name}.pem" 2>/dev/null
    openssl pkcs12 -export \
        -inkey "${name}.key" -in "${name}.pem" \
        -name "${name}" \
        -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 \
        -passout pass:$PIN \
        -out "$APR_DIR/${name}.p12"
    install -m 0644 "${name}.pem" "$APR_DIR/${name}.pem"
    install -m 0600 "${name}.key" "$APR_DIR/${name}.key"
}
issue_approver approver-a
issue_approver approver-b

# -----------------------------------------------------------------------------
# Step 6 — work order (CMS SignedData, 2 signers)
# -----------------------------------------------------------------------------
log "signing work order (approver-a then approver-b -resign)"
# Since 0.2.1 argv_pattern lives in the *signed* CMS encapContent as a TOML
# body. Verifier reads it from the encap eContent and ignores any sidecar.
#
# Pattern matches the canonical argv of `echo`. On Astra Linux (and most
# modern coreutils packagings) `/bin/echo` is a symlink onto
# `/usr/bin/echo`; PAM-CertAuth resolves the binary via realpath(3) before
# the argv glob check, so the pattern MUST reference the canonical
# `/usr/bin/echo`, not the symlink path — otherwise test-happy.sh fails
# on real hardware with "argv does not match argv_pattern".
cat > payload.toml <<'EOF'
argv_pattern = "/usr/bin/echo *"
EOF

# First signer: produces a SignedData with 1 signer and embedded eContent.
openssl cms -sign \
    -in payload.toml -outform DER \
    -signer "$APR_DIR/approver-a.pem" \
    -inkey "$APR_DIR/approver-a.key" \
    -nodetach -binary -nosmimecap -md sha256 \
    -out work-order-1.der 2>/dev/null

# Second signer: -resign adds approver-b to the same SignedData.
# eContent stays embedded (we keep -nodetach).
openssl cms -resign \
    -in work-order-1.der -inform DER -outform DER \
    -signer "$APR_DIR/approver-b.pem" \
    -inkey "$APR_DIR/approver-b.key" \
    -nodetach -binary -nosmimecap -md sha256 \
    -out work-order.der 2>/dev/null

install -m 0644 work-order.der "$WO_DIR/empty.cms"

# Legacy sidecar removed (since 0.2.1 verifier reads argv_pattern from CMS
# encap payload only). Clean up any stale file from previous runs.
rm -f "$WO_DIR/empty.cms.pattern"

# -----------------------------------------------------------------------------
# Step 7 — config + policy
# -----------------------------------------------------------------------------
log "writing /etc/pam_certauth/config.toml"
cat > /etc/pam_certauth/config.toml <<EOF
# E2E M-of-N scenario config — generated by setup-mof-n-scenario.sh.
crypto_backend = "openssl"
mode = "pkcs12"

usb_wait_seconds = 0
on_usb_removed = "lock"
usb_removed_grace_seconds = 5
suspend_grace_seconds = 30
monitor_fail_mode = "permissive"

[monitor]
socket_path = "/run/pam_certauth/monitord.sock"

[trust]
anchors = ["$CA_DIR/engineer-ca.pem"]
intermediates = []
max_chain_depth = 5
clock_skew_seconds = 60
allowed_signature_algorithms = []

[trust.revocation]
mode = "none"
crl_paths = []
crl_max_age_hours = 0
ocsp_timeout_seconds = 0
ocsp_cache_ttl_seconds = 0

[trust.pinning]
enabled = false
allowed_root_spki_sha256 = []

[approver_trust]
anchors = ["$CA_DIR/approver-ca.pem"]
intermediates = []
max_chain_depth = 5
clock_skew_seconds = 60

[approver_trust.revocation]
mode = "none"
crl_paths = []

[policy]
path = "/etc/pam_certauth/policy.toml"
require_approver_eku = true
signing_time_skew_seconds = 300
krl_poll_interval_seconds = 300

[host_identity]
sources = ["machine_id"]
fallback = "deny"
custom_command_timeout_seconds = 5

[logging]
level = "info"
syslog_facility = "auth"
journald_priority = true
EOF
chmod 0640 /etc/pam_certauth/config.toml
chown root:root /etc/pam_certauth/config.toml

log "writing /etc/pam_certauth/policy.toml"
cat > /etc/pam_certauth/policy.toml <<EOF
# E2E M-of-N scenario policy.
[defaults]
m_of_n = 1
audit_level = "info"

[scope."test.scope"]
m_of_n = 2
require_argv_pattern = true
EOF
chmod 0644 /etc/pam_certauth/policy.toml
chown root:root /etc/pam_certauth/policy.toml

# -----------------------------------------------------------------------------
# Step 8 — testuser + sudoers
# -----------------------------------------------------------------------------
if ! getent group atm_engineers >/dev/null; then
    groupadd atm_engineers
fi
if ! id -u testuser >/dev/null 2>&1; then
    useradd -m -s /bin/bash -G atm_engineers testuser
fi

cat > /etc/sudoers.d/pam-certauth-mof-n <<'EOF'
# Phase 13 E2E: engineers may run pam-certauth execute without password.
%atm_engineers ALL=(root) NOPASSWD: /usr/bin/pam-certauth execute *
EOF
chmod 0440 /etc/sudoers.d/pam-certauth-mof-n
visudo -cf /etc/sudoers.d/pam-certauth-mof-n >/dev/null

# Make work-order artefacts readable by testuser (sidecar is consulted on the
# execute path; CMS itself is read by pam-certauth as root post-sudo).
chown -R root:atm_engineers "$WO_DIR"
chmod 0750 "$WO_DIR"
chmod 0640 "$WO_DIR"/*

# -----------------------------------------------------------------------------
# Step 9 — start daemon
# -----------------------------------------------------------------------------
log "enabling pam-certauth.service"
systemctl daemon-reload
systemctl enable --now pam-certauth.service || {
    log "WARN: pam-certauth.service failed to start; dumping status"
    systemctl status pam-certauth.service --no-pager || true
    journalctl -u pam-certauth.service --no-pager -n 50 || true
}

log "scenario provisioning complete"
log "engineer SKI: $(openssl x509 -in $ENG_DIR/testuser.pem -noout -ext subjectKeyIdentifier | tail -n1 | tr -d ' :' | tr 'A-Z' 'a-z')"
log "approver-a SKI: $(openssl x509 -in $APR_DIR/approver-a.pem -noout -ext subjectKeyIdentifier | tail -n1 | tr -d ' :' | tr 'A-Z' 'a-z')"
log "approver-b SKI: $(openssl x509 -in $APR_DIR/approver-b.pem -noout -ext subjectKeyIdentifier | tail -n1 | tr -d ' :' | tr 'A-Z' 'a-z')"
log "next: ./test-happy.sh ; ./test-negative.sh ; ./test-gost.sh"
