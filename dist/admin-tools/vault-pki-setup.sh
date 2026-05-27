#!/usr/bin/env bash
#
# vault-pki-setup.sh — вариант B (локальный openssl CA, Vault для root)
#
# Делает:
#   1. Создаёт в Vault корневой CA (pki_root, 100 лет).
#   2. Генерирует промежуточный CSR + ключ ЛОКАЛЬНО (openssl).
#   3. Просит Vault root подписать intermediate CSR (10 лет).
#   4. Раскладывает локальную openssl-CA-инфраструктуру:
#        ~/.config/pam-certauth-pki/ca/{intermediate.{pem,key},index.txt,serial,
#                              crlnumber,newcerts/,crl/,intermediate.cnf}
#
# После выпуска:
#   - leaf-сертификаты подписываются скриптом issue-service-cert.sh
#     локально через `openssl ca` (Vault не парсит CSR → не упирается в
#     ограничение Go на размер OID-арок 2.25.<UUID>).
#   - CRL генерируется отдельным скриптом (или вручную).
#   - Приватный ключ intermediate живёт в
#       ~/.config/pam-certauth-pki/ca/intermediate.key
#     с mode 0600. Админ-машина обязана быть с шифрованной ФС.
#
# Зависимости: vault, openssl, jq
#
# Переменные окружения:
#   VAULT_ADDR, VAULT_TOKEN  — обязательны.
#   ROOT_MOUNT     (default: pki_root)
#   ROOT_CN        (default: "pam-certauth Root CA")
#   ROOT_TTL_HOURS (default: 876000  ≈ 100 лет)
#   INT_CN         (default: "pam-certauth Intermediate CA")
#   INT_TTL_HOURS  (default: 87600   ≈ 10 лет)
#   ROOT_KEY_BITS  (default: 4096)
#   INT_KEY_BITS   (default: 3072)
#   CA_DIR         (default: ~/.config/pam-certauth-pki/ca)
#   ORGANIZATION   — значение O= в DN intermediate (опционально)

set -euo pipefail
umask 0077

: "${VAULT_ADDR:?VAULT_ADDR не задан}"
: "${VAULT_TOKEN:?VAULT_TOKEN не задан}"
export VAULT_ADDR VAULT_TOKEN

ROOT_MOUNT="${ROOT_MOUNT:-pki_root}"
ROOT_CN="${ROOT_CN:-pam-certauth Root CA}"
ROOT_TTL_HOURS="${ROOT_TTL_HOURS:-876000}"
INT_CN="${INT_CN:-pam-certauth Intermediate CA}"
INT_TTL_HOURS="${INT_TTL_HOURS:-87600}"
ROOT_KEY_BITS="${ROOT_KEY_BITS:-4096}"
INT_KEY_BITS="${INT_KEY_BITS:-3072}"
CA_DIR="${CA_DIR:-${HOME}/.config/pam-certauth-pki/ca}"

for bin in vault openssl jq; do
    command -v "${bin}" >/dev/null || { echo "Не найден: ${bin}" >&2; exit 1; }
done

if [[ -f "${CA_DIR}/intermediate.key" ]]; then
    cat >&2 <<EOF
${CA_DIR}/intermediate.key уже существует.
Повторный запуск создаст НОВЫЙ intermediate — старые leaf-сертификаты
станут невалидными.

Если действительно нужно пересоздать intermediate:
  - сохраните бэкап ${CA_DIR};
  - удалите ${CA_DIR};
  - запустите скрипт снова.
EOF
    exit 1
fi

mkdir -p "${CA_DIR}/newcerts" "${CA_DIR}/crl"
chmod 0700 "${CA_DIR}"

# ---- Vault: корневой CA ------------------------------------------------------

if vault read -format=json "${ROOT_MOUNT}/cert/ca" >/dev/null 2>&1; then
    echo "==> Корневой CA в ${ROOT_MOUNT} уже существует, пропускаю генерацию."
    vault read -format=json "${ROOT_MOUNT}/cert/ca" \
        | jq -r '.data.certificate' > "${CA_DIR}/root.pem"
else
    echo "==> Включаю PKI engine ${ROOT_MOUNT} (max_lease_ttl=${ROOT_TTL_HOURS}h)…"
    vault secrets enable -path="${ROOT_MOUNT}" pki
    vault secrets tune -max-lease-ttl="${ROOT_TTL_HOURS}h" "${ROOT_MOUNT}"

    echo "==> Генерирую корневой CA '${ROOT_CN}' (rsa-${ROOT_KEY_BITS}, ${ROOT_TTL_HOURS}h)…"
    vault write -format=json "${ROOT_MOUNT}/root/generate/internal" \
        common_name="${ROOT_CN}" \
        ttl="${ROOT_TTL_HOURS}h" \
        key_type=rsa key_bits="${ROOT_KEY_BITS}" \
        | jq -r '.data.certificate' > "${CA_DIR}/root.pem"

    vault write "${ROOT_MOUNT}/config/urls" \
        issuing_certificates="${VAULT_ADDR}/v1/${ROOT_MOUNT}/ca" \
        crl_distribution_points="${VAULT_ADDR}/v1/${ROOT_MOUNT}/crl" >/dev/null
fi
chmod 0644 "${CA_DIR}/root.pem"

# ---- Локально: ключ + CSR intermediate ---------------------------------------

echo "==> Генерирую приватный ключ intermediate локально (rsa-${INT_KEY_BITS})…"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:"${INT_KEY_BITS}" \
    -out "${CA_DIR}/intermediate.key" 2>/dev/null
chmod 0600 "${CA_DIR}/intermediate.key"

echo "==> Формирую CSR intermediate…"
if [[ -n "${ORGANIZATION:-}" ]]; then
    int_subj="/CN=${INT_CN}/O=${ORGANIZATION}"
else
    int_subj="/CN=${INT_CN}"
fi
openssl req -new -key "${CA_DIR}/intermediate.key" \
    -subj "${int_subj}" \
    -out "${CA_DIR}/intermediate.csr"
chmod 0644 "${CA_DIR}/intermediate.csr"   # CSR публичен

# ---- Vault: подпись intermediate корнем --------------------------------------

# CSR читаем в переменную ШЕЛЛОМ, не через `csr=@file` — на Astra с
# parsec/MAC и в других ограниченных средах vault-процесс может не иметь
# права открыть файл в ~/.config, даже если владелец совпадает.
csr_content="$(cat "${CA_DIR}/intermediate.csr")"

echo "==> Vault root подписывает intermediate CSR (${INT_TTL_HOURS}h)…"
vault write -format=json "${ROOT_MOUNT}/root/sign-intermediate" \
    csr="${csr_content}" \
    common_name="${INT_CN}" \
    format=pem_bundle \
    ttl="${INT_TTL_HOURS}h" \
    use_csr_values=false \
    | jq -r '.data.certificate' > "${CA_DIR}/intermediate.pem"
chmod 0644 "${CA_DIR}/intermediate.pem"

# ---- openssl CA infrastructure ----------------------------------------------

echo "==> Раскладываю openssl-CA каталог…"
: > "${CA_DIR}/index.txt"
echo '01' > "${CA_DIR}/serial"
echo '01' > "${CA_DIR}/crlnumber"
chmod 0600 "${CA_DIR}/index.txt" "${CA_DIR}/serial" "${CA_DIR}/crlnumber"

cat > "${CA_DIR}/intermediate.cnf" <<EOF
# openssl CA config для подписи leaf-сертификатов pam_certauth.
# Не редактировать вручную — генерируется vault-pki-setup.sh.

[ ca ]
default_ca = certauth_ca

[ certauth_ca ]
dir              = ${CA_DIR}
certificate      = \$dir/intermediate.pem
private_key      = \$dir/intermediate.key
database         = \$dir/index.txt
serial           = \$dir/serial
crlnumber        = \$dir/crlnumber
new_certs_dir    = \$dir/newcerts
default_md       = sha256
default_days     = 30
default_crl_days = 7
policy           = policy_any
unique_subject   = no
copy_extensions  = copy
email_in_dn      = no
preserve         = no
name_opt         = ca_default
cert_opt         = ca_default

[ policy_any ]
commonName             = supplied
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
emailAddress           = optional

# Минимальный req-блок — нужен openssl'у для вызовов через эту секцию.
[ req ]
distinguished_name = req_dn

[ req_dn ]
EOF

# ---- SPKI pin корня ----------------------------------------------------------

root_spki_hash="$(
    openssl x509 -in "${CA_DIR}/root.pem" -noout -pubkey \
    | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -binary \
    | xxd -p -c 256
)"
printf '%s\n' "${root_spki_hash}" > "${CA_DIR}/root.spki.sha256.hex"

# ---- summary -----------------------------------------------------------------

cat <<EOF

================================================================================
PKI развёрнут (вариант B: локальный openssl CA + Vault root).

  Root CA       : ${ROOT_CN}
    в Vault     : ${ROOT_MOUNT}
    TTL         : ${ROOT_TTL_HOURS}h (~$(( ROOT_TTL_HOURS / 8760 )) лет)
    публичный   : ${CA_DIR}/root.pem
    SPKI pin    : ${root_spki_hash}

  Intermediate  : ${INT_CN}
    подписан    : Vault root
    TTL         : ${INT_TTL_HOURS}h (~$(( INT_TTL_HOURS / 8760 )) лет)
    публичный   : ${CA_DIR}/intermediate.pem
    приватный   : ${CA_DIR}/intermediate.key (mode 0600)
    openssl cfg : ${CA_DIR}/intermediate.cnf

  CA DB         : ${CA_DIR}/index.txt
  serial        : ${CA_DIR}/serial         (next: $(cat ${CA_DIR}/serial))
  crlnumber     : ${CA_DIR}/crlnumber

⚠ ВАЖНО про intermediate.key:
  - живёт на диске админ-машины с mode 0600;
  - админ-машина обязана быть на шифрованной ФС (LUKS / FileVault);
  - бэкап ключа делать только в шифрованное хранилище;
  - НЕ коммитить в git.

Дальнейшие шаги:

  1. Раскатать root.pem на все целевые хосты:
       sudo install -m 0640 -o root -g root \\
           ${CA_DIR}/root.pem /etc/pam_certauth/ca/root.pem

  2. В /etc/pam_certauth/config.toml:
       [trust]
       anchors       = ["/etc/pam_certauth/ca/root.pem"]
       intermediates = []

       [trust.pinning]
       enabled                  = true
       allowed_root_spki_sha256 = ["${root_spki_hash}"]

  3. Выпуск leaf'ов — ./issue-service-cert.sh
  4. CRL/OCSP пока не настроены — в config.toml держать
     [trust.revocation] mode = "none". Для отзыва скомпрометированного
     сертификата сейчас единственный путь — короткий TTL leaf'а (≤ 30 дн.).

================================================================================
EOF
