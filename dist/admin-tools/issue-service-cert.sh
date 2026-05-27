#!/usr/bin/env bash
#
# issue-service-cert.sh — выпуск leaf-сертификата pam_certauth
# через локальный openssl CA (вариант B).
#
# Выпускает leaf-сертификат для service@<host>. Спрашивает только
# имя хоста и срок действия — всё остальное делается автоматически.
# Vault в момент выпуска НЕ используется (только корневой CA в Vault,
# подписывает intermediate один раз — см. vault-pki-setup.sh).
#
# Зависимости: bash 4+, openssl, install
#
# Переменные окружения (или ~/.config/pam-certauth-pki/env):
#   CA_DIR        — каталог локального CA
#                   (default: ~/.config/pam-certauth-pki/ca)
#   REGISTRY_FILE — TSV-реестр host_name→host_id_hash
#                   (default: ~/.config/pam-certauth-pki/host-registry.tsv)
#   OUTPUT_BASE   — куда складывать артефакты
#                   (default: ~/pam-certauth-pki-out)
#   ORGANIZATION  — значение O= в DN (если задано, попадает в subject;
#                   по умолчанию O= не выставляется)

set -euo pipefail
umask 0077

config_dir="${HOME}/.config/pam-certauth-pki"
[[ -f "${config_dir}/env" ]] && source "${config_dir}/env"

CA_DIR="${CA_DIR:-${config_dir}/ca}"
REGISTRY_FILE="${REGISTRY_FILE:-${config_dir}/host-registry.tsv}"
OUTPUT_BASE="${OUTPUT_BASE:-${HOME}/pam-certauth-pki-out}"

for f in "${CA_DIR}/intermediate.pem" "${CA_DIR}/intermediate.key" \
         "${CA_DIR}/intermediate.cnf" "${CA_DIR}/root.pem"; do
    [[ -f "$f" ]] || { echo "Не найден ${f}. Сначала запустите vault-pki-setup.sh." >&2; exit 1; }
done

for bin in openssl install; do
    command -v "${bin}" >/dev/null || { echo "Не найден: ${bin}" >&2; exit 1; }
done

mkdir -p "${config_dir}"
touch "${REGISTRY_FILE}"
chmod 0600 "${REGISTRY_FILE}"

# ---- prompts -----------------------------------------------------------------

read -rp "Имя хоста / банкомата ('wildcard' / 'bootstrap' — спец. режимы): " host_name
[[ "${host_name}" =~ ^[a-zA-Z0-9._-]+$ ]] \
    || { echo "Недопустимое имя." >&2; exit 1; }

read -rp "Срок действия, дней [30]: " days
days="${days:-30}"
[[ "${days}" =~ ^[1-9][0-9]*$ ]] && (( days >= 1 && days <= 3650 )) \
    || { echo "Срок: 1..3650 дней." >&2; exit 1; }

# ---- PAM-пользователь --------------------------------------------------------
# Поддерживается '*' (cert работает для ЛЮБОГО PAM-юзера).

read -rp "PAM-пользователь, либо '*' для любого [service]: " pam_user
pam_user="${pam_user:-service}"
[[ "${pam_user}" =~ ^([a-zA-Z_][a-zA-Z0-9_-]*|\*)$ ]] \
    || { echo "Недопустимое имя пользователя." >&2; exit 1; }

# ---- host_id_hash / спец. режимы ---------------------------------------------
# Три режима host_binding'а в leaf-серте:
#
#   wildcard   — UTF8String "*"            : cert работает на ЛЮБОМ хосте.
#                Обходит host-pinning. Только для test/recovery, КОРОТКИЙ TTL.
#
#   bootstrap  — UTF8String "installation" : cert работает на хосте, где
#                resolver возвращает host_id_hash = SHA-256("installation").
#                Парный к golden-image config:
#                    [host_identity]
#                    sources = ["override"]
#                    fallback = "deny"
#                    override = "installation"
#                После раскатки cloned image на новой железке ansible
#                переключает sources на реальные ("dmi_board_serial",
#                "machine_id"), и bootstrap cert автоматически перестаёт
#                быть валидным на этом хосте — host_id_hash меняется.
#                Per-host cert выпускается отдельно (нормальный режим).
#
#   <host-name> — UTF8String "sha256:<hex>" : нормальный per-host cert,
#                bound к конкретному resolved host_id_hash.
#
# Маркеры в переменной host_hash:
#   "wildcard-marker"  — wildcard mode
#   "bootstrap-marker" — bootstrap mode
#   <64-hex>           — нормальный mode

if [[ "${host_name}" == "wildcard" ]]; then
    echo
    echo "ВНИМАНИЕ: будет выпущен cert с host_binding = '*' (любой хост)."
    echo "  - cert будет принят на каждом хосте с этим CA в trust store"
    echo "  - host-pinning защита (см. docs/threat-model.md §2.5) обходится"
    echo "  - использовать только для test/recovery, с КОРОТКИМ TTL"
    read -rp "Подтвердить выпуск wildcard-host cert? (yes/NO): " confirm
    [[ "${confirm}" == "yes" ]] || { echo "Отменено." >&2; exit 1; }
    host_hash="wildcard-marker"
elif [[ "${host_name}" == "bootstrap" ]]; then
    echo
    echo "Будет выпущен bootstrap cert с host_binding = \"installation\"."
    echo "  - Парный config (golden image):"
    echo "      [host_identity]"
    echo "      sources = [\"override\"]"
    echo "      fallback = \"deny\""
    echo "      override = \"installation\""
    echo "  - После раскатки image переключите sources на реальный источник"
    echo "    (dmi_board_serial / machine_id) — cert автоматически перестанет"
    echo "    быть валидным."
    echo "  - Параллельно выпустите per-host cert через этот же скрипт"
    echo "    (с реальным host_name) и установите на узел."
    echo "  - Рекомендуемый TTL bootstrap-cert: 1-7 дней."
    read -rp "Подтвердить выпуск bootstrap cert? (yes/NO): " confirm
    [[ "${confirm}" == "yes" ]] || { echo "Отменено." >&2; exit 1; }
    host_hash="bootstrap-marker"
else
    host_hash="$(awk -v a="${host_name}" -F'\t' '$1==a {print $2; exit}' "${REGISTRY_FILE}")"
    if [[ -z "${host_hash}" ]]; then
        echo "Хост '${host_name}' не в ${REGISTRY_FILE}."
        echo "На хосте (с установленным pam-certauth >= 0.3.7):"
        echo "    sudo journalctl -t pam_certauth | grep 'host_identity: probe selected' | tail -1"
        echo "Скопируйте значение host_id_hash из лога — это resolved hash"
        echo "по deployed [host_identity].sources, без ручного выбора алгоритма."
        echo "Если pam_certauth ещё не запускался — войдите один раз (auth не обязан"
        echo "пройти), probe-строки появятся в syslog."
        read -rp "host_id_hash (64-символьный hex): " host_hash
        host_hash="$(echo "${host_hash}" | tr 'A-F' 'a-f' | tr -d '[:space:]')"
        [[ "${host_hash}" =~ ^[0-9a-f]{64}$ ]] \
            || { echo "Должен быть 64-символьный hex." >&2; exit 1; }
        printf '%s\t%s\n' "${host_name}" "${host_hash}" >> "${REGISTRY_FILE}"
        echo "Сохранено в ${REGISTRY_FILE}."
    fi
fi

# ---- директория выпуска ------------------------------------------------------

ts="$(date -u +%Y%m%dT%H%M%SZ)"
out_dir="${OUTPUT_BASE}/${host_name}/${ts}"
mkdir -p "${out_dir}"
chmod 0700 "${out_dir}"

key_path="${out_dir}/service.key"
csr_path="${out_dir}/service.csr"
cert_path="${out_dir}/service.pem"
chain_path="${out_dir}/chain.pem"
p12_path="${out_dir}/service.p12"
ext_path="${out_dir}/ext.cnf"
pass_path="${out_dir}/passphrase.txt"

# ---- ключ leaf'а -------------------------------------------------------------

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "${key_path}" 2>/dev/null
chmod 0600 "${key_path}"

# ---- CSR + extension config --------------------------------------------------

# Подбираем UTF8String под host_binding по режиму:
case "${host_hash}" in
    wildcard-marker)  hb_value="*"                 ;;
    bootstrap-marker) hb_value="installation"      ;;
    *)                hb_value="sha256:${host_hash}" ;;
esac

# Опционально добавляем O= в DN, если ORGANIZATION задан в env.
if [[ -n "${ORGANIZATION:-}" ]]; then
    dn_block=$(printf 'CN = service@%s\nO  = %s\n' "${host_name}" "${ORGANIZATION}")
else
    dn_block=$(printf 'CN = service@%s\n' "${host_name}")
fi

cat > "${ext_path}" <<EOF
[ req ]
distinguished_name = dn
req_extensions     = v3_req
prompt             = no

[ dn ]
${dn_block}

[ v3_req ]
basicConstraints = critical,CA:FALSE
keyUsage         = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
2.25.183976554325829274683049824615098 = ASN1:SEQUENCE:hb
2.25.215438916728501023845629178354627 = ASN1:SEQUENCE:ub

[ hb ]
e0 = UTF8String:${hb_value}

[ ub ]
e0 = UTF8String:${pam_user}
EOF

openssl req -new -key "${key_path}" -out "${csr_path}" -config "${ext_path}"

# ---- подпись локальным intermediate через openssl ca ------------------------

openssl ca -batch -notext \
    -config "${CA_DIR}/intermediate.cnf" \
    -extfile "${ext_path}" -extensions v3_req \
    -days "${days}" \
    -in "${csr_path}" \
    -out "${cert_path}"

# Sanity-check: оба расширения должны быть в leaf'е.
openssl x509 -in "${cert_path}" -noout -text \
    | grep -q '2.25.215438916728501023845629178354627' \
    || { echo "В leaf'е нет user_binding (проверьте copy_extensions в intermediate.cnf)." >&2; exit 1; }
openssl x509 -in "${cert_path}" -noout -text \
    | grep -q '2.25.183976554325829274683049824615098' \
    || { echo "В leaf'е нет host_binding extension." >&2; exit 1; }

# ---- chain (intermediate + root) для .p12 -----------------------------------

cat "${CA_DIR}/intermediate.pem" "${CA_DIR}/root.pem" > "${chain_path}"

# ---- PKCS#12 -----------------------------------------------------------------

passphrase="$(openssl rand -base64 12 | tr -d '/+=' | head -c 12)"
printf '%s\n' "${passphrase}" > "${pass_path}"
chmod 0400 "${pass_path}"

openssl pkcs12 -export \
    -inkey "${key_path}" \
    -in "${cert_path}" \
    -certfile "${chain_path}" \
    -name service \
    -keypbe AES-256-CBC \
    -certpbe NONE \
    -macalg sha256 \
    -out "${p12_path}" \
    -passout "pass:${passphrase}"
chmod 0400 "${p12_path}"

# Sanity-check: cert должен быть plaintext (диагностика host_binding без пароля).
if ! openssl pkcs12 -in "${p12_path}" -nokeys -nomacver -passin pass: 2>/dev/null \
        | grep -q 'BEGIN CERTIFICATE'; then
    echo "ОШИБКА: cert в .p12 не plaintext (проверьте -certpbe NONE)." >&2
    exit 1
fi

# ---- summary -----------------------------------------------------------------

serial="$(openssl x509 -in "${cert_path}" -noout -serial | awk -F= '{print $2}')"

case "${host_hash}" in
    wildcard-marker)  hb_display="* (wildcard — любой хост)"           ;;
    bootstrap-marker) hb_display="\"installation\" (bootstrap)"        ;;
    *)                hb_display="sha256:${host_hash}"                 ;;
esac

cat <<EOF

================================================================================
Сертификат выпущен.

  Хост:           ${host_name}
  host_binding:   ${hb_display}
  Срок действия:  ${days} дн.
  Subject CN:     service@${host_name}
  PAM-юзер:       ${pam_user}
  Serial:         ${serial}
  CA DB:          ${CA_DIR}/index.txt  (запись добавлена)

  Каталог:        ${out_dir}
  .p12:           ${p12_path}
  Пароль .p12:    ${passphrase}
                  (также в ${pass_path}, mode 0400)

Дальнейшие шаги:
  1. Скопировать на USB-флешку (см. prepare-usb-flash.sh):
       sudo ./prepare-usb-flash.sh
     либо вручную:
       sudo install -m 0600 ${p12_path} /mnt/usb/service.p12
       sync && sudo umount /mnt/usb

  2. Пароль .p12 передать инженеру отдельным каналом (не вместе с
     флешкой). Удалить ${pass_path} после передачи.

  3. Если нужно отозвать сертификат — пока возможности нет (CRL/OCSP
     не настроены). Держите короткий TTL leaf'а и дожидайтесь истечения.
     Запись в ${CA_DIR}/index.txt сохранена — пригодится, когда добавим
     CRL.

  4. Закрытый ключ ${key_path} остаётся ТОЛЬКО на этой админ-машине.
     В git/Vault его не класть.
================================================================================
EOF
