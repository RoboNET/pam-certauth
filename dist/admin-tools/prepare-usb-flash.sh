#!/usr/bin/env bash
#
# prepare-usb-flash.sh — подготовка USB-флешки для pam_certauth.
#
# 1. Находит подключённые USB-флешки (lsblk TRAN=usb), даёт выбор.
# 2. Спрашивает путь к .p12.
# 3. Если на флешке есть раздел с FS из allowlist (ext4/vfat/exfat/ntfs)
#    → монтирует, копирует .p12, выходит. Существующие данные сохраняются.
# 4. Если подходящего раздела нет → предлагает форматирование
#    (wipefs + fdisk + mkfs.ext4). Уничтожает данные после подтверждения.
#
# pam_certauth 0.3.3+ ищет .p12 на всех допустимых FS. Метка раздела
# и название раздела значения не имеют.
#
# Запуск: sudo ./prepare-usb-flash.sh
#
# Зависимости: bash 4+, lsblk, wipefs, fdisk, mkfs.ext4, mount, blkid,
#              install, sync, partprobe, sudo.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Запустите через sudo: sudo $0" >&2
    exit 1
fi

for bin in lsblk wipefs fdisk mkfs.ext4 mount umount blkid install sync partprobe; do
    command -v "${bin}" >/dev/null || { echo "Не найден: ${bin}" >&2; exit 1; }
done

ALLOWED_FS_RE='^(ext4|vfat|exfat|ntfs)$'
MOUNT_POINT="${MOUNT_POINT:-/mnt/usb}"
P12_NAME="${P12_NAME:-service.p12}"

# ---- 1. поиск USB-флешек ---------------------------------------------------

declare -a usb_devs=()
while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    usb_devs+=("${line}")
done < <(lsblk -d -n -o NAME,SIZE,MODEL,TRAN | awk '$NF=="usb" {print}')

if (( ${#usb_devs[@]} == 0 )); then
    echo "Подключённые USB-флешки не найдены. Вставьте флешку и запустите снова."
    exit 1
fi

echo
echo "Найдены USB-устройства:"
printf '%5s  %-10s %-8s %s\n' "№" "Имя" "Размер" "Модель"
echo "  -----  ---------- -------- -------------------------"
i=0
for d in "${usb_devs[@]}"; do
    i=$((i+1))
    name="$(echo "${d}" | awk '{print $1}')"
    size="$(echo "${d}" | awk '{print $2}')"
    model="$(echo "${d}" | awk '{$1=""; $2=""; $NF=""; print}' | sed 's/^  *//; s/ *$//')"
    printf '%5d  %-10s %-8s %s\n' "${i}" "/dev/${name}" "${size}" "${model:-—}"
done
echo

read -rp "Номер устройства [1]: " num
num="${num:-1}"
[[ "${num}" =~ ^[0-9]+$ ]] && (( num >= 1 && num <= ${#usb_devs[@]} )) \
    || { echo "Некорректный номер." >&2; exit 1; }

dev="/dev/$(echo "${usb_devs[$((num-1))]}" | awk '{print $1}')"
echo "Выбрано: ${dev}"
echo
lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINT "${dev}"
echo

# ---- 2. .p12 ----------------------------------------------------------------

read -rp "Путь к .p12 файлу: " p12
p12="${p12/#\~/${HOME}}"
[[ -f "${p12}" ]] || { echo "Файл не найден: ${p12}" >&2; exit 1; }

# Sanity-check: файл обязан быть binary PKCS#12 (DER), не PEM.
# Без этой проверки админ может случайно подсунуть service.key
# (PEM private key) → pam_certauth на целевом хосте упадёт с
# "asn1_check_tlen: wrong tag, Type=PKCS12", а ещё хуже — приватный
# ключ улетит на флешку без шифрования.
if head -c 16 "${p12}" 2>/dev/null | grep -q '^-----BEGIN'; then
    echo "ОШИБКА: ${p12} — PEM-текст, а не PKCS#12 (DER)." >&2
    echo "       Похоже, вы выбрали service.key вместо service.p12." >&2
    echo "       Правильный файл — рядом с тем же именем, расширение .p12." >&2
    exit 1
fi
# Дополнительно — попробовать разобрать ASN.1 конверт (без пароля).
if ! openssl pkcs12 -in "${p12}" -info -nokeys -noout -passin pass: 2>&1 \
        | grep -qE 'MAC.*verify|MAC Iteration|PKCS7'; then
    # MAC verify error (с пустым паролем) = валидный P12 с другим паролем.
    # Если же openssl сразу ругается на ASN.1, файл не P12.
    err="$(openssl pkcs12 -in "${p12}" -info -nokeys -noout -passin pass: 2>&1 | head -1)"
    if echo "${err}" | grep -qi 'asn1\|wrong tag\|not enough data'; then
        echo "ОШИБКА: ${p12} не является валидным PKCS#12 (ASN.1 parse fail)." >&2
        echo "       openssl: ${err}" >&2
        exit 1
    fi
fi
echo "Файл прошёл валидацию как PKCS#12."

# ---- 3. анализ существующей разметки ---------------------------------------

# Ищем первый раздел с FS из allowlist.
candidate_part=""
candidate_fs=""

# Сначала проверяем whole-device (FS прямо на устройстве).
whole_fs="$(blkid -s TYPE -o value "${dev}" 2>/dev/null || true)"
if [[ -n "${whole_fs}" && "${whole_fs}" =~ ${ALLOWED_FS_RE} ]]; then
    candidate_part="${dev}"
    candidate_fs="${whole_fs}"
fi

# Если нет — ищем по партициям.
if [[ -z "${candidate_part}" ]]; then
    for part in "${dev}"[0-9]*; do
        [[ -b "${part}" ]] || continue
        fs="$(blkid -s TYPE -o value "${part}" 2>/dev/null || true)"
        if [[ -n "${fs}" && "${fs}" =~ ${ALLOWED_FS_RE} ]]; then
            candidate_part="${part}"
            candidate_fs="${fs}"
            break
        fi
    done
fi

# Размонтируем всё связанное с устройством перед работой.
for part in "${dev}" "${dev}"[0-9]*; do
    [[ -b "${part}" ]] || continue
    umount "${part}" 2>/dev/null || true
done

if [[ -n "${candidate_part}" ]]; then
    echo "На ${candidate_part}: FS=${candidate_fs}"
    echo "Использую существующую FS, данные на флешке СОХРАНЯТСЯ."
    target_part="${candidate_part}"
else
    echo "Подходящей FS (ext4/vfat/exfat/ntfs) на ${dev} не найдено."
    echo
    echo "================ ВНИМАНИЕ — ФОРМАТИРОВАНИЕ ================="
    echo "Будут УНИЧТОЖЕНЫ ВСЕ ДАННЫЕ на ${dev}."
    echo "============================================================"
    read -rp "Подтвердите: введите YES (заглавными): " confirm
    [[ "${confirm}" == "YES" ]] || { echo "Отменено." >&2; exit 1; }

    echo "==> wipefs -a ${dev}…"
    wipefs -a "${dev}" >/dev/null

    echo "==> Создаю одну партицию на всю флешку…"
    echo -e 'o\nn\np\n1\n\n\nw' | fdisk "${dev}" >/dev/null
    partprobe "${dev}" 2>/dev/null || true
    sleep 1

    target_part="${dev}1"
    [[ -b "${target_part}" ]] || { echo "Раздел ${target_part} не появился." >&2; exit 1; }

    echo "==> mkfs.ext4 ${target_part}…"
    mkfs.ext4 -F "${target_part}" >/dev/null
fi

# ---- 4. копирование .p12 ---------------------------------------------------

mkdir -p "${MOUNT_POINT}"
echo "==> Монтирую ${target_part} в ${MOUNT_POINT}…"
mount "${target_part}" "${MOUNT_POINT}"

if [[ -f "${MOUNT_POINT}/${P12_NAME}" ]]; then
    echo "==> На флешке уже есть ${P12_NAME} — перезаписываю."
fi

install -m 0600 "${p12}" "${MOUNT_POINT}/${P12_NAME}"
sync

echo "==> Содержимое флешки после копирования:"
ls -la "${MOUNT_POINT}" | head -20

umount "${MOUNT_POINT}"

# ---- 5. summary ------------------------------------------------------------

fs_type="$(blkid -s TYPE -o value "${target_part}")"
fs_label="$(blkid -s LABEL -o value "${target_part}" 2>/dev/null || echo '<пусто>')"

cat <<EOF

================================================================================
Флешка готова.

  Устройство:   ${dev}
  Раздел:       ${target_part}
  FS:           ${fs_type}
  Label:        ${fs_label}    (значения не имеет, для информации)
  Файл:         /${P12_NAME}  (mode 0600)

Передайте инженеру вместе с паролем .p12 (паролем — отдельным каналом).
================================================================================
EOF
