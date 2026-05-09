# pam-certauth admin tools

Набор административных скриптов для развёртывания PKI и выпуска
сертификатов под `pam_certauth`. Скрипты **не входят в .deb-пакет**,
а поставляются отдельным tarball'ом в GitHub Release — это
admin-tooling, который запускается только на машине администратора
PKI, не на целевом хосте.

## Состав

| Скрипт | Что делает |
|--------|------------|
| `vault-pki-setup.sh`   | Один раз: создаёт root CA в HashiCorp Vault, генерирует intermediate CA локально, подписывает intermediate root'ом, раскладывает openssl-CA каталог. |
| `issue-service-cert.sh`| Регулярно: выпускает leaf-сертификат `service@<host>` под конкретный хост (или wildcard / bootstrap), упаковывает в `.p12`. |
| `prepare-usb-flash.sh` | Записывает `.p12` на USB-флешку, проверяя что это валидный PKCS#12 и подходящая FS. |

## Workflow

```
[Vault: root CA] --signs--> [local: intermediate CA] --signs--> [leaf .p12] --> [USB] --> [target host]
        ^                            ^                             ^               ^
        |                            |                             |               |
     vault-pki-setup.sh ─────────────┘                             |               |
                                                          issue-service-cert.sh    |
                                                                          prepare-usb-flash.sh
```

1. **Развёртывание PKI (один раз):**
   ```bash
   export VAULT_ADDR=https://vault.example.org
   export VAULT_TOKEN=hvs.…
   ./vault-pki-setup.sh
   ```
   Создаёт `~/.config/pam-certauth-pki/ca/` со всем необходимым:
   `root.pem`, `intermediate.pem`, `intermediate.key` (mode 0600),
   `intermediate.cnf`, `index.txt`, `serial`, `crlnumber`,
   `root.spki.sha256.hex` (для `[trust.pinning]` в `config.toml`).

2. **Выпуск сертификата на хост:**
   ```bash
   ./issue-service-cert.sh
   ```
   Будет запрошено имя хоста (или специальный режим `wildcard` /
   `bootstrap` — см. ниже), срок действия, PAM-пользователь.
   Артефакты сохраняются в
   `~/pam-certauth-pki-out/<host_name>/<UTC-timestamp>/`:
   `service.key`, `service.csr`, `service.pem`, `service.p12`,
   `chain.pem`, `passphrase.txt`.

3. **Перенос на хост:**
   ```bash
   sudo ./prepare-usb-flash.sh
   ```
   Скрипт сам найдёт USB-устройство, проверит файл `.p12`,
   при необходимости переформатирует флешку и положит файл как
   `service.p12` в корень.

## Соглашения о путях

| Назначение | Путь по умолчанию | Переменная окружения |
|-----------|-------------------|----------------------|
| Конфиг + env | `~/.config/pam-certauth-pki/env` | — (source'ится автоматически) |
| Каталог CA | `~/.config/pam-certauth-pki/ca/` | `CA_DIR` |
| Реестр host_name → host_id_hash | `~/.config/pam-certauth-pki/host-registry.tsv` | `REGISTRY_FILE` |
| Каталог выпущенных артефактов | `~/pam-certauth-pki-out/` | `OUTPUT_BASE` |
| Точка монтирования флешки | `/mnt/usb` | `MOUNT_POINT` |
| Имя файла на флешке | `service.p12` | `P12_NAME` |
| Subject O= (опционально) | — (без O=) | `ORGANIZATION` |

## Режимы host_binding в leaf-серте

`issue-service-cert.sh` поддерживает три режима привязки сертификата к хосту:

### `wildcard` — UTF8String `"*"`

Сертификат принимается на любом хосте, где доверенный CA лежит в trust
store. Полностью **обходит host-pinning защиту**
(см. `docs/threat-model.md §2.5`). Только для test/recovery,
с **коротким TTL**.

### `bootstrap` — UTF8String `"installation"`

Cert принимается на хосте, где `pam_certauth` resolver возвращает
`host_id_hash = SHA-256("installation")`. Парный к golden-image
конфигу:

```toml
[host_identity]
sources  = ["override"]
fallback = "deny"
override = "installation"
```

После раскатки cloned image на новой железке ansible (или ваша
сборочная автоматика) переключает `sources` на реальные источники
(`dmi_board_serial`, `machine_id`), и bootstrap-cert автоматически
перестаёт быть валидным на этом хосте — `host_id_hash` меняется.
Per-host cert выпускается отдельно (нормальный режим).

Рекомендуемый TTL bootstrap-cert: 1-7 дней.

### Нормальный режим — UTF8String `"sha256:<hex>"`

Per-host сертификат, bound к конкретному resolved `host_id_hash`.
Хэш берётся из лога `pam_certauth` на целевом хосте:

```bash
sudo journalctl -t pam_certauth \
  | grep 'host_identity: probe selected' | tail -1
```

`issue-service-cert.sh` сохраняет соответствие
`host_name → host_id_hash` в `host-registry.tsv` после первого
выпуска — последующие выпуски для этого же хоста пройдут без
повторного ввода хэша.

## Зависимости

| Скрипт | Бинарники |
|--------|-----------|
| `vault-pki-setup.sh` | `vault`, `openssl`, `jq`, `xxd` |
| `issue-service-cert.sh` | `openssl`, `install` |
| `prepare-usb-flash.sh` | `lsblk`, `wipefs`, `fdisk`, `mkfs.ext4`, `mount`, `umount`, `blkid`, `install`, `sync`, `partprobe`, `sudo` |

Запускать на машине **с шифрованной ФС** (LUKS / FileVault) —
`intermediate.key` лежит на диске в plaintext с mode 0600.

## Что НЕ делают эти скрипты

- **Не интегрируются с банковским PKI / корпоративным CA.** Если у
  вас уже есть свой root, для подписи `intermediate.csr` пропустите
  `vault-pki-setup.sh`, занесите свой `intermediate.pem` и
  `intermediate.key` в `~/.config/pam-certauth-pki/ca/` руками
  (включая `index.txt`, `serial`, `crlnumber`, `intermediate.cnf` —
  скрипт можно использовать как референс) и пользуйтесь только
  `issue-service-cert.sh`.
- **Не настраивают CRL / OCSP.** Отзыв сертификата сейчас возможен
  только через истечение TTL. Держите TTL leaf'а коротким (≤ 30 дн.).
- **Не раскатывают `root.pem` на хосты.** Это работа вашей
  деплой-автоматики (ansible / salt / image bake).

## Disclaimer

Эти скрипты — пример admin-tooling для одного из возможных
вариантов развёртывания PKI под `pam_certauth`. Они **не являются
частью production .deb** пакета, не устанавливаются в
`/usr/share/pam-certauth/` и поставляются отдельным tarball'ом
в GitHub Release. Подгоняйте под свою инфраструктуру.
