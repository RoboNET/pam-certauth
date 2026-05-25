# Установка pam_certauth на Astra Linux SE

Этот документ — пошаговый сценарий установки и базовой настройки
`pam_certauth` на чистой машине Astra Linux SE 1.7+. Каждый раздел
заканчивается командой проверки. Если проверка не прошла — читать
раздел «Что делать, если…» в конце документа.

> Все команды выполняются от имени `root` или с `sudo`. На время
> правки PAM-стека держите открытый рут-shell в **другом** терминале.
> Если PAM-стек собьёт авторизацию, второй терминал — единственный
> способ откатить изменения.

## 1. Подготовка машины

### 1.1 Проверка ОС

```bash
cat /etc/astra_version 2>/dev/null || cat /etc/os-release
```

Ожидаемый вывод: версия `1.7.5` или новее. На других редакциях
Astra Linux (Орёл, Воронеж, Смоленск 1.7+) сценарий идентичен. На
Ubuntu/Debian — best-effort, без ГОСТ.

### 1.2 Проверка ядра

```bash
uname -r
```

Ожидание: `5.15.0-93-generic` или новее (необходимо для корректной
доставки udev-событий извлечения USB).

### 1.3 Установка системных зависимостей

```bash
sudo apt update
sudo apt install -y \
    libpam0g \
    libssl3 \
    libudev1 \
    libdbus-1-3 \
    libsystemd0 \
    pcsc-lite \
    pcscd \
    opensc-pkcs11 \
    gost-engine \
    pamtester
```

Точные имена пакетов соответствуют репозиторию Astra SE 1.7. На
Ubuntu 22.04 пакета `gost-engine` в основном репозитории нет — его
надо собирать из исходников или брать из стороннего PPA, и в этом
случае ГОСТ-функционал работать не будет (см. README, раздел
«Поддерживаемые ОС»).

### 1.4 Проверка `gost-engine`

```bash
openssl engine gost -t
```

Ожидание: вывод содержит `[ available ]` и список доступных
алгоритмов, в том числе `id-GostR3411-2012-256` (Streebog-256) и
`gost2012_256` (ГОСТ 34.10-2012-256).

### Verification (раздел 1)

```bash
openssl dgst -engine gost -md_gost12_256 /etc/hostname
```

Ожидание: 64-символьный шестнадцатеричный хеш в выводе. Если получили
`engine "gost" set.` без хеша — `gost-engine` подключился, но что-то
пошло не так с алгоритмом; вероятно, версия `gost-engine` рассинхронна
с системным OpenSSL. См. раздел «Что делать, если…».

### 1.5 Preflight: USBGuard и Astra ЗПС (DIGSIG)

Перед установкой полезно убедиться, что окружение не заблокирует ни
сам токен на USB-шине, ни запуск `pam_certauth.so` /
`pam-certauth` через ЭЦП-контроль.

#### USBGuard

Если на хосте установлен USBGuard в режиме `block`, USB-токен должен
быть в allowlist — иначе ядро не отдаст устройство `udev`'у, и
`pam_certauth` не увидит его.

```bash
sudo systemctl is-active usbguard          # active / inactive / not-found
sudo usbguard list-devices 2>/dev/null     # столбец "block" → токен заблокирован
```

Разрешить конкретный токен (по vid:pid или по hash) — отдельным
правилом в `/etc/usbguard/rules.conf`:

```
allow id 0aca:0030 name "Rutoken ECP" hash "ABC..."
```

После правки правил — `sudo systemctl reload usbguard`. Подробности
по runtime-аспекту (порядок старта `monitord` относительно USBGuard)
— в [docs/operations.md §3.5](operations.md).

#### Astra ЗПС / DIGSIG (`astra-digsig-control`)

В production-развёртывании на Astra SE требуется одно из двух:

1. **`astra-digsig-control`** переведён в `logging-only`-режим
   (модуль не блокирует выполнение неподписанных ELF, но шумит в
   `/var/log/syslog` сообщениями `DIGSIG: NOT_ELF_SIGNED`); либо
2. бинари `pam_certauth.so` и `pam-certauth` подписаны
   через сервис подписи Astra-партнёра (`bsign` GPG-ключом из
   доверенной связки в `/etc/digsig/keys/`) — обычно это шаг сборки
   `.deb` в Astra-CI.

```bash
sudo astra-digsig-control status     # ВКЛЮЧЕНО / НЕАКТИВНО / logging-only
sudo dmesg | grep -i digsig | tail   # видны ли отказы по подписи
```

В режиме `enforce` без валидной подписи PAM-аутентификация не
проходит — `pam_certauth.so` просто не загружается. См. также
[docs/threat-model.md §3.7](threat-model.md).

## 2. Установка `.deb`

### 2.1 Скачивание

```bash
# Ссылка на релиз — placeholder; заменить на реальный URL после
# публикации v0.1.1 (обычно — GitHub Releases или внутренний репозиторий
# Astra Linux).
wget https://example.test/releases/pam-certauth_0.1.1-1_amd64.deb
wget https://example.test/releases/pam-certauth_0.1.1-1_amd64.deb.sha256
wget https://example.test/releases/pam-certauth_0.1.1-1_amd64.deb.streebog256
```

### 2.2 Проверка SHA-256

```bash
sha256sum -c pam-certauth_0.1.1-1_amd64.deb.sha256
```

Ожидание: `pam-certauth_0.1.1-1_amd64.deb: OK`.

### 2.3 Проверка Streebog-256

```bash
./scripts/verify-checksums.sh \
    pam-certauth_0.1.1-1_amd64.deb \
    checksums/checksums.txt
```

Скрипт описан в [scripts/verify-checksums.sh](../scripts/verify-checksums.sh)
и проверяет обе суммы (SHA-256 и Streebog-256). См.
[configuration.md](configuration.md) для подробностей.

### 2.4 Установка

```bash
sudo apt install ./pam-certauth_0.3.0-1_amd64.deb
# или legacy 0.1.x:
# sudo apt install ./pam-certauth_0.1.1-1_amd64.deb
```

> Начиная с 0.2.0 бинарь `pam-certauth-monitord` переименован в
> `pam-certauth`. Daemon-режим запускается как `pam-certauth daemon`;
> systemd-юнит `pam-certauth.service` уже использует новое имя.

`apt` подтянет недостающие зависимости (`libgost-engine | gost-engine`,
`libpkcs11-helper1`, `librtpkcs11ecp`).

### 2.4½ Предполётная проверка (`pam-certauth check`)

Перед `systemctl restart pam-certauth` или при первой установке прогоните
preflight: он валидирует `config.toml` и доносит ВСЕ потенциальные
мисконфиги в одном проходе — без открытия сокета и без рестарта demon'а.

```bash
sudo pam-certauth check
```

Что проверяется:

- **PAM-стек.** Сканирует `/etc/pam.d/{login,fly-dm,fly-dm-np,sshd,sudo,su}`
  и валит ERROR, если `@include certauth-*` стоит ПЕРЕД
  `auth required pam_parsec_mac.so` (на Astra SE это убивает account-фазу
  с «Can't obtain required data»). Подсказывает команду фикса через
  `integrate-pam.sh`.
- **`[mac].runtime` vs ядро.** `runtime=required` без активного
  `parsec_strict_mode()=1` — ERROR (`required` в strict-mode без МКЦ
  ядра делает demon бесполезным). `auto` + отсутствующее ядро — WARN
  (тихий fallback на `StubBackend`, MAC НЕ enforced). `disabled` — INFO.
- **Trust anchors / intermediates.** Каждый путь из `[trust].anchors`
  и `[trust].intermediates` должен существовать, быть непустым и
  содержать хотя бы один `-----BEGIN CERTIFICATE-----` маркер. Иначе
  ERROR — demon не может валидировать ни одной цепочки.
- **`/etc/pam_certauth/ca/`.** WARN, если world-writable
  (`mode & 0o002 != 0`).
- **`PARSEC_CAP_CHMAC`.** Если МКЦ ядро активно и `[mac].runtime ≠ disabled`,
  но у процесса нет capability — WARN: метки на `sessions.json` не лягут.
- **`host_identity`-источники.** По одной INFO/WARN строке на каждый
  настроенный источник (`machine_id`, `dmi_*`, `hostname`,
  `custom_command`) — видно сразу, что резолвится и что падает.

Exit-код: **0** — только INFO/WARN; **1** — есть хотя бы один ERROR. Тот
же check выполняется demon'ом на старте: при наличии ERROR boot
обрывается, в `journalctl -u pam-certauth` останутся структурные
сообщения с `target=pam_certauth.startup_check` для каждой проверки.

### 2.5 Проверка systemd-юнита

```bash
systemctl status pam-certauth
```

Ожидание: `Active: active (running)`. Если `inactive (dead)` —
запустить вручную:

```bash
sudo systemctl enable --now pam-certauth
```

### Verification (раздел 2)

```bash
pam-certauth --version
test -d /run/pam_certauth && echo "runtime dir OK"
test -S /run/pam_certauth/monitord.sock && echo "socket OK"
```

Ожидание: версия `0.3.0` (или `0.1.1` для legacy), обе строки `OK`.

## 3. Создание тестового CA (ГОСТ)

> Тестовый CA пригоден только для лабораторного развёртывания. Для
> production используется внешний УЦ — см.
> [docs/operations.md](operations.md).

### 3.1 Каталог

```bash
mkdir -p /tmp/ca && cd /tmp/ca
```

### 3.2 Ключ CA

```bash
openssl genpkey -engine gost -algorithm gost2012_256 \
    -pkeyopt paramset:A -out ca.key
chmod 0600 ca.key
```

### 3.3 Сертификат CA

```bash
openssl req -new -x509 -engine gost -key ca.key \
    -out ca.pem -days 3650 \
    -subj "/CN=pam-certauth Test CA/O=Test/OU=Internal" \
    -addext "extendedKeyUsage=clientAuth" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
```

### 3.4 Проверка

```bash
openssl x509 -in ca.pem -text -noout | head -30
```

Ожидаемая строка: `Signature Algorithm: GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)`.

### Verification (раздел 3)

```bash
openssl verify -CAfile ca.pem ca.pem
```

Ожидание: `ca.pem: OK`.

## 4. Создание тестового пользователя

### 4.1 Ключ alice

```bash
openssl genpkey -engine gost -algorithm gost2012_256 \
    -pkeyopt paramset:A -out alice.key
chmod 0600 alice.key
```

### 4.2 CSR

```bash
openssl req -new -engine gost -key alice.key -out alice.csr \
    -subj "/CN=Alice/UID=alice"
```

### 4.3 Подпись CSR

```bash
openssl x509 -req -engine gost -in alice.csr \
    -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out alice.pem -days 365 \
    -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n")
```

### 4.4 Упаковка в P12

```bash
openssl pkcs12 -export -engine gost -inkey alice.key -in alice.pem \
    -out alice.p12 -name alice -passout pass:test
chmod 0600 alice.p12
```

### Verification (раздел 4)

```bash
openssl pkcs12 -in alice.p12 -nokeys -passin pass:test \
    | openssl x509 -noout -subject
```

Ожидание: `subject=CN=Alice, UID=alice` (точный порядок RDN зависит
от версии OpenSSL).

## 5. Подготовка USB-носителя (режим `pkcs12` / Mode A)

> Mode A: ключ хранится в `.p12` на USB-носителе, защищён парольной
> фразой. Для production выбирать Mode B (PKCS#11-токен).

### 5.1 Форматирование

`pam_certauth` ищет `.p12` на **любой** партиции с FS из allowlist
(`vfat`, `exfat`, `ext4`, `ntfs`). Метка партиции значения не имеет —
защита обеспечивается на уровне расшифровки `.p12` пользовательским
паролем и валидации цепочки сертификатов модулем доверия. Лимит на
число перебираемых партиций задаётся параметром `max_usb_partitions`
в `config.toml` (по умолчанию 8, диапазон 1..=64).

> Начиная с 0.3.5: если на USB-флешке несколько разделов и часть
> содержит посторонние файлы с именем, совпадающим с
> `pkcs12_path_pattern` (типично для Apple-форматированных носителей
> и USB с несколькими партициями), `pam_certauth` распознаёт их как
> «не PKCS#12» по ASN.1-конверту (без запроса PIN) и продолжает
> искать настоящий `.p12` на следующих разделах. Ошибки, требующие
> пароля (неверный PIN / MAC verify / decrypt / chain), по-прежнему
> fail-closed без перебора.

Типовой рецепт (`sdX1` — раздел USB-носителя из вывода `lsblk | grep -i usb`):

```bash
# ВНИМАНИЕ: команда УНИЧТОЖАЕТ данные на устройстве /dev/sdX1.
# Поддерживаемые FS: vfat, exfat, ext4, ntfs.
sudo mkfs.ext4 /dev/sdX1
sudo mount /dev/sdX1 /mnt/usb
sudo install -m 0600 bfs_service.p12 /mnt/usb/bfs_service.p12
sudo umount /mnt/usb
```

Если флешка отформатирована без таблицы разделов (FS лежит прямо на
whole-device), это тоже работает: `pam_certauth` читает `ID_FS_TYPE`
udev и монтирует whole-device напрямую.

### 5.2 Layout

```
/mnt/usb/
├─ certs/
│   ├─ user.p12
│   └─ chain.pem
└─ pam_certauth.marker
```

### 5.3 Копирование

```bash
sudo mkdir -p /mnt/usb/certs
sudo cp /tmp/ca/alice.p12  /mnt/usb/certs/user.p12
sudo cp /tmp/ca/ca.pem     /mnt/usb/certs/chain.pem
sudo touch /mnt/usb/pam_certauth.marker
sudo umount /mnt/usb
```

### Verification (раздел 5)

```bash
sudo mount /dev/sdX1 /mnt/usb
ls -la /mnt/usb/certs/
sudo umount /mnt/usb
```

Ожидание: оба файла присутствуют, размер > 0.

## 6. Подготовка Рутокен ЭЦП 2.0 (режим `pkcs11` / Mode B)

### 6.1 Установка драйвера

```bash
sudo apt install librtpkcs11ecp
```

### 6.2 Проверка слота

```bash
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so -L
```

Ожидание: вывод вида `Slot 0 (0x...): ...` с моделью токена.

### 6.3 Инициализация (только для нового, неинициализированного токена)

```bash
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --init-token --label "alice-token" \
    --so-pin '12345678'
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --init-pin --so-pin '12345678' --pin '1234567890'
```

### 6.4 Импорт ключа и сертификата

```bash
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --login --pin '1234567890' \
    --write-object alice.pem --type cert --label alice --id 01
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --login --pin '1234567890' \
    --write-object alice.p12 --type privkey --label alice --id 01
```

### Verification (раздел 6)

```bash
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so \
    --pin '1234567890' -O
```

Ожидание: в выводе присутствуют `Private Key Object` и
`Certificate Object` с `label=alice`.

## 7. Авторизация: расширения сертификата

Привязка «какой пользователь на каком хосте» живёт в самом
сертификате. PAM-модуль читает два X.509 v3 расширения leaf-сертификата:

- `pam_cert_host_binding` (OID `2.25.183976554325829274683049824615098`)
  — список разрешённых хостов;
- `pam_cert_user_binding` (OID `2.25.215438916728501023845629178354627`)
  — список разрешённых PAM-пользователей.

Готовые рецепты `openssl.cnf` для выпуска сертификатов с правильными
расширениями приведены в [cert-issuance.md](cert-issuance.md).

### Verification (раздел 7)

```bash
openssl x509 -in /tmp/ca/alice.pem -noout -text \
    | grep -E '2\.25\.(183976554325829274683049824615098|215438916728501023845629178354627)'
```

Ожидание: обе строки с дотированными OID присутствуют в выводе.

## 8. Правка `/etc/pam.d/*`

> Открыть второй рут-shell (например, `ssh root@<host>`) **до** правки
> PAM-стека. Если основной shell не сможет авторизоваться после
> изменений — второй терминал останется единственным способом
> отката.

`pam_certauth` поставляет включаемый сниппет `/etc/pam.d/certauth`
(см. [dist/pam.d/certauth](../dist/pam.d/certauth)). Подключать его
надо строкой `@include certauth`.

Поставочный скрипт `/usr/share/pam-certauth/integrate-pam.sh`
автоматически вставляет `@include certauth` перед первой `auth`-строкой
и сохраняет резервную копию `<file>.bak.<UTC-timestamp>`.

> **Важно (0.3.10+) — порядок `pam_systemd.so` в `session`-фазе.**
> Начиная с 0.3.10 наш `pam_sm_open_session` подтягивает `XDG_SESSION_ID`
> из PAM-environment и пушит его в monitord, чтобы USB-removal action
> (`Lock` / `Logout`) умел адресовать logind-сессию пользователя.
> `XDG_SESSION_ID` создаётся `pam_systemd.so` в `session`-фазе и
> существует **только** после того, как этот модуль отработал.
> Поэтому в `/etc/pam.d/<сервис>` строка `session ... pam_systemd.so`
> ОБЯЗАНА идти **до** `@include certauth` (или `session ...
> pam_certauth.so`). На штатных Astra SE `login`/`fly-dm` это так по
> умолчанию; если оператор пересобирал стек вручную — проверить
> отдельно. Иначе в journald появится:
>
> ```
> WARN pam_certauth.session: XDG_SESSION_ID not in PAM env during sm_open_session
> WARN pam_certauth.monitord: USB-removal action dropped: session has no logind id
> ```
>
> и при извлечении флешки logout НЕ произойдёт — см. §10
> «Logout requested but session has no logind id».

### 8.1 fly-dm

#### Зачем интегрировать именно fly-dm

`fly-dm` — графический display-manager Astra Linux SE; это **первый**
PAM-потребитель, через который пользователь попадает в графическую
сессию. Без подключения `pam_certauth` в `/etc/pam.d/fly-dm`
USB-токен на этапе GUI-логина не проверяется, и пользователь зайдёт
по паролю, как будто модуль не установлен. Остальные сервисы
(`sudo`, `login`, `sshd`) защищают только последующие действия —
сам факт входа в desktop-сессию остаётся вне контроля.

Конкретные причины, по которым именно `fly-dm` нужно править:

1. **Точка входа в сессию.** МКЦ-метка (`pam_cert_max_integrity ∩ МНКЦ
   пользователя`) применяется в `pam_sm_open_session` и наследуется
   всем дочерним процессам desktop-сессии. Если сессию открыл не
   `pam_certauth`, метка не выставится и доверенные приложения будут
   запускаться с дефолтной (минимальной) меткой.
2. **Привязка USB к сессии.** `pam-certauth daemon` регистрирует
   удаление токена и отправляет lock-event в screen-locker. Регистрация
   возможна только если сессию открыл сам модуль — иначе у демона нет
   записи о соответствии `(uid, session_id, token_serial)`.
3. **Hot-plug до логина.** `fly-dm` стартует раньше пользовательских
   сервисов, поэтому `pam-certauth.service` обязан быть `Before=fly-dm.service`
   (поставочный unit это делает) — иначе на первом логине после ребута
   USB-устройство может быть ещё не проинициализировано.
4. **GUI-prompt для PIN.** `fly-dm` рендерит `PAM_PROMPT_ECHO_OFF` как
   password-field. Без интеграции PKCS#11-prompt уйдёт в `stderr` DM-процесса
   и пользователь его не увидит — выглядит как «токен не работает».
5. **Root-контекст на auth-этапе.** `fly-dm` бежит как root, поэтому доступ
   к `/dev/bus/usb/*` и PCSC-сокету разрешён без дополнительной udev-настройки.
   В обычном пользовательском процессе (например, ручной `pamtester`
   под обычным uid) этого может не быть.

#### Применение

```bash
sudo /usr/share/pam-certauth/integrate-pam.sh /etc/pam.d/fly-dm
sudo cat /etc/pam.d/fly-dm | head -5
```

Ожидаемый верх файла:

```
@include certauth
auth        requisite   pam_nologin.so
auth        required    pam_env.so
...
```

Включение через `sufficient` (контроль определён в
[dist/pam.d/certauth](../dist/pam.d/certauth)) означает: если PAM-модуль
успешно аутентифицировал — пропустить пользователя; если нет —
попробовать следующие модули (как правило, `pam_unix.so`).

#### Screen-locker (отдельный стек)

`fly-dm-screensaver` / `fly-wm-locker` имеют **собственный** PAM-стек.
Интеграция `/etc/pam.d/fly-dm` разлоком экрана не управляет. Чтобы
разблокировка работала по токену:

```bash
sudo /usr/share/pam-certauth/integrate-pam.sh /etc/pam.d/fly-dm-screensaver
```

Без этого извлечение токена корректно блокирует экран (через
`pam-certauth daemon` + D-Bus screen-lock hook), но разблокировать
сессию можно будет только паролем.

#### Проверка стенда

```bash
systemctl status pam-certauth        # daemon up до старта fly-dm?
pamtester fly-dm $USER authenticate  # сухой прогон auth-стека без GUI
journalctl -u fly-dm -f              # логи во время живого логина
```

### 8.2 Режимы аутентификации

`pam_certauth` поддерживает три эксплуатационных режима, переключаемых
выбором PAM-сниппета. Каждый сниппет — отдельный файл, который
`integrate-pam.sh --mode=...` подключит через `@include` в выбранный
сервис.

| Режим | snippet | Сценарий | Вход без USB |
|---|---|---|---|
| `2fa` (default) | `/etc/pam.d/certauth` | Cert + пароль (классический 2FA) | пароль работает, но без USB не зайти |
| `optional` | `/etc/pam.d/certauth-optional` | Cert ИЛИ пароль (миграция) | да, по паролю |
| `cert-only` | `/etc/pam.d/certauth-only` | Cert как единственный фактор | НЕТ, полная блокировка |

Активация:

```bash
# 2FA на sudo (по умолчанию):
sudo /usr/share/pam-certauth/integrate-pam.sh --mode=2fa /etc/pam.d/sudo

# Миграционный режим:
sudo /usr/share/pam-certauth/integrate-pam.sh --mode=optional /etc/pam.d/sudo

# Cert-only (потеря флэшки = lockout!):
sudo /usr/share/pam-certauth/integrate-pam.sh --mode=cert-only /etc/pam.d/sudo
```

Откат — для всех режимов одинаковый:

```bash
sudo /usr/share/pam-certauth/integrate-pam.sh --unintegrate /etc/pam.d/sudo
```

> ⚠️ **Lockout-warning для `cert-only`.** Перед переключением сервиса
> в `cert-only` админ обязан иметь резервный канал доступа:
>
> 1. Открытый root-shell в другом терминале (TTY/SSH) **на всё время
>    проверки**, минимум до того, как убедились, что cert-only auth
>    работает на тестовом аккаунте на этой машине.
> 2. Альтернативный путь логина, который НЕ проходит через
>    `pam_certauth` — например, отдельный sshd-stack с
>    `PubkeyAuthentication=yes` + `UsePAM=no`, или sudoers-правило для
>    админ-аккаунта без `@include certauth`. Иначе потеря или блокировка
>    единственного токена (USBGuard, ЗПС, физическая утрата) выведет
>    хост из строя — никто не сможет залогиниться, включая локальный
>    root.
>
> Откат — `integrate-pam.sh --unintegrate` из живого root-shell или
> через rescue-target (см. § 10 «Замок-аут после неудачной правки»).
> Тот же runbook продублирован в
> [docs/operations.md § 3.6](operations.md).

### 8.3 sudo

```bash
sudo /usr/share/pam-certauth/integrate-pam.sh /etc/pam.d/sudo
```

### 8.4 login

```bash
sudo /usr/share/pam-certauth/integrate-pam.sh /etc/pam.d/login
```

### 8.5 PAM-стек на Astra SE — учёт состояния МКЦ (PARSEC MAC)

Стек PAM зависит от того, включено ли МКЦ-ядро PARSEC на конкретной
машине. `pam_certauth` опционально интегрирован с libparsec через
compile-time feature `astra-mac` (см. также секцию
[`[mac]`](configuration.md) в `config.toml`), однако сам не выставляет
MAC-контекст без неё — поэтому `pam_parsec_mac.so` в стеке нужен
только когда МКЦ-ядро реально работает.

**Как проверить состояние МКЦ:**

```bash
mount | grep -i parsec                           # пусто → МКЦ выключен
cat /etc/parsec/mswitch.conf 2>/dev/null         # zero_if_notfound: yes → МКЦ выключен
ls /sys/kernel/security/parsec 2>/dev/null       # ENOENT → МКЦ выключен
```

Начиная с 0.3.7 выбор backend'а делается **в runtime** через
`[mac].runtime` (`required` | `auto` | `disabled`, default `auto`) —
независимо от compile-time feature `astra-mac`. Это даёт один и тот же
`.deb` использовать на машинах с МКЦ и без, не пересобирая бинарь.

**Сценарий 1 — МКЦ выключен (текущий default на банкоматах):**

```
# /etc/pam.d/login
auth      required pam_certauth.so
account   required pam_certauth.so
session   required pam_certauth.so
```

Никаких `pam_parsec_mac.so` в стеке. В `config.toml`:

```toml
[mac]
cert_integrity = "ignore"
runtime = "disabled"
```

`runtime = "disabled"` гарантирует, что даже если бинарь собран с
`astra-mac`, никакие `pdp_*` вызовы делаться не будут — используется
no-op `StubBackend`. Событие `mac_runtime_disabled` (INFO) фиксируется
в syslog один раз на каждую auth-сессию.

**Сценарий 2 — МКЦ включён:**

```
# /etc/pam.d/login
auth      required pam_certauth.so
auth      required pam_parsec_mac.so       # ВАЖНО: после pam_certauth
account   required pam_parsec_mac.so
session   required pam_parsec_mac.so
```

В `config.toml`:

```toml
[mac]
cert_integrity = "required"
runtime = "required"
```

`runtime = "required"` означает fail-closed: если по какой-то причине
МКЦ-ядро на машине ВЫКЛЮЧИЛОСЬ (после downgrade ядра, например),
аутентификация будет отвергнута с `mac_runtime_required` в syslog
вместо тихой деградации.

`pam_parsec_mac.so` в `account` и `session` фазах читает MAC-контекст,
выставленный в `auth`-фазе. Если в `auth` нет ни одного модуля,
который выставит этот контекст, login падает с:

```
pam_parsec_mac(login:account): Can't obtain required data.
NOTICE: pam_parsec_mac must be added to "auth" "account" and "session" stack
```

**Сценарий 3 — смешанный парк (default):**

```toml
[mac]
cert_integrity = "optional"
runtime = "auto"
```

При `auto` модуль пробует `parsec_strict_mode` ядра — если ядро
отвечает «активно», берёт настоящий `ParsecBackend`; если нет,
fallback на `StubBackend` с событием `mac_runtime_fallback` (WARN) в
syslog. Подходит для дев-машин и smoke-теста на одной сборке.

**Валидация конфига:**

- `runtime = "disabled"` + `cert_integrity = "required"` — отвергается
  на старте (логически несовместимо).
- `runtime = "required"` в бинаре без `astra-mac` — отвергается на
  старте.
- `cert_integrity = "required"` в бинаре без `astra-mac` —
  отвергается на старте (старое поведение).

### 8.5.1 fly-dm greeter — диагностика на экране

Начиная с 0.3.7 `pam_certauth` в начале `pam_sm_authenticate` отправляет
`PAM_TEXT_INFO` с краткой идентификацией машины:

```
Этот банкомат: host_id=a1b2c3d4 (source=MachineId)
```

`fly-dm` отображает это сообщение в greeter UI, если включён
`greeter-show-messages = true` в `/etc/X11/fly-dm/fly-dmrc`. Это
даёт инженеру у банкомата мгновенно сверить hash с реестром, не
заходя в shell. Полный host_id_hash остаётся в syslog (`journalctl
-t pam_certauth | grep host_identity`).

### 8.6 Безопасность правки

- Перед правкой убедиться, что есть второй открытый рут-shell.
- Проверять каждое изменение командой `pamtester` сразу после правки
  (см. раздел 9).
- В случае поломки — восстановить из резервной копии:
  `sudo cp /etc/pam.d/sudo.bak.<TS> /etc/pam.d/sudo`.

### Verification (раздел 8)

```bash
pamtester sudo alice authenticate
```

Ожидание: `Authentication successful` (при вставленном USB-носителе или
токене).

## 9. Smoke-тест через `pamtester`

### 9.1 Авторизация

```bash
pamtester sudo alice authenticate
```

Положительный результат: `pamtester: successfully authenticated`.

### 9.2 Сессия

```bash
pamtester sudo alice open_session
pamtester sudo alice close_session
```

Положительный результат: оба вызова возвращают `pamtester: successfully ...`.

### 9.3 Negative-тест: извлечь USB

В одном терминале запустить:

```bash
pamtester sudo alice authenticate
```

Сразу после ввода извлечь USB. Ожидание: `monitord` пишет в журнал:

```bash
sudo journalctl -u pam-certauth -n 20 -g 'medium absent'
```

## 10. Что делать, если…

### `gost-engine not loaded`

Симптом: `openssl engine gost -t` выводит `engine "gost" not found`
или `dynamic` без `[ available ]`.

Решение:

```bash
sudo apt install --reinstall gost-engine
sudo systemctl restart pcscd
openssl engine gost -t
```

### `host_binding mismatch`

Симптом: PAM-вызов отказывает с `HostNotAllowed` или
`HostExtensionMissing` в журнале. Начиная с 0.3.6 на экране banner'а
выводится `PAM_TEXT_INFO` вида:

```
Сертификат выпущен для другого банкомата.
host_id_hash этой машины: <hex>
источник host_id: DmiBoardSerial
Передайте администратору для перевыпуска.
```

Диагностика на банкомате:

```bash
# Полная таблица — что ответил каждый сконфигурированный источник
# host_identity на старте последней auth-сессии. Источник истины для
# регистрации банкомата в реестре. Доступно начиная с 0.3.7.
sudo journalctl -t pam_certauth | grep 'host_identity: probe' | tail -20
# probe ok      source=MachineId raw=abc... host_id_hash_prefix=a1b2c3d4 host_id_hash=<full sha256 hex>
# probe error   source=DmiBoardSerial error="ENOENT"
# probe selected source=MachineId (first successful) host_id_hash_prefix=a1b2c3d4

# Совместимая команда из старых релизов (одна строка resolved):
sudo journalctl -t pam_certauth | grep 'host_id resolved' | tail -1

# Что зашито в сертификате:
openssl x509 -in /etc/pam_certauth/<atm>.pem -noout -text \
    | grep -A1 '2\.25\.183976554325829274683049824615098'
```

Сверить значения; при расхождении — перевыпустить cert через
`issue-bfs-service-cert.sh` с правильным host_id_hash. **НЕ**
вычислять hash вручную через `sha256sum /etc/machine-id` — реальный
source-of-truth определяется развёрнутым конфигом
`[host_identity].sources` (см.
[architecture.md](architecture.md#host-identity-chain)). Это устраняет
drift между скриптом выпуска и развёрнутой конфигурацией.

### `user_binding mismatch`

Симптом: цепь сертификата валидна, но конкретный пользователь
отвергается с `UserNotAllowed` / `UserExtensionMissing`.

Решение: проверить, что имя `pam_user` присутствует в расширении
`pam_cert_user_binding` сертификата:

```bash
openssl x509 -in /tmp/ca/alice.pem -noout -text \
    | grep -A1 '2\.25\.215438916728501023845629178354627'
```

### Сертификат не принимается на банкомате (общий чек-лист)

Начиная с 0.3.6 PAM выводит на экран `PAM_TEXT_INFO` с актуальной
диагностикой для двух частых случаев — несовпадение `host_binding`
и неверный PIN. На обоих сценариях смотреть на экран **и** в syslog:

```bash
# 1. Реальный host_id_hash этой машины (с указанием источника):
sudo journalctl -t pam_certauth | grep 'host_id resolved' | tail -1

# 2. Пошаговая трасса последней попытки (mount → discovery → envelope →
#    chain → результат):
sudo journalctl -t pam_certauth --since '5 min ago' \
    | grep -E 'pam_certauth\.(flow|host_identity)'
```

Дальше сверять с реестром выпуска (`atm-registry.tsv` на админ-машине):

- `host_id_hash` в логе ≠ значение в cert → cert выпущен для другого
  банкомата. Перевыпустить через `issue-bfs-service-cert.sh`,
  используя hash из лога этого банкомата.
- В логе нет `host_id resolved` → resolver не отработал. Проверить
  `[host_identity].sources` в `/etc/pam_certauth/config.toml`.
- `PAM_TEXT_INFO` сообщает «Пароль .p12 неверный. Этот сертификат
  выпущен для host_id_hash=…, пользователь=…» → user вставил флешку
  другого инженера. Достать и проверить, что host/user в выводе
  соответствует ожидаемому. Если cert закодирован полностью
  (legacy-формат — без открытого SafeBag), будет короткое сообщение
  «Пароль .p12 неверный»; тогда читать cert на админ-машине:

```bash
openssl pkcs12 -in bfs_service.p12 -nokeys -nomacver -passin pass: \
    | openssl x509 -noout -text
```

### `monitord not reachable`

Симптом: PAM-вызов отказывает с `monitord unavailable` или зависает.

Диагностика:

```bash
sudo systemctl status pam-certauth
sudo journalctl -xeu pam-certauth -n 200
sudo ls -la /run/pam_certauth/
```

Типовые причины:

- сокет `/run/pam_certauth/monitord.sock` не создан → проверить
  `RuntimeDirectory=pam_certauth` в юните
  [pam-certauth.service](../dist/systemd/pam-certauth.service);
- права на `/run/pam_certauth/` неверны → должно быть
  `drwxr-x--- root root` (0750);
- `config.toml` повреждён → запустить `monitord` в ручном режиме
  (`sudo /usr/bin/pam-certauth`) и прочитать
  диагностический вывод.

### `pcscd not running`

Симптом: PKCS#11-токен (Рутокен) не виден через `pkcs11-tool -L`.

Решение:

```bash
sudo systemctl enable --now pcscd
sudo systemctl status pcscd
pcsc_scan          # должен показать вставленный токен
```

### `Token PIN locked`

Симптом: `pkcs11-tool` возвращает `CKR_PIN_LOCKED`.

Решение: разблокировать SO-PIN'ом и переинициализировать пользовательский
PIN с помощью `pkcs11-tool --init-pin`.

### `Authentication failed (PAM_AUTH_ERR)` сразу

Симптом: `pamtester` сразу отказывает.

Диагностика:

```bash
sudo tail -f /var/log/auth.log &
pamtester sudo alice authenticate
```

В журнале искать строки `pam_certauth.auth.fail.<reason>`. Список
причин и их семантика — в
[architecture.md](architecture.md#fail-closed-rules).

### `usb_wait_seconds истёк`

Симптом: после ввода `pamtester` ждёт ~10 секунд, потом отказывает с
`usb medium not found`.

Решение: убедиться, что USB-носитель смонтирован и виден в `lsblk`.
Если требуется бóльшее окно — увеличить `usb_wait_seconds` в
`/etc/pam_certauth/config.toml` (см.
[configuration.md](configuration.md#общие-параметры)).

### `revocation: ocsp unavailable`

Симптом: при включённом `[trust.revocation] mode = "ocsp"` модуль
отказывает с `OCSP unavailable`.

Решение: проверить сетевую доступность OCSP-ответчика; если контур
офлайн — использовать `mode = "crl"` с локальным CRL.

### `Logout requested but session has no logind id`

Симптом (0.3.10+): извлечение USB-токена корректно детектится в
journald (`grace window expired, dispatching action`), но через
секунду логаут не происходит, в логе:

```
WARN pam_certauth.monitord: USB-removal action dropped: session has no logind id action=Logout target=Tty("/dev/tty1") ...
INFO pam_certauth.monitord: tip: pam_sm_open_session pushes XDG_SESSION_ID to monitord via UpdateSessionTarget; ensure pam_systemd.so precedes pam_certauth.so in the session phase of /etc/pam.d/<login>
```

Корневая причина: на момент `pam_sm_open_session` нашего модуля
`XDG_SESSION_ID` не был выставлен в PAM-environment, поэтому
зарегистрированная в monitord сессия осталась с placeholder-target'ом
(`Tty` / `Display` / `Unknown`), захваченным на auth-фазе. Action-runner
не может вызвать `terminate_session` без logind id.

**Причина 1 (типичная):** `pam_systemd.so` отсутствует в `session`-фазе
сервиса. Бывает, если admin собрал кастомный `/etc/pam.d/<service>` (не
для штатных Astra SE `login`/`fly-dm`).

Проверка:

```bash
sudo grep -nE 'session.*(pam_systemd|certauth)' /etc/pam.d/login /etc/pam.d/fly-dm
```

Фикс: вставить строку `session optional pam_systemd.so` ДО `@include certauth`
(или восстановить из штатного шаблона `dpkg-reconfigure libpam-runtime`).

**Причина 2:** `pam_systemd.so` есть, но стоит ПОСЛЕ `pam_certauth.so`
в `session`-фазе. Наш `sm_open_session` отрабатывает раньше, чем
`pam_systemd` успевает мнти `XDG_SESSION_ID` → пуш UpdateSessionTarget
уходит с пустым значением и игнорируется (см. `pam_certauth.session:
XDG_SESSION_ID not in PAM env`).

Фикс: переставить так, чтобы `session ... pam_systemd.so` шла перед
`@include certauth`. На штатной Astra SE `/etc/pam.d/login` это уже
так — проблема возникает только при ручной переборке.

**Причина 3:** консольная сессия без systemd (sysvinit, OpenRC).
`pam_systemd` не загружен в принципе, `XDG_SESSION_ID` физически не
создаётся → fallback на TTY-based logout (не logind terminate) пока
не реализован — это отдельная задача в roadmap. До тех пор:

- использовать `[on_usb_removed].action = "shutdown"` (грубо, но
  работает) или `"hook"` со своим скриптом, который умеет
  выкинуть пользователя через `pkill -KILL -u <pam_user>` или
  `chvt 1`;
- либо включить systemd на хосте.

**Verify фикса:**

```bash
sudo journalctl -u pam-certauth -f &
# залогиниться, дождаться:
#   INFO pam_certauth.session: pushed logind session target to monitord
#   target=LogindSession { id: "..." }
# извлечь USB:
#   INFO pam_certauth.monitord: grace window expired, dispatching action
#   (logout должен произойти без WARN'а про "no logind id")
```

### Замок-аут после неудачной правки PAM

Симптом: ни один пользователь не может войти, рут-shell тоже.

Recovery:

1. Перезагрузить машину в single-user mode: на экране GRUB добавить
   к строке ядра `systemd.unit=rescue.target` и `init=/bin/bash`.
2. Перемонтировать `/` в `rw`: `mount -o remount,rw /`.
3. Откатить файлы `/etc/pam.d/*` из резервных копий (`*.bak.<TS>`).
4. Перезагрузить.

См. также [docs/operations.md](operations.md) — раздел «Действия при
инцидентах».

### `pam_parsec_mac(login:account): Can't obtain required data`

Симптом: на банкомате Astra SE наш `pam_certauth` отработал успешно
(в логе `pam_certauth.flow: auth result: success`), но через несколько
секунд `pam_parsec_mac` валит login в `account`-фазе:

```
pam_parsec_mac(login:account): Can't obtain required data.
Did you forget add pam_parsec_mac to "auth" stack?
NOTICE: pam_parsec_mac must be added to "auth" "account" and "session" stack
```

`pam_parsec_mac.so` хранит PAM data между фазами: auth-инстанс пишет,
account/session-инстансы читают. Сообщение появляется когда
auth-инстанс **не выполнился**, хотя в файле он формально присутствует.

**Причина 1 (наиболее частая, integrate-pam.sh < 0.3.8):** наш
`@include certauth-only` оказался ПЕРЕД строкой `auth required
pam_parsec_mac.so`. `certauth-only` использует `auth [success=done
default=die] pam_certauth.so` — `success=done` обрывает auth-стек на
успехе, поэтому pam_parsec_mac в auth не успевает положить data.

Проверка:

```bash
sudo grep -n -E 'certauth|parsec_mac' /etc/pam.d/login /etc/pam.d/fly-dm
```

Если номер строки `@include certauth*` **меньше** номера строки `auth
... pam_parsec_mac.so` — это оно. Фикс:

```bash
# integrate-pam.sh >= 0.3.8 расставляет правильно сам
sudo /usr/share/pam-certauth/integrate-pam.sh --unintegrate /etc/pam.d/login
sudo /usr/share/pam-certauth/integrate-pam.sh --mode=cert-only /etc/pam.d/login
sudo /usr/share/pam-certauth/integrate-pam.sh --unintegrate /etc/pam.d/fly-dm
sudo /usr/share/pam-certauth/integrate-pam.sh --mode=cert-only /etc/pam.d/fly-dm

# либо вручную: переместить `auth required pam_parsec_mac.so` ВЫШЕ строки
# `@include certauth*`. Не забыть backup.
```

**Причина 2:** МКЦ-ядро выключено (`parsec.mac=0` в GRUB cmdline), а
`pam_parsec_mac.so` всё равно в `/etc/pam.d/login`. У модуля нет
источника MAC data, любая auth-фаза не может её положить → account
валится. См. подраздел «`parsec.mac=0` + pam_parsec_mac в стеке» ниже.

**Причина 3:** МКЦ-ядро включено, но у пользователя `bfs_service` нет
MAC-уровня. Проверка:

```bash
sudo /sbin/pdpl-user bfs_service
sudo ls /etc/parsec/macdb/$(id -u bfs_service)
```

Если `pdpl-user` показывает только default range `0:0:0x0:0x0` →
`0:0:0x0:0x0` без записи в `/etc/parsec/macdb/<uid>` — выставить
уровень:

```bash
sudo /sbin/pdpl-user --ilevel 63 bfs_service
```

После любого из фиксов:

```bash
sudo systemctl restart fly-dm
# или для console: просто новая попытка login
```

### `parsec.mac=0` + `pam_parsec_mac` в стеке

Симптом: на банкомате МКЦ-ядро отключено через GRUB cmdline
(`parsec.mac=0`), но `/etc/pam.d/login` всё равно содержит
`pam_parsec_mac.so` в auth/account/session. Модуль ждёт MAC data,
которой не существует в ядре с выключенным МКЦ — login deny.

Проверка:

```bash
cat /proc/cmdline | tr ' ' '\n' | grep parsec
cat /sys/module/parsec/parameters/strict_mode    # N = выключен
sudo astra-strictmode-control status             # НЕАКТИВНО
```

Два варианта решения:

**(А) МКЦ нужен** — включить ядро:

```bash
# /etc/default/grub
GRUB_CMDLINE_LINUX_DEFAULT="... parsec.mac=1 parsec.max_ilev=63 ..."
sudo update-grub
sudo reboot
# после ребута — выставить уровни:
sudo /sbin/pdpl-user --ilevel 63 bfs_service
```

**(Б) МКЦ не нужен** — убрать `pam_parsec_mac.so` из стеков и поставить
`runtime = "disabled"` нашему модулю:

```toml
# /etc/pam_certauth/config.toml
[mac]
runtime        = "disabled"
cert_integrity = "ignored"
```

```bash
# закомментировать pam_parsec_mac.so в login и fly-dm
for f in /etc/pam.d/login /etc/pam.d/fly-dm; do
    sudo sed -i.bak 's|^\(\s*\(auth\|account\|session\).*pam_parsec_mac\.so\)|# disabled МКЦ off: \1|' "$f"
done
sudo systemctl restart pam-certauth fly-dm
```

См. также §8.5 для подробной матрицы PAM-стеков с/без МКЦ.

### `unknown field 'enabled', expected one of ... 'runtime'`

Симптом: daemon не стартует, в логе TOML parse error:

```
failed to load monitord config from /etc/pam_certauth/config.toml:
unknown field `enabled`, expected one of `cert_integrity`,
`fallback_max_integrity`, `warn_on_homedir_label_mismatch`, `runtime`
```

Причина: в конфиге осталось legacy-поле `[mac].enabled = true` из
0.3.0–0.3.6. Начиная с 0.3.7 это поле удалено и заменено на
`[mac].runtime`.

Фикс:

```toml
# было
[mac]
enabled        = true
cert_integrity = "optional"

# стало (для МКЦ-ядра ВКЛ)
[mac]
runtime        = "required"     # или "auto"
cert_integrity = "optional"

# или (для МКЦ-ядра ВЫКЛ)
[mac]
runtime        = "disabled"
cert_integrity = "ignored"
```

### WARN `mac_caps_missing` / `pdp_set_fd rc=-1` в логе daemon

Симптом: при старте daemon в `journalctl -u pam-certauth`:

```
WARN mac.audit: F_event="mac_caps_missing" F_detail="PARSEC_CAP_CHMAC not present in effective set"
WARN mac.audit: F_event="mac_sessions_file_label_warning" F_error="parsec error: op=pdp_set_fd rc=-1"
```

Эти warnings **не блокирующие** — daemon стартует и работает. Они
означают что демон не смог выставить МКЦ-метку на свой
`sessions.json`, но auth-flow это не затрагивает.

Чтобы убрать (опционально, только если МКЦ-ядро активно и нужна метка
на session-файле):

```bash
# Выдать PARSEC_CAP_CHMAC пользователю pamcertauth
sudo /sbin/usercaps -m "+3" pamcertauth

# Включить wrapper execaps в systemd unit:
sudo cp /usr/share/pam-certauth/systemd/mac-integrity.conf.example \
    /etc/systemd/system/pam-certauth.service.d/mac-integrity.conf
sudo systemctl daemon-reload
sudo systemctl restart pam-certauth
```

После этого `mac_caps_missing` пропадает. Подробности — `docs/install.md`
раздел §«МКЦ — опциональная активация».

### 14-секундная тишина после `trying USB candidate`

Симптом (0.3.5 и старше): между строкой `pam_certauth.flow: trying
USB candidate devnode=/dev/sdb1` и завершением модуля проходит 10–30
секунд без логов, потом login deny. На USB-флешке Ventoy или
multi-partition USB.

Причина: в этих версиях не было per-candidate logging — модуль
итерировал партиции (mount → discovery → ASN.1 envelope → cleanup) без
вывода. Длительность = количество партиций × таймаут поиска `.p12`.

Фикс: обновиться до 0.3.6 или новее. В 0.3.6 добавлено пошаговое
INFO-логирование:

```
INFO pam_certauth.flow: candidate mounted devnode="/dev/sdb1"
INFO pam_certauth.flow: p12 not found at <path>, skipping candidate
INFO pam_certauth.flow: trying USB candidate devnode="/dev/sdb2"
...
```

После апгрейда `journalctl -t pam_certauth` показывает что именно
происходит в эти секунды.

### `dmi_board_serial = 0` (виртуалка), hash меняется при пересборке VM

Симптом: на VirtualBox/QEMU `/sys/class/dmi/id/board_serial` пуст или
содержит `0`. Если `[host_identity].sources` начинается с
`dmi_board_serial` — resolver правильно делает fallback на следующий
источник (обычно `machine_id`), но при пересборке VM `machine-id`
тоже может измениться → cert с зашитым hash перестаёт валидироваться.

Проверка:

```bash
cat /sys/class/dmi/id/board_serial   # 0 или пусто = непригоден
sudo journalctl -t pam_certauth | grep 'host_identity:' | tail -10
```

Для разработки/тестов на виртуалке рекомендуется:

```toml
[host_identity]
sources  = ["override"]
fallback = "deny"
override = "test-vm-stable-id"     # любая строка, не меняется при пересборке
```

В production на железных банкоматах `dmi_board_serial` обычно валиден.

### fly-dm не показывает greeter banner `Этот банкомат: host_id=...`

Симптом (0.3.7+): сообщение `PAM_TEXT_INFO` от нашего модуля не видно
на greeter UI до prompt'а PIN'а, хотя в `journalctl` оно есть.

Причина: `fly-dm` по умолчанию не пробрасывает PAM info-messages в UI.

Фикс:

```ini
# /etc/X11/fly-dm/fly-dmrc
[greeter]
greeter-show-messages = true
```

```bash
sudo systemctl restart fly-dm
```

### DIGSIG `enforce` без подписи на `pam_certauth.so`

Симптом: `PAM unable to dlopen(pam_certauth.so)` или
`DIGSIG: blocked unsigned ELF` в `dmesg`. На production-Astra с
включённым `astra-digsig-control` в enforce-режиме.

Проверка:

```bash
sudo astra-digsig-control status   # ВКЛЮЧЕНО = enforce
sudo dmesg | grep -i digsig | grep pam_certauth
```

Два варианта:

1. Подписать `.deb`-артефакты через Astra-партнёрский CI/CD
   (`bsign` ключом из `/etc/digsig/keys/`). Стандартный pipeline для
   production.
2. Временно перевести в `logging-only`-режим:

   ```bash
   sudo astra-digsig-control logging
   ```

   Не для production — в syslog появятся `DIGSIG: NOT_ELF_SIGNED` от
   каждого вызова `pam_certauth.so`.

См. также `docs/threat-model.md` §3.7.

### `pam-certauth` в `/etc/pam.d/login` не находится после правки

Симптом: после ручной правки `/etc/pam.d/login` login отказывает с
`Module is unknown` или вообще не стартует.

Проверка:

```bash
ls -la /lib/security/pam_certauth.so
test -f /lib/security/pam_certauth.so && echo "module installed"
sudo ldd /lib/security/pam_certauth.so | grep -i 'not found'
```

- Если `not found` → недостающая зависимость (например `libparsec-mic.so.3`
  на старых сборках). Обновиться до `pam-certauth >= 0.3.7-1_amd64-astra.deb`
  — в этой сборке `cargo:rustc-link-lib=parsec-mic` добавлен в `build.rs`.
- Если файл `pam_certauth.so` отсутствует — `dpkg -l pam-certauth`
  покажет состояние пакета. Возможно прерванная установка → `sudo
  dpkg --configure -a`.

## 11. Хосты без systemd: SysV init

Пакет `pam-certauth` ставит **оба** init-варианта:

- systemd-юнит `pam-certauth.service` — основной, на хостах с
  systemd активируется автоматически через `dh_installsystemd`;
- SysV init-скрипт `/etc/init.d/pam-certauth` — для
  non-systemd окружений (чистый sysvinit, OpenRC). Включается через
  `update-rc.d` или вручную:

  ```bash
  sudo update-rc.d pam-certauth defaults
  sudo service pam-certauth start
  sudo service pam-certauth status
  ```

Скрипт оборачивает запуск `/usr/bin/pam-certauth` через
`start-stop-daemon`, кладёт PID-файл в `/run/pam_certauth/pam-certauth.pid`
и читает `/etc/pam_certauth/config.toml`. На хостах без systemd
hardening-сэндбокса (cgroups, ProtectSystem) — нет, оператор
принимает этот компромисс осознанно. На systemd-хостах править
SysV-скрипт не требуется — авторитативный источник конфигурации
службы — `pam-certauth.service`.

## Дальнейшие шаги

- [docs/configuration.md](configuration.md) — справочник по всем
  параметрам `config.toml`.
- [docs/cert-issuance.md](cert-issuance.md) — выпуск сертификатов с
  расширениями `pam_cert_host_binding` и `pam_cert_user_binding`.
- [docs/operations.md](operations.md) — runbook эксплуатации и
  процедуры incident response.
- [docs/threat-model.md](threat-model.md) — модель угроз и какие
  атаки модуль защищает.

## МКЦ (MAC integrity) — опциональная активация

На хостах Astra SE с включённым strict-mode `pam-certauth` опционально
поддерживает мандатный контроль целостности (МКЦ) — назначает сессии
метку `(level, categories)` согласно расширению `MAX_INTEGRITY` сертификата
пользователя.

**По умолчанию МКЦ-fd-labelling не активируется.** Демон запускается как
`User=pamcertauth` с минимальным capability-set (только
`CAP_DAC_READ_SEARCH`) и без `PARSEC_CAP_CHMAC`. При `[mac]
cert_integrity = "ignore"` (значение по умолчанию) ни один шаг ниже не
требуется — **эта конфигурация production-готова без активации МКЦ.**
postinst на Astra-хостах печатает напоминание о том, как активировать
МКЦ, если оператору это нужно.

### Активация МКЦ

1. **Проверьте strict-mode ядра:**

   ```bash
   sudo /sbin/astra-strictmode-control status
   # ожидается: АКТИВНО
   ```

   Если не активно — включите и перезагрузитесь:

   ```bash
   sudo /sbin/astra-strictmode-control enable
   sudo reboot
   ```

2. **Выдайте PARSEC_CAP_CHMAC демону и поднимите ему МНКЦ=63:**

   ```bash
   sudo /sbin/usercaps -m "+3" pamcertauth
   sudo /sbin/usercaps pamcertauth          # должен содержать parsec_cap_chmac
   sudo /sbin/pdpl-user --ilevel 63 pamcertauth
   ```

   Первая команда добавляет запись в `/etc/parsec/capdb/<uid>` с битом
   3 (`PARSEC_CAP_CHMAC`). Вторая ставит МНКЦ пользователя
   `pamcertauth` в 63 в `/etc/parsec/micdb/<uid>` — это потолок, до
   которого `pam_parsec_mac.so` поднимет ilevel самого процесса демона
   при старте.

3. **Установите шипованный PAM-стек для демона:**

   ```bash
   sudo install -m 0644 \
     /usr/share/pam-certauth/pam.d/pam-certauth.example \
     /etc/pam.d/pam-certauth
   ```

   Стек содержит `session required pam_parsec_cap.so` и `session
   required pam_parsec_mac.so` — две session-фазы, которые перенесут
   parsec capabilities из capdb и поставят ilevel из micdb на сам
   процесс демона в момент `fork+exec`. `auth`/`account` короткозамкнуты
   на `pam_permit.so` — они не используются (демон — service account, а
   не интерактивная сессия).

4. **Установите шипованный drop-in:**

   ```bash
   sudo install -m 0644 \
     /usr/share/pam-certauth/systemd/mac-integrity.conf.example \
     /etc/systemd/system/pam-certauth.service.d/mac-integrity.conf
   sudo systemctl daemon-reload
   sudo systemctl restart pam-certauth.service
   ```

   Drop-in задаёт `AmbientCapabilities=CAP_MAC_ADMIN CAP_MAC_OVERRIDE`
   и `PAMName=pam-certauth`. Последняя директива говорит systemd
   открыть PAM-сессию против `/etc/pam.d/pam-certauth` при запуске
   юнита, благодаря чему `pam_parsec_cap.so`/`pam_parsec_mac.so`
   успевают применить parsec caps и ilevel к процессу демона до того,
   как стартует `ExecStart=`.

   **Историческая заметка.** Ранее эта же активация делалась через
   обёртку `/usr/sbin/execaps -c 0x8 -- ...`. От подхода отказались:
   `execaps` сам зовёт `parsec_capset` на дочерний процесс и требует
   для этого `PARSEC_CAP_CAP` у *запускающего* процесса. Демон под
   `User=pamcertauth` этой capability не имеет — `execaps` падает с
   EPERM ещё до `exec` бинаря. `PAMName=`-подход обходит проблему,
   потому что capability ставится изнутри уже-форкнутого процесса
   через PAM-модуль, а не снаружи через wrapper.

5. **Убедитесь, что capabilities и ilevel активированы в процессе:**

   ```bash
   DPID=$(systemctl show -p MainPID pam-certauth.service | cut -d= -f2)
   sudo cat /proc/$DPID/status | grep ^CapEff
   # должен быть выставлен бит CAP_MAC_ADMIN (33, маска ~0x200000000)
   sudo pdpl-ps $DPID
   # должен показывать ilevel=63 (Уровень_0:...:Нет:0x3f!)
   sudo journalctl -u pam-certauth.service --since="1 min ago" | grep -i mac_caps
   # НЕ должно быть строки "mac_caps_missing"
   ```

6. **Назначьте per-user максимальный integrity (`MNKC`)** для
   end-users, открывающих сессии через pam_certauth — иначе intersect
   с `MAX_INTEGRITY` сертификата всегда выдаст 0:

   ```bash
   sudo /sbin/pdpl-user --ilevel 63 <pam_user>
   ```

7. **Включите политику в `config.toml`:**

   ```toml
   [mac]
   cert_integrity = "required"   # или "optional"
   ```

   ```bash
   sudo systemctl restart pam-certauth.service
   ```

### sudo не требуется

Активация МКЦ не требует выдачи sudo-прав пользователю `pamcertauth`.
Демон никогда не делает privilege-escalation: linux-capabilities приходят
из `AmbientCapabilities=` юнита (выставляется systemd на этапе fork),
а PARSEC capability и ilevel — из parsec capdb/micdb-записей, созданных
`usercaps(8)` и `pdpl-user(8)`, активируемых через `PAMName=pam-certauth`
+ `pam_parsec_cap.so` / `pam_parsec_mac.so` в шипованном PAM-стеке.

### Откат

Возврат к не-МКЦ-дефолту:

```bash
sudo rm /etc/systemd/system/pam-certauth.service.d/mac-integrity.conf
sudo rm /etc/pam.d/pam-certauth
sudo systemctl daemon-reload
sudo systemctl restart pam-certauth.service
```

Также установите `cert_integrity = "ignore"` в `config.toml`, если
секция `[mac]` была добавлена.

### Технический контекст активации

- Runtime-пакет `libpdp3 (>= 3.11+ci97~)` подтягивается автоматически
  при `apt install pam-certauth` (см. `debian/control`).
- postinst на Astra-хостах (`/etc/astra_version`) при включённом
  strict-mode выставляет MAC-лейблы `pdpl-file :::iinh` на
  `/etc/pam_certauth/`, `/var/lib/pam_certauth/`,
  `/var/cache/pam_certauth/` и ставит `chattr +i` на
  `/var/lib/pam_certauth/host_id`. Эти шаги выполняются всегда — они
  безопасны и не зависят от того, активирован МКЦ в `config.toml` или
  нет.
- `sessions.json` лежит в `/run/pam_certauth/` (tmpfs); systemd создаёт
  каталог через `RuntimeDirectory=pam_certauth` на каждом boot. Файл
  intentionally volatile: переживает перезапуск демона в пределах
  одного boot, но не reboot — все sshd/login/sudo-процессы, держащие
  эти сессии, всё равно умирают на reboot.
- Перевыпустите сертификаты пользователей с расширением
  `MAX_INTEGRITY` (OID `2.25.273824307386008814506455310913083078403`).
  См. `docs/cert-issuance.md`. Без этого расширения значение
  применённой метки — нулевой integrity.
- Дополнительные параметры (`required` vs `optional`, обработка
  intersect с MNKC пользователя) описаны в `docs/configuration.md`
  §«MAC integrity».

### МКЦ — поведение по среде установки

Postinst автоматически адаптирует МКЦ-настройку под среду:

| Среда | Что делает postinst |
|---|---|
| Не-Astra (Debian/Ubuntu без parsec) | Полный no-op: `pdpl-file`/`usercaps` отсутствуют, MAC-блок постинста пропускается |
| Astra без strict mode (`astra-strictmode-control is-enabled` = НЕАКТИВНО) | MAC-блок пропускается; кernel не enforce'нет метки, postinst не тратит впустую |
| Astra со strict mode | Ставит `iinh` на конфиг/state-директории, поднимает ilevel=63 на конфиг-файлах, печатает напоминание про opt-in drop-in для daemon'а |

Файл `/usr/share/pam-certauth/systemd/mac-integrity.conf.example` и
парный к нему `/usr/share/pam-certauth/pam.d/pam-certauth.example`
устанавливаются всегда (вместе ≈2 КБ), но активируются только когда
оператор сам копирует их в `/etc/systemd/system/pam-certauth.service.d/`
и `/etc/pam.d/pam-certauth` соответственно, выдаёт
`usercaps -m "+3" pamcertauth` и `pdpl-user --ilevel 63 pamcertauth`.

### Защита конфига через МКЦ

После установки на Astra strict mode:

- `/etc/pam_certauth/config.toml`, `anchors.pem`, `host_acl.toml` имеют
  **ilevel=63 (Высокий)**.
- Процессы с ilevel<63 (включая обычного root без CAP_MAC_ADMIN,
  обычного пользователя) **не могут писать** в эти файлы — kernel
  returns EACCES на любой `O_WRONLY`/`O_RDWR`/`unlink`/`rename`.
- Чтение разрешено (read-down): daemon `pamcertauth` на ilevel=0
  нормально читает конфиг на старте.

Чтобы редактировать конфиг (rotate CA, изменить policy, обновить
host_acl):

```bash
# 1. Поднять max ilevel пользователя-администратора:
sudo /sbin/pdpl-user --ilevel 63 <admin_user>

# 2. Войти под ним. Astra-стандартный fly-dm/login PAM-стек уже включает
#    pam_parsec_mac.so, который поднимет ilevel сессии до МНКЦ пользователя.
ssh <admin_user>@host

# 3. Теперь можно редактировать:
sudo vim /etc/pam_certauth/config.toml
```

Альтернативно для одиночной правки без интерактивной high-ilevel сессии
используйте `execaps`/`runpdp` от root:

```bash
sudo /usr/sbin/runpdp "0:63::" -- vim /etc/pam_certauth/config.toml
```

Это design choice: **только владелец maximum integrity** может
tamper'нуть конфиг pam-certauth'а. Low-integrity malware (даже с full
Linux caps) физически не способно write на ilevel=63 файл.

### Не использую МКЦ — что делать?

Если МКЦ не используется (default `[mac] cert_integrity = "ignore"`):

- На non-Astra хосте — ничего не нужно делать, install no-op для MAC.
- На Astra strict mode — postinst всё равно поднимет ilevel=63 на
  конфиг. Это безвредно: daemon продолжает работать (read-down), просто
  редактировать конфиг можно только из high-integrity сессии. Если эта
  защита не нужна (e.g. тестовый стенд), отключите strict mode
  (`astra-strictmode-control disable`+reboot) или явно опустите ilevel
  назад: `sudo pdpl-file -v "0:0::iinh" /etc/pam_certauth/config.toml`.

### Проверка применения метки

```bash
journalctl -u pam-certauth.service | grep mac_runtime_detected
```

Должна быть запись `F_runtime="libpdp"`. Если `F_runtime="stub"` —
strict-mode не включён или libpdp не найден.

После открытия сессии метка применяется к `sessions.json` через
fd-based API:

```bash
sudo pdpl-file /run/pam_certauth/sessions.json
# verified output (Astra 1.8.4 strict-mode):
# Уровень_0:Сетевые_сервисы:Нет:0x0!
```

В формате метки `pdpl-file` поля идут как
`Уровень_<level>:<categories>:<flags>:<ilevel_hex>!` (4 сегмента,
flags=`Нет` для fd-labeled файлов — `irelax` нельзя передать через
`pdp_set_fd`, ядро возвращает EINVAL; relax-наследование делается
через `iinh` на parent dir).
