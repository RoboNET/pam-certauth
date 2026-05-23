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

`pam_certauth` поддерживает **два варианта** разметки USB-носителя:

**Вариант A — FS на разделе (рекомендуется для флешек с partition table).**
Большинство магазинных флешек поставляются уже с MBR/GPT и одним разделом.
Имя метки **должно** быть ровно `PAMCERT` (с учётом регистра).
Если на whole-device нет ФС, `pam_certauth` ищет среди разделов ровно один
с меткой `PAMCERT` и FS из allowlist (`vfat`, `exfat`, `ext4`, `ntfs`).
Если подходящих разделов несколько — отказ (fail-closed).

```bash
# ВНИМАНИЕ: команда УНИЧТОЖАЕТ данные на устройстве /dev/sdX1.
# Замените sdX1 на реальный путь к разделу USB-носителя
# (lsblk | grep -i usb).
sudo mkfs.ext4 -L PAMCERT /dev/sdX1
```

**Вариант B — FS прямо на whole-device (без partition table).**
Совместимый сценарий, использовавшийся в более ранних версиях. Метка не
требуется (но не мешает). `pam_certauth` сразу читает `ID_FS_TYPE` у
udev-устройства и монтирует его.

```bash
# ВНИМАНИЕ: УНИЧТОЖАЕТ partition table и данные.
sudo wipefs -a /dev/sdX
sudo mkfs.ext4 -L PAMCERT /dev/sdX
```

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

### 8.1 fly-dm

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

### 8.5 Безопасность правки

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
`HostExtensionMissing` в журнале.

Диагностика:

```bash
cat /etc/machine-id
journalctl -u pam-certauth -g host_id -n 20
openssl x509 -in /tmp/ca/alice.pem -noout -text \
    | grep -A1 '2\.25\.183976554325829274683049824615098'
```

Сверить `sha256:<HEX>`-записи из расширения с реально вычисленным
`host_id_hash = sha256(host_id)` (см.
[architecture.md](architecture.md#host-identity-chain)).

### `user_binding mismatch`

Симптом: цепь сертификата валидна, но конкретный пользователь
отвергается с `UserNotAllowed` / `UserExtensionMissing`.

Решение: проверить, что имя `pam_user` присутствует в расширении
`pam_cert_user_binding` сертификата:

```bash
openssl x509 -in /tmp/ca/alice.pem -noout -text \
    | grep -A1 '2\.25\.215438916728501023845629178354627'
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
