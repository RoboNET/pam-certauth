# Runbook эксплуатации pam_certauth

Этот документ — операционный runbook для администратора Astra Linux SE,
обслуживающего парк машин с установленным `pam_certauth`. Каждый
инцидент описан по схеме «симптом → диагностика → действие → проверка».

## 1. Мониторинг

### 1.1 Health-check файл

`monitord` периодически (раз в `5–10` секунд) обновляет
`/run/pam_certauth/health`. Формат:

```
OK 1735689600
```

Алгоритм мониторинга:

1. Прочитать файл.
2. Если первое слово не `OK` — критическая ошибка.
3. Если timestamp старше `60` секунд — stale (демон висит или упал).

### 1.2 systemd-сервис

```bash
systemctl is-active pam-certauth
```

Ожидание: `active`. Любое другое значение — алерт.

### 1.3 Сокет

```bash
test -S /run/pam_certauth/monitord.sock && echo OK || echo FAIL
```

### 1.4 Snippet для Zabbix UserParameter

```ini
UserParameter=pam_certauth.health,
    awk '{print $1}' /run/pam_certauth/health
UserParameter=pam_certauth.timestamp,
    awk '{print $2}' /run/pam_certauth/health
UserParameter=pam_certauth.active,
    systemctl is-active pam-certauth
```

### 1.5 Snippet для Prometheus textfile collector

`/var/lib/node_exporter/textfile_collector/pam_certauth.prom`:

```
# HELP pam_certauth_up 1 if monitord is healthy.
# TYPE pam_certauth_up gauge
pam_certauth_up <0|1>
# HELP pam_certauth_health_age_seconds age of the health file.
# TYPE pam_certauth_health_age_seconds gauge
pam_certauth_health_age_seconds <int>
```

Скрипт обновления (cron каждые 30 сек):

```bash
#!/usr/bin/env bash
set -e
NOW=$(date +%s)
HEALTH=/run/pam_certauth/health
if [[ -f "$HEALTH" ]]; then
    TS=$(awk '{print $2}' "$HEALTH")
    AGE=$((NOW - TS))
    UP=$([[ "$AGE" -lt 60 ]] && echo 1 || echo 0)
else
    AGE=999999
    UP=0
fi
TMP=$(mktemp)
{
    echo "# HELP pam_certauth_up 1 if monitord is healthy."
    echo "# TYPE pam_certauth_up gauge"
    echo "pam_certauth_up $UP"
    echo "# HELP pam_certauth_health_age_seconds"
    echo "# TYPE pam_certauth_health_age_seconds gauge"
    echo "pam_certauth_health_age_seconds $AGE"
} > "$TMP"
mv "$TMP" /var/lib/node_exporter/textfile_collector/pam_certauth.prom
```

## 2. Регулярные операции

### 2.1 Обновление CA-сертификата

**Когда:** за 6 месяцев до истечения текущего CA.

**Как:**

1. Сгенерировать новый CA в HSM или защищённом сегменте.
2. Подписать новый CA старым (cross-sign) для плавного перехода.
3. Распространить новый `chain.pem` на каждое устройство:
   - на USB-носители (Mode A) — обновить `certs/chain.pem`;
   - в `/etc/pam_certauth/ca/bundle.pem` (через apt-репозиторий
     организации или ansible/puppet).
4. Перевыпустить пользовательские сертификаты новой CA-парой,
   сохраняя в них корректные расширения `pam_cert_host_binding` и
   `pam_cert_user_binding` (см. [cert-issuance.md](cert-issuance.md)).
5. После полного перехода — отозвать старый CA через CRL и удалить
   из `[trust].anchors`.

**Проверка:**

```bash
openssl x509 -in /etc/pam_certauth/ca/bundle.pem -noout -enddate
```

### 2.2 Обновление CRL

**Когда:** ежедневно через cron / systemd timer.

**Как:**

systemd timer (`/etc/systemd/system/pam-certauth-crl-update.timer`):

```
[Unit]
Description=pam_certauth daily CRL refresh

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Service (`/etc/systemd/system/pam-certauth-crl-update.service`):

```
[Unit]
Description=pam_certauth CRL refresh

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/pam-certauth-crl-fetch
```

`/usr/local/sbin/pam-certauth-crl-fetch` — скрипт, скачивающий CRL по
подписанному HTTP-каналу или с CA-шары и атомарно перезаписывающий
`/etc/pam_certauth/crl/*.crl`.

**Проверка:**

```bash
ls -la /etc/pam_certauth/crl/
openssl crl -in /etc/pam_certauth/crl/staff.crl -noout -lastupdate -nextupdate
```

### 2.3 Изменение области действия сертификата

**Когда:** при добавлении/удалении пользователя или машины из
области действия конкретного сертификата.

Так как авторизация описана в самих X.509-расширениях
(`pam_cert_host_binding`, `pam_cert_user_binding`), отдельной
конфигурации обновлять не нужно. Жизненный цикл — через УЦ:

1. Отозвать текущий сертификат через CRL (см. §3.1).
2. Перевыпустить сертификат с обновлёнными списками в расширениях
   (рецепты `openssl.cnf` — в [cert-issuance.md](cert-issuance.md)).
3. Распространить новый сертификат на USB/токен пользователя.
4. Обновить CRL на endpoints (см. §2.2).

`monitord` перечитывать конфиг не требуется — изменения вступают в
силу при следующем `pam_sm_authenticate`.

### 2.4 Раскатка клонированного образа

**Когда:** установили один эталонный АРМ, сняли образ, разворачиваете
по парку. На каждой железке `machine_id` / DMI / hostname уникальны и
отличаются от эталонного.

Workflow подробно — в [cert-issuance.md](cert-issuance.md), раздел
«Workflow для клонированных образов». Краткий план:

1. На эталоне `config.toml` — `[host_identity].sources = ["override"]`
   + `override = "installation"`, в trust store — bootstrap-сертификат
   с `host_binding = "installation"` (см. `dist/admin-tools/issue-service-cert.sh`,
   режим `bootstrap`).
2. Клон образа → новая железка → boot. Bootstrap-сертификат принят.
3. Оператор на АРМ-е запускает:
   ```bash
   sudo /usr/share/pam-certauth/finish-bootstrap.sh
   ```
   Скрипт меняет `sources` на реальные (по умолчанию
   `["dmi_board_serial", "machine_id"]`), валидирует конфиг,
   перезапускает daemon, снимает дамп host_id'ов на USB.
4. Оператор приносит USB CA-админу. Админ выписывает per-host
   сертификат по `hash_hex` из строки `active_under_current_config=yes`,
   кладёт через `dist/admin-tools/prepare-usb-flash.sh` обратно
   на ту же флешку.
5. Оператор возвращает USB на АРМ — bootstrap-сертификат больше
   не валиден (host_id_hash изменился после flip-а), работает только
   per-host цепочка.

Для ansible-раскатки скрипт принимает `--non-interactive` и
`--sources "dmi_board_serial,machine_id"`. Идемпотентен.

## 3. Действия при инцидентах

### 3.1 Компрометация сертификата пользователя

**Симптом:** уведомление от пользователя или SOC.

**Действия:**

1. Внести серийник в CRL УЦ.
2. Перевыпустить и опубликовать CRL.
3. Сразу обновить CRL на endpoints (см. §2.2; ускоренная процедура —
   `systemctl start pam-certauth-crl-update.service`).
4. Проверить журнал:

   ```bash
   sudo journalctl -u pam-certauth -g 'revoked' -n 100
   ```

5. Сообщить пользователю; организовать выпуск нового сертификата.

### 3.2 Потеря токена

**Действия:**

1. Revoke серийника (см. 3.1).
2. Дождаться propagation CRL.
3. Выпустить replacement-токен с новым сертификатом, в котором
   корректно проставлены `pam_cert_host_binding` и
   `pam_cert_user_binding` (см. [cert-issuance.md](cert-issuance.md)).

### 3.3 Утрата CA private key (worst-case)

**Действия:**

1. **Немедленно** прекратить новые выпуски сертификатов.
2. Объявить инцидент уровня Critical; задействовать команду ИБ.
3. Disaster recovery — отдельный sub-runbook
   `docs/operations-disaster-recovery.md` (создаётся организацией;
   объём типового документа — 10–20 страниц).
4. Подготовить новый CA из cold-storage backup'а или перевыпустить с
   нуля.
5. Координированное обновление всех endpoints.
6. Опубликовать инцидент через канал `security@...` и в
   [docs/changelog.md](changelog.md) секции `Security`.

### 3.4 monitord не запускается

**Симптом:** `systemctl status pam-certauth` показывает
`failed`.

**Диагностика:**

```bash
sudo journalctl -xeu pam-certauth -n 200
```

**Типовые причины:**

- занятый сокет: проверить `lsof /run/pam_certauth/monitord.sock`;
- нет прав на `/run/pam_certauth/`: проверить `ls -la /run/pam_certauth/`,
  должно быть `0750 root:root`;
- повреждённый `config.toml`: запустить вручную:

  ```bash
  sudo /usr/bin/pam-certauth
  ```

  и прочитать stdout/stderr;
- отсутствие `gost-engine`: проверить `openssl engine gost -t`.

### 3.5 USB-токен заблокирован USBGuard или политикой ЗПС

**Симптом:** аутентификация падает с
`AUTHINFO_UNAVAIL` сразу после вставки токена; в `/var/log/auth.log`
строка вида:

```
pam_certauth: WARN  pam_certauth.flow: usb device found ...
pam_certauth: WARN  pam_certauth.auth: authentication failed
              error=mount: mount(2) failed: Operation not permitted (os error 1)
```

**Причины:**

- USBGuard в `block`-режиме и токен не в allowlist-rule;
- ЗПС (`astra-digsig-control`) в `enforce`-режиме и
  `/lib/security/pam_certauth.so` или `/usr/bin/pam-certauth`
  не подписаны валидным ключом из `/etc/digsig/keys/`.

**Диагностика:**

```bash
# USBGuard
sudo usbguard list-devices              # столбец "block" → токен заблокирован
sudo usbguard list-rules
journalctl -u usbguard.service -n 30 --no-pager

# ЗПС
sudo astra-digsig-control status        # "ВКЛЮЧЕНО"/"НЕАКТИВНО"
sudo dmesg | grep -i digsig | tail
```

**Действие — USBGuard:**

```bash
# либо разрешить конкретный токен по vid:pid:
sudo usbguard append-rule \
    'allow id 0aca:1234 name "Rutoken ECP" hash "ABC..."'

# либо вписать правило в /etc/usbguard/rules.conf и перезапустить:
sudo systemctl restart usbguard
```

Дополнительно в systemd-юнит monitord следует добавить порядок запуска,
чтобы наш демон не стартовал до USBGuard:

```bash
sudo mkdir -p /etc/systemd/system/pam-certauth.service.d
sudo tee /etc/systemd/system/pam-certauth.service.d/usbguard.conf <<EOF
[Unit]
After=usbguard.service
Wants=usbguard.service
EOF
sudo systemctl daemon-reload
```

**Действие — ЗПС:**

`pam_certauth.so` и `pam-certauth` обязаны быть подписаны
системой ЭЦП Astra. На машине разработки подпись устанавливается через
`bsign` GPG-ключом из доверенного связки `/etc/digsig/keys/`. Production-
сборки должны проходить через CI Astra-партнёра, который выдаёт
подписанный `.deb`. Без подписи в `enforce`-режиме никакая
PAM-аутентификация не пройдёт; logging-only режим не блокирует, но
заполняет `/var/log/syslog` шумом `DIGSIG: NOT_ELF_SIGNED`.

### 3.6 USB-токен утерян / заблокирован — пользователь не может войти

**Это by-design**, но операторам сети надо понимать последствия.

`pam_certauth` спроектирован как **жёсткий** второй фактор: без
физического присутствия валидного токена с правильными расширениями
`pam_cert_host_binding` и `pam_cert_user_binding` пользователь
**не может пройти** PAM-стек, в который интегрирован модуль
(`/etc/pam.d/sudo`, `/etc/pam.d/login`, `/etc/pam.d/fly-dm` и т. д.).
Альтернативного пути аутентификации `pam_certauth` сам не предоставляет.

**Что должен сделать админ ДО первого внедрения:**

1. Сохранить локальный root-shell с выключенным `pam_certauth` или
   оставить sudoers-правило для админ-аккаунта без второго фактора —
   иначе блокировка единственного токена выводит из строя машину.
2. Подготовить процесс выпуска **резервных** сертификатов: каждому
   привилегированному пользователю — две физические флешки с разными
   ключами, обе подписаны CA, обе с одинаковым `pam_cert_user_binding`.
3. Документировать SLA на перевыпуск утерянного сертификата
   (см. § 3.1 «Компрометация сертификата пользователя»).

**Что произойдёт при потере токена:**

- Все последующие попытки auth → `Authentication service cannot retrieve
  authentication info` (PAM_AUTHINFO_UNAVAIL после `usb_wait_seconds`,
  по умолчанию 10 c).
- `monitord` продолжит работать, но не зарегистрирует ни одной активной
  сессии — `on_usb_removed`-действие не сработает (нечего блокировать).

**Что произойдёт при блокировке токена USBGuard'ом или ЗПС'ом:**

- То же что при отсутствии токена + строки ошибки в `auth.log` (см. §
  3.5).
- Если блокировка случайная (новое правило USBGuard) — рекомендуется
  держать админ-канал доступа (SSH с key-only auth, без PAM-цепочки
  pam_certauth) до полной валидации развёртывания.

### 3.6.1 USB извлечён, но logout не происходит (0.3.10+)

**Симптом:** в journald корректно фиксируется удаление токена, monitord
объявляет grace-окно истёкшим, но logout/lock не выполняется:

```
INFO pam_certauth.monitord: grace window expired, dispatching action serial="..."
WARN pam_certauth.monitord: USB-removal action dropped: session has no logind id
                            action=Logout target=Tty("/dev/tty1") ...
INFO pam_certauth.monitord: tip: pam_sm_open_session pushes XDG_SESSION_ID to monitord ...
```

**Причина:** `pam_sm_open_session` не смог достать `XDG_SESSION_ID` из
PAM-environment, поэтому monitord-запись осталась с placeholder-target'ом
(`Tty` / `Display` / `Unknown`), а action-runner физически не умеет
вызвать `terminate_session` без logind id.

**Action-runner fallback (текущее поведение, 0.3.10):**

| Конфигурация              | Что произойдёт без logind id                |
|---------------------------|---------------------------------------------|
| `action = "lock"`         | Дропается с WARN; сессия остаётся открытой  |
| `action = "logout"`       | Дропается с WARN; сессия остаётся открытой  |
| `action = "shutdown"`     | Срабатывает — `power_off` не требует logind |
| `action = "hook"`         | Срабатывает — hook получает SESSION_ID env  |

Hook-сценарий даёт оператору запасной выход: написать скрипт, который
сам решает что делать без logind (например `pkill -KILL -u $PAM_USER`
или `chvt 1` + sysrq).

**Полный разбор причин и фикс** — `docs/install.md` §10
«`Logout requested but session has no logind id`».

### 3.7 PAM-стек заблокирован после неудачной правки

**Симптом:** все пользователи (включая root) не могут войти.

**Recovery:**

1. На экране GRUB добавить к строке ядра:
   `systemd.unit=rescue.target init=/bin/bash`.
2. Перемонтировать `/` в `rw`:

   ```bash
   mount -o remount,rw /
   ```

3. Откатить `/etc/pam.d/*` из резервных копий, созданных
   `integrate-pam.sh`:

   ```bash
   ls /etc/pam.d/*.bak.* | tail
   cp /etc/pam.d/sudo.bak.20260501T103000Z /etc/pam.d/sudo
   ```

4. `systemctl reboot`.

## 4. Backup и restore конфигурации

### 4.1 Что бэкапить

- `/etc/pam_certauth/` (config, ca/, crl/);
- `/var/lib/pam_certauth/` (если есть persistent state);
- `/etc/pam.d/` (с резервными копиями `.bak.*`).

### 4.2 Что НЕ бэкапить

- `/run/pam_certauth/` — runtime, восстанавливается systemd-tmpfiles
  при загрузке.
- `/var/cache/pam_certauth/ocsp/` — кэш, восстанавливается при работе.

### 4.3 Команды

Backup:

```bash
sudo tar --acls --xattrs -czf /backup/pam_certauth-$(date +%F).tgz \
    /etc/pam_certauth /var/lib/pam_certauth /etc/pam.d
gpg --encrypt --recipient backup@example.test \
    /backup/pam_certauth-$(date +%F).tgz
```

Restore:

```bash
gpg --decrypt /backup/pam_certauth-2026-01-20.tgz.gpg \
    | sudo tar -xzC /
sudo systemctl reload pam-certauth
```

## 5. Ротация `gost-engine` при обновлении Astra

### 5.1 Когда

После `apt upgrade`, в логах указано обновление пакета `gost-engine` или
`libgost-engine`.

### 5.2 Что проверить

```bash
openssl engine gost -t
# Сразу после обновления должен показывать [ available ].
pamtester sudo alice authenticate
# Smoke-тест аутентификации после обновления.
```

### 5.3 Откат

Если обновление сломало совместимость:

```bash
apt install gost-engine=<previous-version>
apt-mark hold gost-engine
sudo systemctl restart pam-certauth
```

## 6. Логи: где искать, что искать

### 6.1 monitord

```bash
sudo journalctl -u pam-certauth
sudo journalctl -u pam-certauth -g 'pam_certauth.monitord'
```

> Имя `pam_certauth.monitord` сохраняется как операционный ABI: им
> пользуются журнал-агрегаторы и шаблоны journalctl-фильтров. Сам
> бинарь и unit называются `pam-certauth`, но `tracing target` и
> путь к Unix-сокету (`/run/pam_certauth/monitord.sock`) остаются
> историческими — переименование сломало бы фильтры в проде.

Полезные теги:

- `pam_certauth.monitord.start` — запуск.
- `pam_certauth.monitord.removal` — udev REMOVE-события.
- `pam_certauth.monitord.reinsert` — отмена в grace-окне.
- `pam_certauth.monitord.lock` — отправка `LockSession` к logind.
- `pam_certauth.monitord.reload` — reload конфига.
- `USB-removal action dropped` (WARN, 0.3.10+) — action не отправлен,
  потому что в сессии нет logind id. См. §3.6.1.
- `pushed logind session target to monitord` (INFO, `pam_certauth.session`,
  0.3.10+) — `pam_sm_open_session` успешно проксировал `XDG_SESSION_ID`
  в monitord; норма для logind-сессии.

### 6.2 cdylib (PAM-модуль)

```bash
sudo tail -f /var/log/auth.log
sudo journalctl -t pam_certauth
```

Полезные теги:

- `pam_certauth.auth.start` — начало `pam_sm_authenticate`.
- `pam_certauth.auth.success` — успех.
- `pam_certauth.auth.fail.<reason>` — отказ; `<reason>` — категория.
- `pam_certauth.cert_scope.host_mismatch` — `host_id_hash` не входит
  в `pam_cert_host_binding`.
- `pam_certauth.cert_scope.user_mismatch` — `pam_user` не входит в
  `pam_cert_user_binding`.
- `pam_certauth.session.open` — открыта сессия.
- `pam_certauth.session.close` — закрыта сессия.

### 6.3 Полезные `grep`-фильтры

```bash
# Все отказы за сутки:
sudo journalctl -t pam_certauth --since="1 day ago" | grep -F 'auth.fail'

# Все события извлечения USB:
sudo journalctl -u pam-certauth | grep -F 'monitord.removal'

# Все mismatch'и cert scope (host/user binding):
sudo journalctl -t pam_certauth | grep -E 'cert_scope\.(host|user)_mismatch'

# Сессии конкретного пользователя:
sudo journalctl -t pam_certauth | grep -E 'pam_user[=:]"alice"'
```

### 6.4 Что не логируется (по политике)

- PIN-коды и парольные фразы — `<redacted>`.
- Полные DN сертификатов на уровне `info` — отображаются только CN.
  На уровне `debug` — полный DN.
- Полное содержимое X.509-расширений `pam_cert_host_binding` /
  `pam_cert_user_binding` — на уровне `info` логируется только
  совпавшая запись; полный список — на уровне `debug`.

## 7. МКЦ (MAC integrity)

Активация мандатного контроля целостности — опциональный шаг,
выполняется оператором вручную после установки пакета. Демон
`pam-certauth.service` работает как `pamcertauth` без
`CAP_MAC_ADMIN`/`PARSEC_CAP_CHMAC`, пока оператор не установит
шипованный drop-in
`/usr/share/pam-certauth/systemd/mac-integrity.conf.example` в
`/etc/systemd/system/pam-certauth.service.d/`, парный PAM-стек
`/usr/share/pam-certauth/pam.d/pam-certauth.example` в
`/etc/pam.d/pam-certauth` (использует `pam_parsec_cap.so` +
`pam_parsec_mac.so`) и не выдаст `PARSEC_CAP_CHMAC` через
`usercaps -m "+3" pamcertauth` плюс `pdpl-user --ilevel 63 pamcertauth`.
Полная процедура активации, проверки и отката описана в
[docs/install.md §«МКЦ (MAC integrity) — опциональная активация»](install.md#мкц-mac-integrity--опциональная-активация).

**Состояние сессий.** Реестр `sessions.json` лежит на tmpfs
(`/run/pam_certauth/sessions.json`, `RuntimeDirectory=`). Volatile
across reboot — это by design: sshd/login/sudo-процессы, держащие
эти сессии, всё равно умирают на reboot. `daemon.lock` и
OCSP/CRL-кэши остаются в `/var/lib/pam_certauth/` и
`/var/cache/pam_certauth/` соответственно.

## 8. Emergency contact

Для конфиденциальных сообщений о безопасности — см. контакты в
[README.md](../README.md#безопасность-и-сообщения-об-уязвимостях).
