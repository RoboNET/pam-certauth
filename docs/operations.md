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
systemctl is-active pam-certauth-monitord
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
    systemctl is-active pam-certauth-monitord
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
   sudo journalctl -u pam-certauth-monitord -g 'revoked' -n 100
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

**Симптом:** `systemctl status pam-certauth-monitord` показывает
`failed`.

**Диагностика:**

```bash
sudo journalctl -xeu pam-certauth-monitord -n 200
```

**Типовые причины:**

- занятый сокет: проверить `lsof /run/pam_certauth/monitord.sock`;
- нет прав на `/run/pam_certauth/`: проверить `ls -la /run/pam_certauth/`,
  должно быть `0750 root:root`;
- повреждённый `config.toml`: запустить вручную:

  ```bash
  sudo /usr/sbin/pam-certauth-monitord
  ```

  и прочитать stdout/stderr;
- отсутствие `gost-engine`: проверить `openssl engine gost -t`.

### 3.5 PAM-стек заблокирован после неудачной правки

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
sudo systemctl reload pam-certauth-monitord
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
sudo systemctl restart pam-certauth-monitord
```

## 6. Логи: где искать, что искать

### 6.1 monitord

```bash
sudo journalctl -u pam-certauth-monitord
sudo journalctl -u pam-certauth-monitord -g 'pam_certauth.monitord'
```

Полезные теги:

- `pam_certauth.monitord.start` — запуск.
- `pam_certauth.monitord.removal` — udev REMOVE-события.
- `pam_certauth.monitord.reinsert` — отмена в grace-окне.
- `pam_certauth.monitord.lock` — отправка `LockSession` к logind.
- `pam_certauth.monitord.reload` — reload конфига.

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
sudo journalctl -u pam-certauth-monitord | grep -F 'monitord.removal'

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

## 7. Emergency contact

Для конфиденциальных сообщений о безопасности — см. контакты в
[README.md](../README.md#безопасность-и-сообщения-об-уязвимостях).
