# Migration 0.1.x → 0.2.0 (+ 0.2.0 → 0.2.1 breaking)

В 0.2.0 появилась поддержка scopes и M-of-N work order. Это аддитивные
изменения: существующие deployments продолжают работать без правок,
если scopes не используются. Но для production-апгрейда есть
несколько обязательных шагов.

## 0.2.0 → 0.2.1 (breaking для scope c `require_argv_pattern`)

В 0.2.0 `argv_pattern` доставлялся unsigned-сайдкаром
`<work_order>.cms.pattern` рядом с CMS-файлом. Это был security gap:
любой локальный актор мог переписать сайдкар без инвалидации подписей
одобряющих, фактически обойдя intent M-of-N approval.

В 0.2.1 `argv_pattern` читается **только** из подписанного
`encapContentInfo.eContent` CMS. Сайдкар-файлы игнорируются.

**Что делать:**

* Перевыпустить все work orders для scope с `require_argv_pattern`:
  ```bash
  cat > payload.toml <<'EOF'
  argv_pattern = "flashrom -w /opt/fw/fw_v*.bin"
  EOF
  openssl cms -sign -in payload.toml -signer alice.pem -inkey alice.key \
      -outform DER -binary -nodetach -out wo.cms   # ← -nodetach обязателен
  openssl cms -resign -inform DER -in wo.cms -signer bob.pem -inkey bob.key \
      -outform DER -binary -out wo.cms
  ```
* Удалить любые `*.cms.pattern` файлы — они не читаются и могут
  ввести оператора в заблуждение.
* См. `work-order.md` для полной процедуры.

## Что точно меняется

1. **Бинарь переименован.** Был `pam-certauth-monitord`, стал
   `pam-certauth` (мульти-командный CLI). Старый имя сохранено
   в `pam-certauth.service` как symlink на период миграции.
   Команда `pam-certauth daemon` запускает старое поведение
   monitord; новые subcommands — `execute`, `policy`, `gc`.

2. **IPC version: 1 → 2.** Сервер 0.2.0 отказывает клиентам v1
   (`Error { code: 1000 }`). Обновляйте cdylib и daemon синхронно
   (через `.deb`-пакет — это атомарно).

3. **Audit-payload `SessionOpen` расширен.** В v2 добавлены поля
   `engineer_ski`, `engineer_cert_sha256`, `scopes`, `uid`. Внешние
   потребители аудит-логов могут продолжать парсить — поля
   аддитивные.

## Что появилось (опционально)

| Фича                            | Где включается                              | Обязательно? |
|---------------------------------|---------------------------------------------|--------------|
| `pam_cert_scopes` X.509 ext     | новый расширение на сертификате             | нет          |
| M-of-N CMS work order           | `pam-certauth-execute` + `policy.toml`      | нет          |
| `[approver_trust]` секция       | `config.toml`                                | при использовании `execute` |
| `[tsa_trust]` секция            | `config.toml`                                | при `require_timestamp_token=true` (deferred) |
| `[policy]` секция               | `config.toml`                                | при использовании `execute` |
| `require_scope` PAM-параметр    | строка модуля в `/etc/pam.d/...`            | нет          |
| GC timer (retention)            | systemd unit                                 | при использовании `execute` |

## Шаги апгрейда (production)

### 1. Обновить пакет

```bash
sudo apt update && sudo apt install pam-certauth=0.2.0
```

После установки:

- daemon перезапустится через `dpkg` triggers;
- cdylib обновится атомарно;
- старые сессии в `/var/lib/pam_certauth/sessions.json` пере-валидируются
  (формат совместим).

### 2. (опционально) Включить scopes в существующих сертификатах

Если планируется `pam-certauth-execute`, инженерским сертификатам
нужно добавить `pam_cert_scopes`. Это требует **переоформления**
leaf'ов через ваш CA. Старые сертификаты без scopes продолжают
работать для PAM-логина — отсутствие `pam_cert_scopes` блокирует
только `execute`.

См. [x509-extensions.md](x509-extensions.md).

### 3. Настроить approver-CA

Банкам / удостоверяющим центрам нужно выдать сертификаты
подписантам (short-lived: 24–72 ч), содержащие:

- `pam_cert_scopes` со списком scope, которые они вправе одобрять;
- EKU `approver_eku` (если включён `require_approver_eku`).

Approver-CA может быть отдельным сертификатным ансамблем или
поддеревом существующего PKI. Anchor добавляется в
`[approver_trust]`:

```toml
[approver_trust]
anchors = ["/etc/pam_certauth/ca/approver-bundle.pem"]
```

### 4. Создать `policy.toml`

```bash
sudo install -m 0640 -o root -g root \
    /usr/share/doc/pam-certauth/policy.toml.example \
    /etc/pam_certauth/policy.toml
sudo pam-certauth policy validate \
    --path=/etc/pam_certauth/policy.toml
```

Сослаться на него в `config.toml`:

```toml
[policy]
path = "/etc/pam_certauth/policy.toml"
require_approver_eku = true
signing_time_skew_seconds = 300
krl_poll_interval_seconds = 60
```

### 5. Обновить sudoers

```text
%atm_engineers ALL=(root) NOPASSWD: /usr/bin/pam-certauth-execute *
```

См. [execute.md](execute.md).

**Адаптация существующих sudo-конфигураций (важно).** Целевая модель
0.2.0 — на ATM **нет** учётных записей с интерактивным sudo (см.
[architecture.md §1.1.1](architecture.md) и
[threat-model.md §1.2](threat-model.md)). При апгрейде с 0.1.x:

- Убрать инженерские аккаунты из групп `sudo` / `wheel` / `admin`,
  если они там оказались на этапе провижининга 0.1.x:

  ```bash
  for u in $(getent group atm_engineers | cut -d: -f4 | tr ',' ' '); do
      sudo gpasswd -d "$u" sudo  2>/dev/null || true
      sudo gpasswd -d "$u" wheel 2>/dev/null || true
      sudo gpasswd -d "$u" admin 2>/dev/null || true
  done
  ```

- Удалить (или ограничить до recovery-аккаунта) любые широкие
  правила вида `NOPASSWD: ALL` / `(ALL) ALL` в `/etc/sudoers.d/`,
  относящиеся к инженерам. Их заменяет узкое правило выше.

- **Проверка отрицательная:** под учёткой инженера `sudo -i`
  должен **отказать**:

  ```bash
  sudo -u alice -i sudo -i
  # ожидание: Sorry, user alice is not allowed to execute '/bin/bash' as root
  ```

  Положительная проверка — `pam-certauth-execute` остаётся
  разрешённым (см. §7 ниже).

- **Не отключать сам механизм логина** — инженер по-прежнему должен
  иметь возможность залогиниться через PAM cert-auth, чтобы потом
  вызывать `pam-certauth-execute`. Удаление из `wheel` / `sudo` не
  ломает логин (логин управляется PAM-стеком, а не sudoers).

- Аудит инварианта — см. [operations.md §1.6](operations.md).

### 6. Включить GC-timer

```bash
sudo systemctl enable --now pam-certauth-gc.timer
systemctl list-timers pam-certauth-gc.timer
```

### 7. (опционально) Включить `require_scope` в PAM

В `/etc/pam.d/<service>`:

```text
auth required pam_certauth.so \
    config=/etc/pam_certauth/config.toml \
    require_scope=bios.flash,atm.diag.dump \
    scope_match=any
```

Это блокирует логин, если у инженера нет ни одного из перечисленных
scope.

## Rollback

`pam-certauth-0.1.x` пакеты остаются в репозитории. Apt-downgrade
работает, **но**:

- сессии, открытые на 0.2.0 с v2-payload, будут отброшены при
  старте 0.1.x (формат `sessions.json` ужесточился).
- `pam-certauth-execute` исчезнет — work-order'ы, отправленные
  оператору, временно нельзя будет применить.

Рекомендация: тестовый rollback на стенде до production-выкатки.

## Известные ограничения 0.2.0

- RFC 3161 TSA: валидация не реализована; `require_timestamp_token=true`
  отклоняет CMS до phase 2.
- `argv_pattern` доставляется sidecar-файлом `<wo>.pattern`, не
  encapContent CMS. Запланировано в phase 2.
- `policy.toml` подписывание не реализовано; защита — root containment
  + audit drift через `policy_sha256`.

См. [changelog.md](changelog.md) и [threat-model.md](threat-model.md).
