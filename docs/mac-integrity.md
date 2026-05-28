# МКЦ (MAC integrity) — opt-in activation

End-to-end активация мандатного контроля целостности (Astra SE
strict-mode) для `pam_certauth`. Документ собран из install/configuration/
threat-model — здесь всё, что нужно для решения «нужен мне МКЦ или нет»
и пошаговой активации.

> **TL;DR.** На банкомате без МКЦ-ядра — оставить `cert_integrity = "ignore"`,
> `runtime = "disabled"`, не трогать `pam_parsec_mac.so`. На банкомате
> с МКЦ-ядром — поднять capability демону, прописать `runtime = "required"`,
> `cert_integrity = "required"` или `"optional"`, выпустить cert с
> расширением `MAX_INTEGRITY`.

## 1. Три уровня контроля

`pam_certauth` решает три независимых вопроса:

| Уровень          | Что решает                                   | Где конфигурируется            |
|------------------|----------------------------------------------|--------------------------------|
| **compile-time** | Может ли бинарь линковаться с libpdp         | feature `astra-mac` (Cargo)    |
| **runtime**      | Использует ли настоящий backend в процессе   | `[mac].runtime` в config.toml  |
| **policy**       | Что делать, если cert не содержит метки      | `[mac].cert_integrity`         |

Эти три уровня позволяют один и тот же `.deb` (собранный с
`astra-mac`) ставить на:

- банкомат с МКЦ-3 → `runtime = "required"`;
- банкомат без МКЦ → `runtime = "disabled"`;
- дев-машину/смешанный парк → `runtime = "auto"`.

Поведение управляется через `config.toml`, не пересборкой.

## 2. Когда МКЦ не нужен (default)

`cert_integrity = "ignore"` (default) — production-готовая
конфигурация без активации МКЦ:

- демон запускается как `User=pamcertauth` с минимальным
  capability-set (`CAP_DAC_READ_SEARCH`);
- никакие `pdp_*` вызовы не делаются;
- расширение `MAX_INTEGRITY` в cert парсится для диагностики
  (`mac_label_parsed`), но не применяется.

Эта конфигурация работает на:

- Не-Astra хостах (Debian/Ubuntu без parsec) — `pdpl-file`/`usercaps`
  отсутствуют, MAC-блок postinst пропускается, **полный no-op**.
- Astra без strict-mode — kernel не enforce'нет метки, postinst
  пропускает MAC-блок.
- Astra со strict-mode, но без opt-in активации — postinst ставит
  `iinh` на конфиг-директории (защита write от low-integrity),
  daemon работает на ilevel=0 (read-down работает).

**Ничего настраивать не надо.** postinst на Astra печатает напоминание
о том, как активировать МКЦ, если оператору это нужно.

## 3. Когда МКЦ нужен

- Production банкомат на Astra SE strict-mode 1.8.3+.
- Cert содержит расширение `MAX_INTEGRITY` (OID
  `2.25.273824307386008814506455310913083078403`) — потолок integrity
  сессии инженера.
- Требуется, чтобы доверенные приложения в desktop-сессии
  наследовали высокий ilevel от `pam_sm_open_session`.

## 4. Активация МКЦ

### 4.1 Проверить strict-mode ядра

```bash
sudo /sbin/astra-strictmode-control status
# ожидается: АКТИВНО
```

Если не активно — включить и перезагрузиться:

```bash
sudo /sbin/astra-strictmode-control enable
sudo reboot
```

Альтернативно — через GRUB:

```bash
# /etc/default/grub
GRUB_CMDLINE_LINUX_DEFAULT="... parsec.mac=1 parsec.max_ilev=63 ..."
sudo update-grub
sudo reboot
```

Verify:

```bash
cat /proc/cmdline | tr ' ' '\n' | grep parsec
cat /sys/module/parsec/parameters/strict_mode    # Y = включён
```

### 4.2 Выдать `PARSEC_CAP_CHMAC` демону и поднять ему МНКЦ=63

```bash
sudo /sbin/usercaps -m "+3" pamcertauth
sudo /sbin/usercaps pamcertauth          # должен содержать parsec_cap_chmac
sudo /sbin/pdpl-user --ilevel 63 pamcertauth
```

Первая команда добавляет запись в `/etc/parsec/capdb/<uid>` с битом
3 (`PARSEC_CAP_CHMAC`). Вторая ставит МНКЦ пользователя `pamcertauth`
в 63 в `/etc/parsec/micdb/<uid>` — потолок, до которого
`pam_parsec_mac.so` поднимет ilevel самого процесса демона при старте.

### 4.3 Установить шипованный PAM-стек для демона

```bash
sudo install -m 0644 \
  /usr/share/pam-certauth/pam.d/pam-certauth.example \
  /etc/pam.d/pam-certauth
```

Стек содержит `session required pam_parsec_cap.so` и
`session required pam_parsec_mac.so` — две session-фазы, которые
перенесут parsec capabilities из capdb и поставят ilevel из micdb на
сам процесс демона в момент `fork+exec`. `auth`/`account`
короткозамкнуты на `pam_permit.so` — они не используются (демон —
service account, не интерактивная сессия).

### 4.4 Установить шипованный systemd drop-in

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
юнита, благодаря чему `pam_parsec_cap.so`/`pam_parsec_mac.so` успевают
применить parsec caps и ilevel к процессу демона до того, как
стартует `ExecStart=`.

**Историческая заметка.** Раньше эта активация делалась через обёртку
`/usr/sbin/execaps -c 0x8 -- ...`. Отказались: `execaps` зовёт
`parsec_capset` на дочерний процесс и требует `PARSEC_CAP_CAP` у
*запускающего* процесса. Демон под `User=pamcertauth` этой capability
не имеет — `execaps` падает с EPERM ещё до `exec`. `PAMName=`-подход
обходит проблему, потому что capability ставится изнутри
уже-форкнутого процесса через PAM-модуль.

### 4.5 Verify caps + ilevel активированы

```bash
DPID=$(systemctl show -p MainPID pam-certauth.service | cut -d= -f2)
sudo cat /proc/$DPID/status | grep ^CapEff
# должен быть выставлен бит CAP_MAC_ADMIN (33, маска ~0x200000000)
sudo pdpl-ps $DPID
# должен показывать ilevel=63 (Уровень_0:...:Нет:0x3f!)
sudo journalctl -u pam-certauth.service --since="1 min ago" | grep -i mac_caps
# НЕ должно быть строки "mac_caps_missing"
```

### 4.6 Назначить per-user MNKC для end-users

Иначе intersect с `MAX_INTEGRITY` cert всегда выдаст 0:

```bash
sudo /sbin/pdpl-user --ilevel 63 <pam_user>
```

### 4.7 Включить политику в `config.toml`

```toml
[mac]
cert_integrity = "required"   # или "optional"
runtime        = "required"   # fail-closed на банкомате с МКЦ
```

```bash
sudo systemctl restart pam-certauth.service
```

## 5. Конфигурация `[mac]` в `config.toml`

Полный справочник полей — [configuration.md §MAC integrity](configuration.md).
Кратко:

| Поле                              | Default      | Что делает                                                                                  |
|-----------------------------------|--------------|---------------------------------------------------------------------------------------------|
| `cert_integrity`                  | `"ignore"`   | `required` / `optional` / `ignore`. Что делать с cert без `MAX_INTEGRITY`.                  |
| `runtime`                         | `"auto"`     | `required` / `auto` / `disabled`. Какой backend (real libpdp или stub).                     |
| `fallback_max_integrity.level`    | —            | Уровень fallback-метки если cert без расширения и `cert_integrity = "optional"`.            |
| `fallback_max_integrity.categories` | —          | Битовая маска категорий fallback (hex или CSV).                                             |
| `warn_on_homedir_label_mismatch`  | `true`       | Логировать `homedir_label_above_session_cap` при расхождении.                               |

### Матрица `runtime × cert_integrity × astra-mac`

| `runtime`  | `cert_integrity` | astra-mac | Поведение                                                                 |
|------------|------------------|-----------|---------------------------------------------------------------------------|
| `disabled` | любая            | любая     | StubBackend, нет `pdp_*`. Событие `mac_runtime_disabled` (INFO).          |
| `disabled` | `required`       | любая     | **Отвергается на старте** — несовместимо.                                 |
| `required` | любая            | без флага | **Отвергается на старте** — нет libpdp.                                   |
| `required` | любая            | с флагом  | Fail-closed. Если ядро не active → `mac_runtime_required` (ERROR).        |
| `auto`     | любая            | с флагом  | Probe ядра. Active → `ParsecBackend`. Inactive → stub + `mac_runtime_fallback` (WARN). |
| `auto`     | любая            | без флага | Всегда stub.                                                              |

### Эффективная метка

При `open_session`:

```
effective = intersect(cert_label, runtime_caps)
```

`runtime_caps` — потолок от libpdp `ipdp_get_caps()`. Уровень эффективной
метки — `min(cert.level, caps.level)`; категории —
`cert.categories & caps.categories`. Если `effective.level < cert.level`
— пишется `mac_level_intersected`.

### Полный пример (production МКЦ)

```toml
[mac]
cert_integrity = "required"
runtime        = "required"
```

### Полный пример (миграция / dev)

```toml
[mac]
cert_integrity = "optional"
runtime        = "auto"

[mac.fallback_max_integrity]
level      = 0
categories = ""
```

## 6. PAM-стек для МКЦ-сценариев

Стек PAM зависит от того, включено ли МКЦ-ядро. `pam_parsec_mac.so`
в стеке нужен **только когда МКЦ-ядро реально работает**.

### МКЦ выключен (`runtime = "disabled"`)

```
# /etc/pam.d/login (0.3.12+ two-include pattern)
@include certauth
auth       requisite   pam_nologin.so
auth       required    pam_env.so
@include common-auth
@include common-account
@include common-session
session    required    pam_certauth.so   # ← ПОСЛЕ common-session
```

Никаких `pam_parsec_mac.so` в стеке.

### МКЦ включён (`runtime = "required"`)

```
# /etc/pam.d/login (0.3.12+ two-include pattern)
auth       required   pam_parsec_mac.so       # ← raw МКЦ строка
@include certauth                              # ← добавлено integrate-pam.sh
account    required   pam_parsec_mac.so
@include common-session
session    required   pam_parsec_cap.so
session    required   pam_parsec_mac.so
session    required   pam_certauth.so          # ← добавлено integrate-pam.sh
```

`pam_parsec_mac.so` в `account` и `session` фазах читает MAC-контекст,
выставленный в `auth`-фазе. Если в `auth` нет ни одного модуля,
который выставит этот контекст, login падает с
`pam_parsec_mac(login:account): Can't obtain required data`.
См. [troubleshooting.md §5](troubleshooting.md#5-мкц-astra-strict-mode).

### Mixed (`runtime = "auto"`)

Тот же стек, что для «МКЦ включён» — `auto` пробует libpdp,
а `pam_parsec_mac.so` в стеке безопасен на любой машине, где
МКЦ-ядро присутствует (даже если выключено).

## 7. Защита `config.toml` через МКЦ

После активации МКЦ:

- `/etc/pam_certauth/config.toml`, `anchors.pem`, `host_acl.toml` имеют
  **ilevel=63 (Высокий)**.
- Процессы с ilevel<63 (включая обычного root без `CAP_MAC_ADMIN`)
  **не могут писать** в эти файлы — kernel возвращает EACCES на любой
  `O_WRONLY`/`O_RDWR`/`unlink`/`rename`.
- Чтение разрешено (read-down): daemon на ilevel=0 нормально читает
  конфиг на старте.

### Как редактировать защищённый конфиг

```bash
# 1. Поднять max ilevel пользователя-администратора:
sudo /sbin/pdpl-user --ilevel 63 <admin_user>

# 2. Войти под ним. Astra-стандартный fly-dm/login PAM-стек уже включает
#    pam_parsec_mac.so, который поднимет ilevel сессии до МНКЦ пользователя.
ssh <admin_user>@host

# 3. Теперь можно редактировать:
sudo vim /etc/pam_certauth/config.toml
```

Альтернативно для одиночной правки без high-ilevel сессии:

```bash
sudo /usr/sbin/runpdp "0:63::" -- vim /etc/pam_certauth/config.toml
```

**Design choice:** только владелец maximum integrity может tamper'нуть
конфиг. Low-integrity malware (даже с full Linux caps) физически не
способно write на ilevel=63 файл.

## 8. Verify применения метки

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

Формат метки `pdpl-file`:
`Уровень_<level>:<categories>:<flags>:<ilevel_hex>!`. `flags=Нет` для
fd-labeled файлов — `irelax` нельзя передать через `pdp_set_fd`, ядро
возвращает EINVAL; relax-наследование делается через `iinh` на parent
dir.

## 9. Откат активации

Возврат к не-МКЦ-default:

```bash
sudo rm /etc/systemd/system/pam-certauth.service.d/mac-integrity.conf
sudo rm /etc/pam.d/pam-certauth
sudo systemctl daemon-reload
sudo systemctl restart pam-certauth.service
```

Также установить `cert_integrity = "ignore"`, `runtime = "disabled"`
в `config.toml`, если секция `[mac]` была добавлена.

## 10. Технический контекст

- Runtime-пакет `libpdp3 (>= 3.11+ci97~)` подтягивается автоматически
  при `apt install pam-certauth` (см. `debian/control`).
- postinst на Astra-хостах (`/etc/astra_version`) при включённом
  strict-mode выставляет MAC-лейблы `pdpl-file :::iinh` на
  `/etc/pam_certauth/`, `/var/lib/pam_certauth/`,
  `/var/cache/pam_certauth/` и `chattr +i` на
  `/var/lib/pam_certauth/host_id`. Безопасно и не зависит от
  активации МКЦ в `config.toml`.
- `sessions.json` лежит в `/run/pam_certauth/` (tmpfs); systemd создаёт
  каталог через `RuntimeDirectory=pam_certauth` на каждом boot. Файл
  intentionally volatile: переживает рестарт демона в пределах одного
  boot, но не reboot.
- Активация МКЦ **не требует** sudo-прав пользователю `pamcertauth`.
  Демон никогда не делает privilege-escalation: linux-capabilities из
  `AmbientCapabilities=` юнита, parsec capability и ilevel — из
  capdb/micdb через PAM-стек `pam-certauth`.

## 11. Поведение postinst по среде

| Среда                                | postinst делает                                                                                                                            |
|--------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| Не-Astra (Debian/Ubuntu)             | Полный no-op: `pdpl-file`/`usercaps` отсутствуют, MAC-блок пропускается                                                                    |
| Astra без strict mode                | MAC-блок пропускается; kernel не enforce'нет, postinst не тратит впустую                                                                   |
| Astra со strict mode                 | Ставит `iinh` на конфиг/state-директории, поднимает ilevel=63 на конфиг-файлах, печатает напоминание про opt-in drop-in                    |

`mac-integrity.conf.example` и `pam-certauth.example` устанавливаются
**всегда** (~2 KB), активируются только когда оператор сам копирует
их в `/etc/systemd/system/pam-certauth.service.d/` и `/etc/pam.d/`.

## 12. Troubleshooting

См. [troubleshooting.md §5 МКЦ](troubleshooting.md#5-мкц-astra-strict-mode):

- `pam_parsec_mac: Can't obtain required data` (3 причины + фиксы);
- `parsec.mac=0` + `pam_parsec_mac` в стеке;
- `unknown field 'enabled'` (legacy `[mac].enabled` → `[mac].runtime`);
- WARN `mac_caps_missing` / `pdp_set_fd rc=-1`;
- `dmi_board_serial = 0` (VM) и host_id drift.

## 13. См. также

- [install.md](install.md) — установка `pam_certauth`.
- [pam-integration.md](pam-integration.md) — правка `/etc/pam.d/*`.
- [configuration.md §MAC integrity](configuration.md) — справочник полей.
- [cert-issuance.md §MAX_INTEGRITY](cert-issuance.md) — выпуск cert
  с расширением `pam_cert_max_integrity`.
- [threat-model.md §9](threat-model.md) — МКЦ через призму угроз.
