<p align="center">
    <img
      src="../media/fhg.gif"
      alt="FoxHole DB"
      width="180"
      height="180"
    >
</p>

<p align="center">
  <a href="../README.md">
    <img src="https://img.shields.io/badge/🇬🇧-English-ff7a00?style=flat-square">
  </a>
  <a href="README.ru.md">
    <img src="https://img.shields.io/badge/🇷🇺-Русский-ff7a00?style=flat-square">
  </a>
</p>

<p align="center">
  <a href="https://github.com/foxhole-team/foxhole-db/releases">
    <img src="https://img.shields.io/github/v/release/foxhole-team/foxhole-db?label=version&style=flat-square" alt="Version">
  </a>
</p>

# 🗃️ FoxHole DB

![Feeds](https://img.shields.io/badge/data_feeds-5-007ec6?style=flat-square)
![Manifests](https://img.shields.io/badge/manifests-signed-success?style=flat-square)
![Integrity](https://img.shields.io/badge/integrity-SHA--256-555?style=flat-square)
![Delivery](https://img.shields.io/badge/delivery-GitHub_Pages-222?style=flat-square&logo=github)
![❤️ We support I2P](https://img.shields.io/badge/❤️_We_support-I2P-7B1FA2?style=flat-square)

Публичный канал обновлений данных FoxHole Guard содержит пять
подписанных **наборов данных**.

Каждый набор данных использует одну модель доставки:

```text
signed manifest
      ↓
size + SHA-256
      ↓
download to temp
      ↓
verify
      ↓
atomic replace
```

> [!IMPORTANT]
> Приложение не доверяет изменяемым файлам из `raw.githubusercontent.com/main`. Артефакт, не прошедший проверку, никогда не заменяет уже установленный; поведение при первой установке зависит от конкретного набора данных и описано ниже.

---

## 📦 Наборы данных

| Набор данных | Артефакт | Формат | Источник | Лицензия | Версия |
| ------------ | -------- | ------ | -------- | -------- | ------ |
| **DNS** — списки фильтрации | `adguard-dns-filter.fhds` | `foxhole-dns-fst-v1` | [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter) | GPL-3.0 | для каждой сборки фиксируется точный коммит источника; в манифесте растёт `sequence` |
| **TOR** - зеркало встроенных мостов | `bridges.json` | `tor-bridges-json` | [Встроенные мосты Tor Project (Moat)](https://bridges.torproject.org/moat/circumvention/builtin) | публичные данные обхода цензуры | метка `generated_at`; ключи объектов нормализуются, но порядок элементов массивов сохраняется, поэтому одинаковые наборы мостов в разном порядке имеют разные хеши |
| **FoxHole Sentinel** — данные об угрозах | `threat-intel.json` | `sentinel-threat-intel-json`, документ `schema: 3` | [AssoEchap/stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) | CC-BY-4.0 | для каждой сборки фиксируется точный коммит источника в `threat-intel-source-info.json` |
| **Геобаза данных** — IP→страна | `dbip-country-ipv4.csv`, `dbip-country-ipv6.csv` | `dbip-country-csv` | [DB-IP Lite через sapics/ip-location-db](https://github.com/sapics/ip-location-db) (`dbip-country`) | CC-BY-4.0 | версия набора из `package.json` переносится в манифест |
| **TLS-отпечатки** — таблицы ClientHello | `fingerprints.json` | `tls-fingerprint-tables-json` | [`fingerprints/` в FoxHole Core](https://github.com/foxhole-team/foxhole-core) | GPL-3.0-or-later | для каждой публикации фиксируется ревизия источника; для каждого профиля заново вычисляется `fingerprint_sha256` |

В каждом `*-source-info.json` записываются сведения об источнике: ревизия или
URL, дайджест входных данных или версия набора и, где применимо, результаты
преобразования. Полные условия лицензий и обязательные атрибуции — в
[LICENSES.md](../LICENSES.md).

---

## 📁 Публикуемые файлы

**Публикуется** только то, что сборка кладёт в `public/`. Файлы в корне репозитория —
снимки для проверки и могут отставать от сервера. Адрес каждого артефакта
вычисляется относительно URL манифеста, поэтому отсутствующий в `public/` файл
недоступен, даже если его снимок есть в Git.

Релизные подписи создаются только в `public/` из секрета GitHub и до публикации
проверяются через `manifest.public.pem`; приватный ключ и фиктивные подписи в Git не входят.


### ⬇️ Загружаемые файлы

| Файл | Назначение |
| ---- | ---------- |
| `manifest.json` | манифест DNS ruleset |
| `manifest.json.sig` | подпись `manifest.json` |
| `adguard-dns-filter.fhds` | скомпилированный DNS ruleset |
| `adguard-dns-filter.fhds.sha256` | SHA-256 ruleset |
| `source-info.json` | источник и метаданные сборки DNS |
| `threat-intel-manifest.json` | манифест набора данных FoxHole Sentinel |
| `threat-intel-manifest.json.sig` | подпись threat-intel-манифеста |
| `threat-intel.json` | threat-intel bundle |
| `threat-intel.json.sha256` | SHA-256 threat-intel |
| `threat-intel-source-info.json` | источник, лицензия и результаты преобразования |
| `bridges-manifest.json` | манифест мостов TOR |
| `bridges-manifest.json.sig` | подпись bridges-манифеста |
| `bridges.json` | builtin-мосты TOR по транспортам |
| `bridges.json.sha256` | SHA-256 мостов |
| `bridges-source-info.json` | метаданные источника мостов |
| `geoip-manifest.json` | манифест геобазы данных (версия + 2 артефакта) |
| `geoip-manifest.json.sig` | подпись geo-манифеста |
| `dbip-country-ipv4.csv` | диапазоны IPv4 → страна (DB-IP Lite) |
| `dbip-country-ipv4.csv.sha256` | SHA-256 IPv4-диапазонов |
| `dbip-country-ipv6.csv` | диапазоны IPv6 → страна (DB-IP Lite) |
| `dbip-country-ipv6.csv.sha256` | SHA-256 IPv6-диапазонов |
| `geoip-source-info.json` | метаданные источника гео |
| `fingerprint-manifest.json` | манифест таблиц TLS-отпечатков |
| `fingerprint-manifest.json.sig` | подпись манифеста TLS-отпечатков |
| `fingerprints.json` | таблицы ClientHello, по одной записи на профиль |
| `fingerprints.json.sha256` | SHA-256 набора таблиц |
| `fingerprint-source-info.json` | метаданные источника таблиц |

27 файлов: пять манифестов, пять подписей и артефакты с метаданными.

### 🧰 Остаётся в репозитории

| Файл | Назначение |
| ---- | ---------- |
| `manifest.public.pem` | публичный ключ проверки, для человека |
| `adguard-vpn-compatibility-allowlist.txt` | allowlist для control-plane AdGuard |
| `LICENSES.md` | лицензии источников и сгенерированных данных |
| `build-adguard-dns-filter.sh` | сборка набора данных DNS |
| `build-threat-intel.sh` | сборка набора данных threat-intel |
| `build-bridges.sh` | сборка набора данных мостов TOR |
| `build-geoip.sh` | сборка набора данных геобазы |
| `build-fingerprints.sh` | сборка набора таблиц TLS-отпечатков |
| `verify-feeds.sh` | проверка собранного `public/` перед публикацией |


Все манифесты подписываются одним ключом.

---

## 📜 Манифесты

Манифестов пять, по одному на набор данных. Общей схемы или общего набора
полей у них **нет**, общий только ключ подписи.

| Манифест                     | `schema` | `name`                          | `format`                     |
| ---------------------------- | -------- | ------------------------------- | ---------------------------- |
| `manifest.json`              | 2        | `foxhole-adguard-dns-filter`    | `foxhole-dns-fst-v1`         |
| `threat-intel-manifest.json` | 1        | `foxhole-sentinel-threat-intel` | `sentinel-threat-intel-json` |
| `bridges-manifest.json`      | 1        | `foxhole-tor-bridges`           | `tor-bridges-json`           |
| `geoip-manifest.json`        | 1        | `foxhole-geoip`                 | `dbip-country-csv`           |
| `fingerprint-manifest.json`  | 1        | `foxhole-tls-fingerprints`      | `tls-fingerprint-tables-json` |

### 🌐 DNS-манифест

`manifest.json`

```text
schema
name
format
sequence
generated_at_unix
expires_at_unix
key_sha256
source
artifact
compatibility
```



### 📑 Остальные четыре манифеста



```text
schema
name
format
generated_at
source
artifact | artifacts
compatibility.min_app_version
```

- `generated_at` - строка RFC 3339; ни окна годности, ни поля `key_sha256`.
  Ключ вкомпилирован в приложение.
- `geoip-manifest.json` - единственный с **`artifacts`**: массив из двух
  элементов.
- клиент старее `compatibility.min_app_version` отклоняет набор. DNS-манифест
  вместо этого использует `compatibility.core_schema`.

---

## 🧬 DNS-артефакт

`adguard-dns-filter.fhds` использует формат `foxhole-dns-fst-v1`:

- 80-байтовый заголовок;
- magic `FHDNS1\0\0`;
- счётчики block/allow-записей;
- длины block/allow-карт;
- SHA-256 исходного `Filters/filter.txt`;
- зарезервированные байты;
- две FST-карты: block и allow.

FoxHole Core сверяет заголовок, счётчики и дайджест источника с
`manifest.json`.

`.fhds` - **данные**, не исполняемый код.

---

## 🛡️ Данные об угрозах FoxHole Sentinel

Формат:

```json
{
  "schema": 3,
  "packages": ["com.example.some.stalkerware"],
  "certs": [],
  "certsSha1": [],
  "domains": [],
  "ips": []
}
```

Документ использует `schema: 3`. В схеме 1 были только `packages` и `certs`,
`certsSha1` появился в схеме 2, а два сетевых списка — в схеме 3. Приложение
читает диапазон схем `1..4` (`ThreatIntelDocument.SCHEMA` равен `4`), поэтому
этот артефакт остаётся совместимым. Покрывающий его `threat-intel-manifest.json`
— отдельный документ со своей схемой `1` (см. [Манифесты](#-манифесты)).

Правила полей:

| Поле        | Содержимое                                                            |
| ----------- | --------------------------------------------------------------------- |
| `packages`  | нижний регистр, без пробелов по краям и дублей, отсортированы; сравниваются с идентификаторами пакетов Android |
| `certs`     | SHA-256 DER-сертификата подписи: 64 шестнадцатеричных символа в нижнем регистре |
| `certsSha1` | SHA-1 DER-сертификата подписи: 40 шестнадцатеричных символов в нижнем регистре |
| `domains`   | нижний регистр, без дублей, отсортированы; сайты продуктов и C2-хосты источника |
| `ips`       | нижний регистр, без дублей, отсортированы; C2-адреса                  |

SHA-1-отпечатки лежат в своём поле, а не подмешаны в `certs`: механизм, не
отличающий два дайджеста, можно обмануть более слабым. Сетевые индикаторы
сравниваются локально; сборщик не разрешает их через DNS и не обращается к ним.
Встроенный начальный набор приложения объединяется с проверенным удалённым.

Зеркалируются идентификаторы пакетов Android, SHA-256- и SHA-1-отпечатки
сертификатов, сайты продуктов, C2-домены и C2-адреса источника. Не
зеркалируются отдельное поле `distribution`, YARA-правила, SHA-256 APK,
идентификаторы пакетов iOS и шаблоны полей X.509.

Правила конверсии:

| Вход                                    | Обработка               |
| --------------------------------------- | ----------------------- |
| отсутствует идентификатор пакета        | пропуск                 |
| SHA-1-отпечатки сертификатов источника  | `certsSha1`             |
| неверный идентификатор пакета Android   | пропуск                 |
| `certificate_cname_re`                  | пропуск                 |
| `certificate_organizations`             | пропуск                 |
| `ios_bundles`                           | пропуск                 |
| `distribution`                          | пропуск                 |
| `com.example.*`                         | включён по умолчанию; для исключения задайте `INCLUDE_EXAMPLE_PREFIX=false` |
| `watchware.yaml`                        | исключён по умолчанию   |

`INCLUDE_WATCHWARE=true` добавляет отдельный список watchware, а
`INCLUDE_EXAMPLE_PREFIX=false` исключает индикаторы `com.example.*`. Счётчики
конверсии и примеры отклонённых значений записываются в
`threat-intel-source-info.json`.

`KNOWN_THREAT` - локальный сигнал FoxHole Sentinel; абсолютная точность не
гарантируется.

---

## 🔏 Таблицы TLS-отпечатков

`fingerprints.json` зеркалирует таблицы ClientHello из каталога `fingerprints/`
[FoxHole Core](https://github.com/foxhole-team/foxhole-core): одна запись на
профиль, записи отсортированы по `name`.

Через набор данных передаются только таблицы. Логика генератора ClientHello
остаётся скомпилированной в FoxHole Core: набор задаёт значения только для уже
поддерживаемых полей и не может добавить исполняемый код или новый путь
генератора.

Каждый профиль содержит `fingerprint_sha256` — SHA-256 объекта `fingerprint`,
сериализованного с отсортированными ключами, без пробелов и только в ASCII.
`build-fingerprints.sh` и `verify-feeds.sh` независимо пересчитывают этот
дайджест, поэтому публикация с устаревшим или несогласованным внутренним хешем
отклоняется.

FoxHole Core хранит источник отдельно для каждого профиля и через
`scripts/fingerprint-from-utls.py` сравнивает его с
[refraction-networking/utls](https://github.com/refraction-networking/utls),
если соответствующая таблица есть в uTLS.

---

## ✅ Порядок проверки

```text
download manifest
      ↓
verify manifest signature
      ↓
check identity / compatibility / rollback
      ↓
download referenced artifact
      ↓
verify size
      ↓
verify SHA-256
      ↓
parse artifact
      ↓
atomic replace
```

При любой ошибке уже установленный артефакт сохраняется. Если его ещё нет,
компонент использует предусмотренный именно для него вариант:

```text
встроенный начальный набор или таблицы
      или
работа без загруженных данных
```

---

## 🌍 Официальные адреса

```text
https://foxhole-team.github.io/foxhole-db/manifest.json
https://foxhole-team.github.io/foxhole-db/bridges-manifest.json
https://foxhole-team.github.io/foxhole-db/threat-intel-manifest.json
https://foxhole-team.github.io/foxhole-db/geoip-manifest.json
https://foxhole-team.github.io/foxhole-db/fingerprint-manifest.json
```

Репозиторий:

```text
https://github.com/foxhole-team/foxhole-db
```

Адреса артефактов и подписей вычисляются относительно URL манифеста.

---

## ⚙️ Модель сборки

Один workflow GitHub Actions запускается при отправке изменений, для запросов на
слияние, вручную и раз в трое суток. Все пять наборов собираются вместе, а из
`main` публикуются одним неделимым комплектом.

Общие шаги:

1. проверка shell-скриптов, публичного дерева, закоммиченных данных и отсутствия
   секретов;
2. извлечение этого репозитория и публичного FoxHole Core на неизменяемой
   ревизии, указанной в workflow;
3. сборка `foxcore-dns-compile`;
4. однократный запуск `build-all-feeds.sh` без проверки подписей: точный состав
   файлов, поля манифестов, размеры, хеши и внутренние дайджесты TLS-профилей
   проверяются уже на этом этапе;
5. сравнение нормализованных манифестов с текущей публикацией Pages; если данные
   не изменились, публикация не запускается;
6. для изменившегося кандидата из `main` — проверка соответствия
   `FOXHOLE_DNS_SIGNING_KEY_PEM` ключу `manifest.public.pem`, подпись всех пяти
   манифестов и повторный запуск `verify-feeds.sh` уже с проверкой подписей;
7. загрузка одного и того же проверенного каталога в GitHub Pages и релиз
   `data-feeds-*`;
8. сохранение трёх последних релизов наборов данных и текущей публикации Pages.

Проверку неподписанного кандидата можно запустить локально без секретов:

```bash
FOXHOLE_VERIFY_SIGNATURES=false ./verify-feeds.sh /path/to/unsigned-candidate
```


Внутри шага DNS:

1. клонирование `AdguardTeam/AdGuardSDNSFilter`;
2. фиксация точного коммита источника;
3. сборка или использование готового `Filters/filter.txt`;
4. компиляция `.fhds`;
5. подсчёт SHA-256 / размера / счётчиков;
6. запись манифеста + метаданных источника.


---

## 🔏 Подпись

Секрет репозитория:

```text
FOXHOLE_DNS_SIGNING_KEY_PEM
```

Сгенерировать ключ P-256:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out manifest.private.pem
openssl ec -in manifest.private.pem -pubout -out manifest.public.pem
```

Подписать манифесты (один ключ подписывает все пять):

```sh
for m in manifest threat-intel-manifest bridges-manifest geoip-manifest fingerprint-manifest; do
  openssl dgst -sha256 \
    -sign manifest.private.pem \
    -out "$m.json.sig" \
    "$m.json"
done
```

Проверить перед публикацией:

```sh
openssl dgst -sha256 \
  -verify manifest.public.pem \
  -signature manifest.json.sig \
  manifest.json
```

> [!WARNING]
> `build-adguard-dns-filter.sh` отклоняет неверный ключ до подписи. Остальные сборщики полагаются на обязательную итоговую проверку `verify-feeds.sh`, которая не пропустит набор с неверным ключом.

---

## 🛠️ Локальная сборка

```sh
FOXHOLE_DB_OUT="$(mktemp -d)"
FOXHOLE_DNS_REQUIRE_SIGNATURE=false FOXCORE_ROOT=/path/to/foxhole-core \
  OUT_DIR="$FOXHOLE_DB_OUT" ./build-all-feeds.sh # полная неподписанная сборка и проверка

./verify-feeds.sh /path/to/signed-public          # полная проверка подписанной публикации
```

`build-all-feeds.sh` сам выбирает режим проверки: без подписей при
`FOXHOLE_DNS_REQUIRE_SIGNATURE=false`, с подписями — во всех остальных случаях.
Прямой вызов `verify-feeds.sh <dir>` по умолчанию проверяет подписи через
закоммиченный `manifest.public.pem`; `FOXHOLE_VERIFY_SIGNATURES=false` допустим
только для неподписанного кандидата. Для тестового ключа задаётся
`FOXHOLE_DNS_PUBLIC_KEY`.

Параметры:

```sh
# явный путь к FoxHole Core (DNS)
FOXCORE_ROOT=/path/to/foxhole-core ./build-adguard-dns-filter.sh

# явный путь к FoxHole Core (таблицы TLS-отпечатков)
FOXCORE_ROOT=/path/to/foxhole-core ./build-fingerprints.sh

# готовый фильтр AdGuard (DNS)
ADGUARD_SOURCE_REF=gh-pages ./build-adguard-dns-filter.sh

# точный коммит источника (данные об угрозах)
THREAT_INTEL_SOURCE_REF=<commit> ./build-threat-intel.sh

# неподписанная пробная сборка (любой набор данных)
FOXHOLE_DNS_REQUIRE_SIGNATURE=false ./build-adguard-dns-filter.sh
```

Все пять скриптов принимают `OUT_DIR` (по умолчанию - корень репозитория) и
один и тот же ключ подписи из `FOXHOLE_DNS_SIGNING_KEY_PEM` или
`FOXHOLE_DNS_SIGNING_KEY`, и все пять поддерживают
`FOXHOLE_DNS_REQUIRE_SIGNATURE=false` для пробной сборки. Переменная названа по
набору данных DNS только потому, что он был первым.

Неподписанный результат **не предназначен для публикации**.

---

## 🏪 Заметки для проверки магазинами приложений

Для F-Droid / Google Play:

- DNS `.fhds` и базы GeoIP доступны только после загрузки; контрактные тесты
  клиента не дают снова встроить эти наборы в APK;
- для мостов TOR, FoxHole Sentinel и TLS-отпечатков в приложении есть базовые
  встроенные наборы; неудачное обновление сохраняет их или последнюю проверенную
  загрузку;
- загрузка обновлений требует согласия пользователя;
- URL источника настраивается;
- скачиваемые артефакты — данные, не код;
- манифесты подписаны;
- размер и SHA-256 проверяются;
- неудачное обновление не ломает работу VPN;
- сканирование FoxHole Sentinel выполняется локально;
- имена пакетов, результаты сканирования и вердикты не отправляются;
- журналы DNS, история браузинга, статистика фильтрации и список
  установленных приложений в этот репозиторий не отправляются.

---

## ❤️ Поддержать

**XMR (Monero):**

```text
48yBVPTdcyJ1WoJtnKmVpEZziEsDy4HvbCW7eQDS9mfdiWPFXwZ8F5h9YZ2UTTBLxPcJgQgvth7iqLZM2yMCaQ432qaouqr
```

**BTC (Bitcoin):**

```text
bc1qatnyy7jcpqrp0d3dk9rta9vqfejgh4mysd6m2f
```

**ETH (Ethereum):**

```text
0xDEBA357Cc8f5E865ea7FFa98E138C8241A16A465
```

---

## ⚠️ Дисклеймер

> [!WARNING]
> Tor является товарным знаком The Tor Project. FoxHole DB не является продуктом The Tor Project, не одобрен, не спонсируется и не аффилирован с The Tor Project.
>
> FoxHole DB не является продуктом AdGuard и не аффилирован с AdGuard Software Ltd.
>
> Данные IP-геолокации предоставлены DB-IP (`https://db-ip.com`) по CC-BY-4.0; этот репозиторий не аффилирован с DB-IP.

---

## 📄 Лицензия

Код и метаданные репозитория распространяются по [GNU General Public License
версии 3 или новее](../LICENSE). Лицензии источников и сгенерированных данных,
включая обязательные атрибуции, документированы в
[LICENSES.md](../LICENSES.md).

## 🔗 Связанные проекты

[![FoxHole Guard](https://img.shields.io/badge/GitHub-FoxHole_Guard-181717?logo=github&style=flat-square)](https://github.com/foxhole-team/foxhole-guard)
[![Version](https://img.shields.io/github/v/release/foxhole-team/foxhole-guard?label=version&style=flat-square)](https://github.com/foxhole-team/foxhole-guard/releases)

[![FoxHole Core](https://img.shields.io/badge/GitHub-FoxHole_Core-181717?logo=github&style=flat-square)](https://github.com/foxhole-team/foxhole-core)
[![Version](https://img.shields.io/github/v/release/foxhole-team/foxhole-core?label=version&style=flat-square)](https://github.com/foxhole-team/foxhole-core/releases)
