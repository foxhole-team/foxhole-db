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

![Feeds](https://img.shields.io/badge/data_feeds-4-007ec6?style=flat-square)
![Manifests](https://img.shields.io/badge/manifests-signed-success?style=flat-square)
![Integrity](https://img.shields.io/badge/integrity-SHA--256-555?style=flat-square)
![Delivery](https://img.shields.io/badge/delivery-GitHub_Pages-222?style=flat-square&logo=github)
![❤️ We support I2P](https://img.shields.io/badge/❤️_We_support-I2P-7B1FA2?style=flat-square)

Публичный канал обновлений данных FoxHole Guard содержит четыре
подписанных **набора данных**.

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
> Приложение не доверяет изменяемым файлам из `raw.githubusercontent.com/main`. Если проверка не проходит, используется последний успешно проверенный локальный артефакт.

---

## 📦 Наборы данных

| Набор данных | Артефакт | Формат | Источник | Лицензия | Версия |
| ------------ | -------- | ------ | -------- | -------- | ------ |
| **DNS** - листы фильтрации | `adguard-dns-filter.fhds` | `foxhole-dns-fst-v1` | [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter) | GPL-3.0 | коммит upstream пинится на каждую сборку; монотонный `sequence` в манифесте |
| **TOR** - зеркало builtin-мостов | `bridges.json` | `tor-bridges-json` | [Builtin-мосты Tor Project (Moat)](https://bridges.torproject.org/moat/circumvention/builtin) | публичные данные обхода цензуры | метка `generated_at`; артефакт байтово воспроизводим из неизменённого upstream |
| **FoxHole Sentinel** - списки безопасности (threat intel) | `threat-intel.json` | `sentinel-threat-intel-json`, документ `schema: 3` | [AssoEchap/stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) | CC-BY-4.0 | коммит upstream пинится на каждую сборку; фиксируется в `threat-intel-source-info.json` |
| **геобаза данных** - IP→страна | `dbip-country-ipv4.csv`, `dbip-country-ipv6.csv` | `dbip-country-csv` | [DB-IP Lite через sapics/ip-location-db](https://github.com/sapics/ip-location-db) (`dbip-country`) | CC-BY-4.0 | upstream-`version` из `package.json` датасета, переносится в манифест |

Провенанс каждой сборки - точный коммит, дайджест входа, учёт пропусков -
записывается в файл `*-source-info.json` рядом с каждым артефактом. Полные
условия лицензий и обязательные атрибуции - в [LICENSES.md](../LICENSES.md).

---

## 📁 Публикуемые файлы

**Публикуется** только то, что сборка кладёт в `public/`. Файлы в корне репозитория —
снимки для ревью и могут отставать от endpoint. Приложение резолвит каждый артефакт
относительно URL манифеста, поэтому отсутствующий в `public/` файл недоступен, даже если
его снимок закоммичен.

Релизные подписи создаются только в `public/` из секрета GitHub и до публикации
проверяются через `manifest.public.pem`; приватный ключ и фиктивные подписи в Git не входят.


### ⬇️ Загружаемые файлы

| Файл | Назначение |
| ---- | ---------- |
| `manifest.json` | манифест DNS ruleset |
| `manifest.json.sig` | подпись `manifest.json` |
| `adguard-dns-filter.fhds` | скомпилированный DNS ruleset |
| `adguard-dns-filter.fhds.sha256` | SHA-256 ruleset |
| `source-info.json` | upstream + метаданные сборки DNS |
| `threat-intel-manifest.json` | манифест набора данных FoxHole Sentinel |
| `threat-intel-manifest.json.sig` | подпись threat-intel-манифеста |
| `threat-intel.json` | threat-intel bundle |
| `threat-intel.json.sha256` | SHA-256 threat-intel |
| `threat-intel-source-info.json` | upstream, лицензия, учёт конверсии/пропусков |
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

22 файла: четыре манифеста, четыре подписи и артефакты с метаданными.

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
| `verify-feeds.sh` | проверка собранного `public/` перед публикацией |


Все манифесты подписываются одним ключом.

---

## 📜 Манифесты

Манифестов четыре, по одному на набор данных. Общей схемы или общего набора
полей у них **нет**, общий только ключ подписи.

| Манифест                     | `schema` | `name`                          | `format`                     |
| ---------------------------- | -------- | ------------------------------- | ---------------------------- |
| `manifest.json`              | 2        | `foxhole-adguard-dns-filter`    | `foxhole-dns-fst-v1`         |
| `threat-intel-manifest.json` | 1        | `foxhole-sentinel-threat-intel` | `sentinel-threat-intel-json` |
| `bridges-manifest.json`      | 1        | `foxhole-tor-bridges`           | `tor-bridges-json`           |
| `geoip-manifest.json`        | 1        | `foxhole-geoip`                 | `dbip-country-csv`           |

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



### 📑 Остальные три манифеста



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
- `compatibility.min_app_version` отказывает фиду приложению старше той
  сборки, под которую фид сделан. DNS-манифест вместо этого использует
  `compatibility.core_schema`.

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

## 🛡️ Threat intelligence FoxHole Sentinel

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

Документ - `schema: 3`. В схеме 1 были только `packages` и `certs`;
`certsSha1` появился со схемой 2, два сетевых списка - со схемой 3. Приложение
пинит это число точно (`ThreatIntelDocument.SCHEMA`) и отвергает любое другое,
так что артефакт и приложение движутся вместе. Манифест, покрывающий этот
артефакт, - отдельный документ со своим номером: `threat-intel-manifest.json`
это `schema: 1` (см. [Манифесты](#манифесты)).

Правила полей:

| Поле        | Содержимое                                                            |
| ----------- | --------------------------------------------------------------------- |
| `packages`  | lower-case, trimmed, без дублей, отсортированы; сравниваются с Android package id |
| `certs`     | lower-case hex SHA-256 (64 символа) DER-сертификата подписи           |
| `certsSha1` | lower-case hex SHA-1 (40 символов) DER-сертификата подписи            |
| `domains`   | lower-case, без дублей, отсортированы; C2 и хосты раздачи             |
| `ips`       | lower-case, без дублей, отсортированы; C2 и адреса раздачи            |

SHA-1-отпечатки лежат в своём поле, а не подмешаны в `certs`: матчер, не
отличающий два дайджеста, можно обмануть более слабым. Сетевые индикаторы
сравниваются локально; сборщик фида их не резолвит и никуда не ходит. Вшитый
seed в приложении объединяется с проверенным удалённым фидом через union.

Зеркалируется из upstream: Android package id, SHA-256- и SHA-1-отпечатки
сертификатов, C2-домены и домены раздачи, C2-адреса и адреса раздачи. Не
зеркалируются: сайты вендоров, YARA-правила, APK SHA-256, iOS bundles,
X.509 subject matchers.

Правила конверсии:

| Вход                                    | Обработка               |
| --------------------------------------- | ----------------------- |
| отсутствует package id                  | пропуск                 |
| SHA-1-отпечатки сертификатов upstream   | `certsSha1`             |
| невалидный Android package id           | пропуск                 |
| `certificate_cname_re`                  | пропуск                 |
| `certificate_organizations`             | пропуск                 |
| `ios_bundles`                           | пропуск                 |
| `com.example.*`                         | исключён по умолчанию   |
| `watchware.yaml`                        | исключён по умолчанию   |

Переопределения: `INCLUDE_WATCHWARE=true`, `INCLUDE_EXAMPLE_PREFIX=true`. Все
результаты пропусков/подсчётов записываются в
`threat-intel-source-info.json`.

`KNOWN_THREAT` - локальный сигнал FoxHole Sentinel; абсолютная точность не
гарантируется.

---

## ✅ Порядок проверки

```text
download manifest
      ↓
verify manifest signature
      ↓
check key_sha256 / sequence / expiry
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

При любой ошибке:

```text
bundled fallback
      или
последний проверенный локальный артефакт
```

---

## 🌍 Официальные endpoints

```text
https://foxhole-team.github.io/foxhole-db/manifest.json
https://foxhole-team.github.io/foxhole-db/bridges-manifest.json
https://foxhole-team.github.io/foxhole-db/threat-intel-manifest.json
https://foxhole-team.github.io/foxhole-db/geoip-manifest.json
```

Репозиторий:

```text
https://github.com/foxhole-team/foxhole-db
```

Артефакты и подписи резолвятся относительно URL манифеста.

---

## ⚙️ Модель сборки

Один scheduled-workflow GitHub Actions собирает все четыре набора данных одним
job'ом раз в трое суток и публикует их вместе. Расписания по наборам данных
нет: четыре набора данных выкладываются разом и разъехаться на сервере не
могут.

Общие шаги:

1. гейты shell, публичного дерева, закоммиченных данных и секретов без доступа к
   секретам;
2. checkout этого репозитория;
3. checkout приватного FoxHole Core через read-only deploy key из секрета
   `FOXCORE_READ_SSH_KEY`;
4. сборка `foxcore-dns-compile`;
5. запуск `build-all-feeds.sh`, который складывает все четыре набора в один каталог;
6. подпись каждого манифеста одним ключом: временным в проверочном job и
   `FOXHOLE_DNS_SIGNING_KEY_PEM` только при публикации из `main`;
7. `verify-feeds.sh` - все четыре манифеста на месте, подписи сходятся с выбранным
   публичным ключом, каждый артефакт совпадает с объявленными размером и SHA-256.
   Пока это не пройдёт, не публикуется ничего;
8. загрузка результата как артефакта workflow;
9. деплой на GitHub Pages;
10. все опубликованные файлы прикладываются к новому релизу `data-feeds-*`.

Шаг 7 запускается на локальной сборке и без единого секрета:

```bash
./verify-feeds.sh public
```


Внутри DNS-шага:

1. clone `AdguardTeam/AdGuardSDNSFilter`;
2. пин коммита upstream;
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

Подписать манифесты (один ключ подписывает все четыре):

```sh
for m in manifest threat-intel-manifest bridges-manifest geoip-manifest; do
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
> `build-adguard-dns-filter.sh` отклоняет неверный ключ до подписи. Остальные сборщики полагаются на обязательный финальный гейт `verify-feeds.sh`, который не пропустит к публикации весь набор с неверным ключом.

---

## 🛠️ Локальная сборка

```sh
OUT_DIR=public ./build-all-feeds.sh             # полная сборка и проверка
OUT_DIR=public ./build-adguard-dns-filter.sh   # DNS
OUT_DIR=public ./build-threat-intel.sh         # threat intel FoxHole Sentinel
OUT_DIR=public ./build-bridges.sh              # мосты TOR
OUT_DIR=public ./build-geoip.sh                # геобаза данных
./verify-feeds.sh public                       # то же, что проверяет CI перед публикацией
```

`verify-feeds.sh` - тот же гейт, что стоит в workflow, и секретов ему не нужно:
подпись он проверяет закоммиченным `manifest.public.pem`, то есть тем ключом,
который есть у самого приложения, а каждый артефакт - против размера и SHA-256 из
его манифеста. Каталог задаётся аргументом (`./verify-feeds.sh <dir>`), а для
сборки, подписанной тестовым ключом, переопределяется `FOXHOLE_DNS_PUBLIC_KEY`.

Опции:

```sh
# явный путь к FoxHole Core (DNS)
FOXCORE_ROOT=/path/to/foxhole-core ./build-adguard-dns-filter.sh

# готовый фильтр AdGuard (DNS)
ADGUARD_SOURCE_REF=gh-pages ./build-adguard-dns-filter.sh

# пин коммита upstream (threat intel)
THREAT_INTEL_SOURCE_REF=<commit> ./build-threat-intel.sh

# неподписанная smoke-сборка (любой набор данных)
FOXHOLE_DNS_REQUIRE_SIGNATURE=false ./build-adguard-dns-filter.sh
```

Все четыре скрипта принимают `OUT_DIR` (по умолчанию - корень репозитория) и
один и тот же ключ подписи из `FOXHOLE_DNS_SIGNING_KEY_PEM` или
`FOXHOLE_DNS_SIGNING_KEY`, и все четыре понимают
`FOXHOLE_DNS_REQUIRE_SIGNATURE=false` для smoke-сборки. Переменная названа по
набору данных DNS только потому, что он был первым.

Неподписанный вывод **не предназначен для публикации**.

---

## 🏪 Заметки для ревью сторов

Для F-Droid / Google Play:

- у приложения есть вшитый fallback;
- обновления opt-in;
- URL источника настраивается;
- скачиваемые артефакты - данные, не код;
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
