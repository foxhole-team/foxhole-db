<p align="center">
    <img
      src="media/fhg.gif"
      alt="FoxHole DB"
      width="180"
      height="180"
    >
</p>

<p align="center">
  <a href="README.md">
    <img src="https://img.shields.io/badge/🇬🇧-English-ff7a00?style=flat-square">
  </a>
  <a href="docs/README.ru.md">
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

FoxHole DB is the public data update channel for FoxHole Guard. It contains five signed **data feeds**.

Each data feed uses the same delivery model:

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
> The application does not trust mutable files served from `raw.githubusercontent.com/main`. If verification fails, the last successfully verified local artifact is used.

---

## 📦 Data feeds

| Data feed | Artifact | Format | Source | License | Version |
| --- | --- | --- | --- | --- | --- |
| **DNS** - filter lists | `adguard-dns-filter.fhds` | `foxhole-dns-fst-v1` | [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter) | GPL-3.0 | upstream commit is pinned for every build; monotonic `sequence` in the manifest |
| **TOR** - builtin bridge mirror | `bridges.json` | `tor-bridges-json` | [Tor Project builtin bridges (Moat)](https://bridges.torproject.org/moat/circumvention/builtin) | public censorship-circumvention data | `generated_at` timestamp; artifact is byte-for-byte reproducible from unchanged upstream |
| **FoxHole Sentinel** - security lists (threat intelligence) | `threat-intel.json` | `sentinel-threat-intel-json`, document `schema: 3` | [AssoEchap/stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) | CC-BY-4.0 | upstream commit is pinned for every build; recorded in `threat-intel-source-info.json` |
| **Geo database** - IP → country | `dbip-country-ipv4.csv`, `dbip-country-ipv6.csv` | `dbip-country-csv` | [DB-IP Lite via sapics/ip-location-db](https://github.com/sapics/ip-location-db) (`dbip-country`) | CC-BY-4.0 | upstream dataset `version` from `package.json` is propagated into the manifest |
| **TLS fingerprints** - ClientHello tables | `fingerprints.json` | `tls-fingerprint-tables-json` | [FoxHole Core `fingerprints/`](https://github.com/foxhole-team/foxhole-core) | GPL-3.0 | upstream revision is pinned for every build; each profile re-derives its own `fingerprint_sha256` |

The provenance of every build - exact commit, input digest, and skipped-entry accounting - is recorded in a `*-source-info.json` file next to each artifact. Full license terms and required attributions are documented in [LICENSES.md](LICENSES.md).

---

## 📁 Published files

Only files placed by the build into `public/` are **published**. The committed root files are review snapshots and may lag behind the endpoint. The application resolves each artifact relative to its manifest URL, so a file missing from `public/` is unavailable even if a snapshot exists in Git.

Release signatures are generated only in `public/` from the GitHub signing secret and verified against `manifest.public.pem` before publication; no private key or fake signature is committed.

### ⬇️ Downloadable files

| File | Purpose |
| --- | --- |
| `manifest.json` | DNS ruleset manifest |
| `manifest.json.sig` | signature for `manifest.json` |
| `adguard-dns-filter.fhds` | compiled DNS ruleset |
| `adguard-dns-filter.fhds.sha256` | ruleset SHA-256 |
| `source-info.json` | DNS upstream + build metadata |
| `threat-intel-manifest.json` | FoxHole Sentinel data feed manifest |
| `threat-intel-manifest.json.sig` | threat-intel manifest signature |
| `threat-intel.json` | threat-intel bundle |
| `threat-intel.json.sha256` | threat-intel SHA-256 |
| `threat-intel-source-info.json` | upstream, license, conversion/skipped-entry accounting |
| `bridges-manifest.json` | TOR bridges manifest |
| `bridges-manifest.json.sig` | bridges manifest signature |
| `bridges.json` | TOR builtin bridges grouped by transport |
| `bridges.json.sha256` | bridges SHA-256 |
| `bridges-source-info.json` | bridge source metadata |
| `geoip-manifest.json` | geo database manifest (version + 2 artifacts) |
| `geoip-manifest.json.sig` | geo manifest signature |
| `dbip-country-ipv4.csv` | IPv4 ranges → country (DB-IP Lite) |
| `dbip-country-ipv4.csv.sha256` | IPv4 range SHA-256 |
| `dbip-country-ipv6.csv` | IPv6 ranges → country (DB-IP Lite) |
| `dbip-country-ipv6.csv.sha256` | IPv6 range SHA-256 |
| `geoip-source-info.json` | geo source metadata |
| `fingerprint-manifest.json` | TLS fingerprint table manifest |
| `fingerprint-manifest.json.sig` | fingerprint manifest signature |
| `fingerprints.json` | ClientHello tables, one entry per profile |
| `fingerprints.json.sha256` | fingerprint bundle SHA-256 |
| `fingerprint-source-info.json` | fingerprint source metadata |

27 files: five manifests, five signatures, plus artifacts and metadata.

### 🧰 Kept in the repository

| File | Purpose |
| --- | --- |
| `manifest.public.pem` | public verification key for human inspection |
| `adguard-vpn-compatibility-allowlist.txt` | allowlist for the AdGuard control plane |
| `LICENSES.md` | licenses for sources and generated data |
| `build-adguard-dns-filter.sh` | builds the DNS data feed |
| `build-threat-intel.sh` | builds the threat-intel data feed |
| `build-bridges.sh` | builds the TOR bridge data feed |
| `build-geoip.sh` | builds the geo database feed |
| `build-fingerprints.sh` | builds the TLS fingerprint table feed |
| `verify-feeds.sh` | verifies the generated `public/` directory before publication |

All manifests are signed with the same key.

---

## 📜 Manifests

There are five manifests, one per data feed. They **do not** share one common schema or one common field set; only the signing key is shared.

| Manifest | `schema` | `name` | `format` |
| --- | --- | --- | --- |
| `manifest.json` | 2 | `foxhole-adguard-dns-filter` | `foxhole-dns-fst-v1` |
| `threat-intel-manifest.json` | 1 | `foxhole-sentinel-threat-intel` | `sentinel-threat-intel-json` |
| `bridges-manifest.json` | 1 | `foxhole-tor-bridges` | `tor-bridges-json` |
| `geoip-manifest.json` | 1 | `foxhole-geoip` | `dbip-country-csv` |
| `fingerprint-manifest.json` | 1 | `foxhole-tls-fingerprints` | `tls-fingerprint-tables-json` |

### 🌐 DNS manifest

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

### 📑 The other four manifests

```text
schema
name
format
generated_at
source
artifact | artifacts
compatibility.min_app_version
```

- `generated_at` is an RFC 3339 string; there is no validity window and no `key_sha256` field. The key is compiled into the application.
- `geoip-manifest.json` is the only manifest with **`artifacts`**: an array containing two elements.
- `compatibility.min_app_version` rejects the feed for an application older than the build the feed was produced for. The DNS manifest uses `compatibility.core_schema` instead.

---

## 🧬 DNS artifact

`adguard-dns-filter.fhds` uses the `foxhole-dns-fst-v1` format:

- 80-byte header;
- magic `FHDNS1\0\0`;
- block/allow record counters;
- block/allow map lengths;
- SHA-256 of the source `Filters/filter.txt`;
- reserved bytes;
- two FST maps: block and allow.

FoxHole Core compares the header, counters, and source digest against `manifest.json`.

`.fhds` contains **data**, not executable code.

---

## 🛡️ FoxHole Sentinel threat intelligence

Format:

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

The document is `schema: 3`. Schema 1 contained only `packages` and `certs`; `certsSha1` was added in schema 2, and the two network lists were added in schema 3. The application pins this value exactly (`ThreatIntelDocument.SCHEMA`) and rejects any other value, so the artifact and the application move forward together. The manifest covering this artifact is a separate document with its own schema number: `threat-intel-manifest.json` is `schema: 1` (see [Manifests](#-manifests)).

Field rules:

| Field | Contents |
| --- | --- |
| `packages` | lower-case, trimmed, deduplicated, sorted; compared with Android package IDs |
| `certs` | lower-case hexadecimal SHA-256 (64 characters) of the signing DER certificate |
| `certsSha1` | lower-case hexadecimal SHA-1 (40 characters) of the signing DER certificate |
| `domains` | lower-case, deduplicated, sorted; C2 and distribution hosts |
| `ips` | lower-case, deduplicated, sorted; C2 and distribution addresses |

SHA-1 fingerprints are stored in their own field rather than mixed into `certs`: a matcher that does not distinguish the two digests can be misled by the weaker digest. Network indicators are compared locally; the feed builder does not resolve them and does not contact them. The built-in seed in the application is unioned with the verified remote feed.

Mirrored from upstream: Android package IDs, SHA-256 and SHA-1 certificate fingerprints, C2 domains and distribution domains, C2 addresses and distribution addresses. Not mirrored: vendor websites, YARA rules, APK SHA-256 values, iOS bundles, X.509 subject matchers.

Conversion rules:

| Input | Handling |
| --- | --- |
| package ID missing | skip |
| upstream SHA-1 certificate fingerprints | `certsSha1` |
| invalid Android package ID | skip |
| `certificate_cname_re` | skip |
| `certificate_organizations` | skip |
| `ios_bundles` | skip |
| `com.example.*` | excluded by default |
| `watchware.yaml` | excluded by default |

Overrides: `INCLUDE_WATCHWARE=true`, `INCLUDE_EXAMPLE_PREFIX=true`. All skipped-entry and count results are written to `threat-intel-source-info.json`.

`KNOWN_THREAT` is a local FoxHole Sentinel signal; absolute accuracy is not guaranteed.

---

## 🔏 TLS fingerprint tables

`fingerprints.json` mirrors the ClientHello tables committed in [FoxHole Core](https://github.com/foxhole-team/foxhole-core) under `fingerprints/`, one entry per browser profile, sorted by `name`.

Only tables travel. The ClientHello generator is compiled into the application, so this feed changes which values a parrot chooses from a fixed set of fields and can never introduce behaviour.

Every profile carries the upstream `fingerprint_sha256` - SHA-256 over its `fingerprint` object serialised with sorted keys, no whitespace and ASCII-only content. `build-fingerprints.sh` re-derives it before signing and `verify-feeds.sh` re-derives it again before publication, so a rewritten table is refused even when the manifest and its signature are internally consistent.

The tables themselves are checked against [refraction-networking/utls](https://github.com/refraction-networking/utls) upstream, by FoxHole Core's `scripts/fingerprint-from-utls.py`.

---

## ✅ Verification order

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

On any error:

```text
bundled fallback
      or
last verified local artifact
```

---

## 🌍 Official endpoints

```text
https://foxhole-team.github.io/foxhole-db/manifest.json
https://foxhole-team.github.io/foxhole-db/bridges-manifest.json
https://foxhole-team.github.io/foxhole-db/threat-intel-manifest.json
https://foxhole-team.github.io/foxhole-db/geoip-manifest.json
https://foxhole-team.github.io/foxhole-db/fingerprint-manifest.json
```

Repository:

```text
https://github.com/foxhole-team/foxhole-db
```

Artifacts and signatures are resolved relative to the manifest URL.

---

## ⚙️ Build model

A single scheduled GitHub Actions workflow builds all five data feeds in one job every three days and publishes them together. There is no per-feed schedule: all five data feeds are published as one set and cannot drift apart on the server.

Common steps:

1. run shell, public-tree, committed-data and secret-scan gates without secrets;
2. check out this repository;
3. check out the public FoxHole Core anonymously at the full revision pinned in the workflow;
4. build `foxcore-dns-compile`;
5. run `build-all-feeds.sh`, which builds all five feeds into one output directory;
6. sign every manifest with the same key (an ephemeral key in verification; `FOXHOLE_DNS_SIGNING_KEY_PEM` only on `main` publication);
7. run `verify-feeds.sh` - all five manifests must exist, signatures must verify against the selected public key, and every artifact must match its declared size and SHA-256. Nothing is published until this passes;
8. upload the output as a workflow artifact;
9. deploy it to GitHub Pages;
10. attach every published file to a new `data-feeds-*` release.

Step 7 can be run against a local build without any secrets:

```bash
./verify-feeds.sh public
```

Inside the DNS step:

1. clone `AdguardTeam/AdGuardSDNSFilter`;
2. pin the upstream commit;
3. build or use the existing `Filters/filter.txt`;
4. compile `.fhds`;
5. calculate SHA-256 / size / counters;
6. write the manifest + source metadata.

---

## 🔏 Signing

Repository secret:

```text
FOXHOLE_DNS_SIGNING_KEY_PEM
```

Generate a P-256 key:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out manifest.private.pem
openssl ec -in manifest.private.pem -pubout -out manifest.public.pem
```

Sign the manifests - one key signs all five:

```sh
for m in manifest threat-intel-manifest bridges-manifest geoip-manifest fingerprint-manifest; do
  openssl dgst -sha256 \
    -sign manifest.private.pem \
    -out "$m.json.sig" \
    "$m.json"
done
```

Verify before publication:

```sh
openssl dgst -sha256 \
  -verify manifest.public.pem \
  -signature manifest.json.sig \
  manifest.json
```

> [!WARNING]
> `build-adguard-dns-filter.sh` rejects a key mismatch before signing. The other builders rely on the mandatory final `verify-feeds.sh` gate, which rejects the whole output set before publication.

---

## 🛠️ Local build

```sh
OUT_DIR=public ./build-all-feeds.sh             # preferred complete build + verification
OUT_DIR=public ./build-adguard-dns-filter.sh   # DNS
OUT_DIR=public ./build-threat-intel.sh         # FoxHole Sentinel threat intel
OUT_DIR=public ./build-bridges.sh              # TOR bridges
OUT_DIR=public ./build-geoip.sh                # geo database
OUT_DIR=public ./build-fingerprints.sh         # TLS fingerprint tables
./verify-feeds.sh public                       # same gate CI runs before publication
```

`verify-feeds.sh` is the same gate used by the workflow and requires no secrets: it verifies signatures with the committed `manifest.public.pem`, which is the same key available to the application, and verifies every artifact against the size and SHA-256 declared in its manifest. The directory is passed as an argument (`./verify-feeds.sh <dir>`); for builds signed with a test key, override `FOXHOLE_DNS_PUBLIC_KEY`.

Options:

```sh
# explicit FoxHole Core path (DNS)
FOXCORE_ROOT=/path/to/foxhole-core ./build-adguard-dns-filter.sh

# prebuilt AdGuard filter (DNS)
ADGUARD_SOURCE_REF=gh-pages ./build-adguard-dns-filter.sh

# pin upstream commit (threat intel)
THREAT_INTEL_SOURCE_REF=<commit> ./build-threat-intel.sh

# unsigned smoke build (any data feed)
FOXHOLE_DNS_REQUIRE_SIGNATURE=false ./build-adguard-dns-filter.sh
```

All five scripts accept `OUT_DIR` (repository root by default) and the same signing key from `FOXHOLE_DNS_SIGNING_KEY_PEM` or `FOXHOLE_DNS_SIGNING_KEY`. All five also support `FOXHOLE_DNS_REQUIRE_SIGNATURE=false` for smoke builds. The variable name contains DNS only because the DNS feed was implemented first.

Unsigned output is **not intended for publication**.

---

## 🏪 Store review notes

For F-Droid / Google Play:

- the application includes a built-in fallback;
- updates are opt-in;
- the source URL is configurable;
- downloaded artifacts are data, not code;
- manifests are signed;
- size and SHA-256 are verified;
- a failed update does not break VPN operation;
- FoxHole Sentinel scanning runs locally;
- package names, scan results, and verdicts are not sent anywhere;
- DNS logs, browsing history, filtering statistics, and the installed application list are not sent to this repository.

---

## ❤️ Support

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

## ⚠️ Disclaimer

> [!WARNING]
> Tor is a trademark of The Tor Project. FoxHole DB is not a product of The Tor Project and is not endorsed, sponsored, or affiliated with The Tor Project.
>
> FoxHole DB is not a product of AdGuard and is not affiliated with AdGuard Software Ltd.
>
> IP geolocation data is provided by DB-IP (`https://db-ip.com`) under CC-BY-4.0; this repository is not affiliated with DB-IP.

---

## 📄 License

The repository code and metadata are distributed under the [GNU General Public License version 3 or later](LICENSE). Licenses for source and generated data, including required attributions, are documented in [LICENSES.md](LICENSES.md).

## 🔗 Related projects

[![FoxHole Guard](https://img.shields.io/badge/GitHub-FoxHole_Guard-181717?logo=github&style=flat-square)](https://github.com/foxhole-team/foxhole-guard)
[![Version](https://img.shields.io/github/v/release/foxhole-team/foxhole-guard?label=version&style=flat-square)](https://github.com/foxhole-team/foxhole-guard/releases)

[![FoxHole Core](https://img.shields.io/badge/GitHub-FoxHole_Core-181717?logo=github&style=flat-square)](https://github.com/foxhole-team/foxhole-core)
[![Version](https://img.shields.io/github/v/release/foxhole-team/foxhole-core?label=version&style=flat-square)](https://github.com/foxhole-team/foxhole-core/releases)
