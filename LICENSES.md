# Licenses

## Generated DNS Rule Set

`adguard-dns-filter.fhds` is generated from:

- Project: AdGuard DNS filter
- Repository: <https://github.com/AdguardTeam/AdGuardSDNSFilter>
- License: GPL-3.0
- Input path: `Filters/filter.txt`

The generated `.fhds` file is derived rule-set data and should be treated as GPL-3.0-covered data from the upstream filter source.

## Generated FoxHole Sentinel threat intel

`threat-intel.json` is generated from:

- Project: Stalkerware Indicators List
- Author: Association Echap
- Repository: <https://github.com/AssoEchap/stalkerware-indicators>
- License: CC-BY-4.0 (<https://creativecommons.org/licenses/by/4.0/>)
- Input path: `ioc.yaml`

Required CC-BY attribution, reproduced here and in `threat-intel-source-info.json`:

> "Stalkerware Indicators List" by Association Echap (<https://github.com/AssoEchap/stalkerware-indicators>), licensed under CC-BY 4.0 (<https://creativecommons.org/licenses/by/4.0/>).

What is mirrored: Android package identifiers, certificate fingerprints (SHA-256 and SHA-1, in separate fields), product websites, and C2 domains and IP addresses from the same upstream records. They are reformatted into the `sentinel-threat-intel-json` structure the app reads. Not mirrored: the separate `distribution` field, YARA rules, APK digests, iOS bundle identifiers, and X.509 subject matchers. No upstream content is modified in substance; the exact upstream commit and input digest are recorded in `threat-intel-source-info.json` so the derivation stays auditable.

The generated `threat-intel.json` is derived data and remains CC-BY-4.0-covered, with attribution as above.

Upstream states that, while they do their best, accuracy is not guaranteed. That warning carries over to this mirror.

## Generated TOR Bridges List

`bridges.json` is generated from:

- Project: Tor Project builtin bridges (Moat circumvention API)
- Source: <https://bridges.torproject.org/moat/circumvention/builtin>

The upstream response is the Tor Project's own list of bridge lines shipped with Tor Browser. It is public circumvention data, published for exactly this use and carrying no separate license grant; it is mirrored verbatim per transport and reformatted into `tor-bridges-json` without alteration.

Tor is a trademark of The Tor Project. This repository is not produced, endorsed, sponsored by, or affiliated with The Tor Project.

## Generated Geo Database

`dbip-country-ipv4.csv` and `dbip-country-ipv6.csv` are mirrored from:

- Project: ip-location-db (`dbip-country` dataset)
- Repository: <https://github.com/sapics/ip-location-db>
- Upstream data: DB-IP Lite
- License: CC BY 4.0 (<https://creativecommons.org/licenses/by/4.0/>)

Required CC-BY attribution, reproduced here, in `geoip-manifest.json`, in `geoip-source-info.json`, and — as the license requires — in the application interface that displays the data:

> IP Geolocation by DB-IP (<https://db-ip.com>)

The CSVs are mirrored byte-for-byte; no derivation is performed in this repository. **This attribution must remain visible wherever the geo data is shown**; removing it from the app violates CC-BY-4.0.

## Generated TLS Fingerprint Tables

`fingerprints.json` is generated from the profile documents in FoxHole Core:

- Project: FoxHole Core
- Repository: <https://github.com/foxhole-team/foxhole-core>
- Input path: `fingerprints/*.json`
- License: GPL-3.0-or-later

The bundle copies data tables and their profile-specific provenance. ClientHello generator logic is not part of the feed and remains in the FoxHole Core binary.

## Build Script and Repository Metadata

The FoxHole DB build scripts, workflow, manifest metadata, the compatibility allowlist, and documentation in this repository are intended to be distributed under GPL-3.0-or-later, matching the generated filter data's upstream license boundary.

Two exceptions, both CC-BY-4.0 data from upstream and documented above: `threat-intel.json` and the two `dbip-country-*.csv` files.

## FoxHole Core Rule-Set Compiler

The build uses `foxcore-dns-compile` from the FoxHole Core repository to compile AdGuard DNS filter text into the `foxhole-dns-fst-v1` binary rule-set format read by the FoxHole Guard app.

The compiler is a build tool and is not shipped to FoxHole Guard users from this repository.

## No Executable App Code

Every published artifact is data.

- `.fhds` is DNS filtering data.
- `threat-intel.json` is a JSON list of identifiers.
- `bridges.json` is a JSON list of bridge lines.
- `dbip-country-ipv4.csv` and `dbip-country-ipv6.csv` are CSV address-range tables.
- `fingerprints.json` is a JSON bundle of ClientHello data tables.

None of them is executable application code, a plugin, or a runtime backend.
