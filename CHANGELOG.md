# Changelog

## 1.0.0 (unreleased)

- Use the published owner-signed Core compiler archive for CI feed builds, with exact source, handoff and artifact pins and no compiler source-build fallback.

- Validate manifest epochs before shell arithmetic and match client clock limits: ten minutes for DNS, one day for other feeds. DNS validity must be between one second and 31 days.
- Accept the common PEM signing-key input for categorized DNS builds and verify its identity before compilation. All feed builders remove materialized temporary key files even when build work is retained.
- Document five signed data feeds and nine manifest/signature pairs, including four categorized DNS variants with separate schemas.
- Align client data-delivery and version documentation with Core, Guard and VPN 1.0.0 and the OpenWrt 1.0.0-r4 public beta.
- Build four signed DNS category variants with explicit source pins, category memberships, reproducible compiler inputs and bounded conversion. Preserve separate legacy schema2 delivery.
- Validate categorized signatures, canonical manifests, provenance, expiry and artifact bounds; include category data in publication comparison and release archives.
- Default the legacy DNS producer to the official generated gh-pages input while preserving explicit source overrides.

- Keep caller-supplied working directories intact; each feed builder cleans up only its own temporary child directory.
- Validate IPv4 and IPv6 indicators as numeric addresses and normalize equivalent IPv6 spellings without DNS lookups.
- Build the fallback DNS compiler with its committed Cargo lockfile.

## 2026-09-08

- Cache the pinned DNS feed compiler between CI runs.
- Skip publication when only build timestamps change, including the TLS fingerprint bundle timestamp. Preserve publication on changed data, contracts, or source provenance.
- Verify the current publication's signatures and fingerprint payload before deciding to skip. Renew unchanged feeds after 21 days or within seven days of DNS expiry.
