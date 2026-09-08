# Changelog

## 2026-09-08

- Cache the pinned DNS feed compiler between CI runs.
- Skip publication when only build timestamps change, including the TLS fingerprint bundle timestamp. Preserve publication on changed data, contracts, or source provenance.
- Verify the current publication's signatures and fingerprint payload before deciding to skip. Renew unchanged feeds after 21 days or within seven days of DNS expiry.
