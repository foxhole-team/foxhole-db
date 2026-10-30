# DNS source pins and refresh review

The four files in `dns-category-sources/` pin purpose-specific inputs from
AdGuard Filters, EasyPrivacy and HaGeZi. They are a suffix-only projection,
not a claim to implement the complete browser-filter syntax. Keep the source
IDs, licenses, category assignments and selected paths under review.

`dns-category-source-pins.json` records the immutable repository commits,
their official commit API references and commit timestamps. This is producer
metadata; it adds no fields to the signed schema-3 manifest or Core input.
The producer refuses a missing review, an unmatched pin, a timestamp more than
five minutes in the future, or a source/review older than seven days. The
clock is the current wall clock, not the artifact generation timestamp or
`SOURCE_DATE_EPOCH`. The gate runs before a cached input is accepted and again
before compilation, including when a caller supplies `SOURCE_ROOT`.

## Prepare a local refresh

1. Use an isolated local checkout. Read the official default-branch HEAD once
   for each repository, retaining the API response, full commit SHA,
   `commit.committer.date`, observation time and canonical commit URL:

   ```sh
   curl --fail --silent --show-error --proto '=https' \
     'https://api.github.com/repos/AdguardTeam/AdguardFilters/commits?per_page=1'
   curl --fail --silent --show-error --proto '=https' \
     'https://api.github.com/repos/easylist/easylist/commits?per_page=1'
   curl --fail --silent --show-error --proto '=https' \
     'https://api.github.com/repos/hagezi/dns-blocklists/commits?per_page=1'
   ```

2. Verify each selected identity through
   `https://api.github.com/repos/OWNER/REPO/commits/FULL_SHA`. Download every
   already-selected input from
   `https://raw.githubusercontent.com/OWNER/REPO/FULL_SHA/PATH`, with normal
   HTTPS verification, a timeout and the existing 64 MiB file bound. Hash the
   actual unmodified bytes with SHA-256. Never pin a moving branch or infer a
   hash from a rendered browser excerpt. Keep failed transport attempts separate.

3. Update every occurrence of that repository commit and its input hashes in
   all four source specifications. Record each exact repo/commit, its Unix
   commit timestamp and immutable API URL in `dns-category-source-pins.json`;
   set `reviewed_at_unix` to the actual inspection time. Do not make an old
   commit fresh by changing only this time. Do not edit release versions,
   signing data, publisher workflow or a future Core compiler asset pin.

4. Compare old and new supported suffix sets. Record per-source input bytes,
   supported block/exception counts, unsupported-format counts, added/removed
   suffixes and conversion refusals. Report those counts as the supported
   projection, not the complete upstream list. Inspect unexpectedly large
   changes before delivery.

5. Run the focused producer checks:

   ```sh
   python3 -m unittest discover -s tests -p test_dns_categories.py -v
   python3 -m unittest discover -s tests -p test_dns_source_freshness.py -v
   ```

   Then fetch/hash the pinned inputs and generate a local candidate using the
   separately verified actual Core compiler. Keep the compiler, four-variant
   signed delivery and final publication gates separate from these Python
   checks. A skipped compiler test or unsigned candidate is not release PASS.

The local review/PR proposal should contain only the changed pins, producer
checks/docs/tests and the recorded source/delta report. Human review and the
authorized release process perform any later PR, commit, signature or push.
This procedure requests no bot permission, schedule or remote write.

## Source exceptions and representability

An exception can remove rules from its own source only. If one source allows
`shared.test`, another source can still block it in the same category or as
malicious. Source exceptions are never promoted into global `allow_suffixes`.

For `||parent.test^` plus `@@||safe.parent.test^`, keeping the parent would
still block the safe child. Positive suffix rules cannot express this hole,
and a global allow could clear an independent malicious source. The producer
therefore refuses this source with an explicit source/exception/parent-suffix
explanation. It does not silently broaden a block, weaken another category or
skip a required check. A future scoped representation requires a separately
reviewed Core/compiler contract; do not invent signed JSON fields.
