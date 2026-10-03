# Evidence format v2

## Schema and migration

`PRAGMA user_version=2` identifies the schema. New tables use the `dw_` prefix to avoid overwriting the original `files` and `scans` tables. Migration is additive and transactional. Unknown versions are rejected. `migrate --db legacy.db` adds modern tables, while all historic SHA-1 values and compressed fields remain unchanged. New scans appended to an old database establish a new dual-hash baseline; an absent historic SHA-256 is never invented.

* `dw_scans`: parent, machine, mode, scope/key identifier, status, system/network observations, roots, summary, manifest and optional timestamp proof.
* `dw_volumes`: volume information and journal start/end/continuity per selected root.
* `dw_files`: composite `(scan_id, canonical_path)` key; native comparison metadata; volume/file IDs; 32-byte BLAKE3/SHA-256 BLOBs; hash method; SHA-256 origin/provenance; outcome; hard-link count; compressed compatibility display fields.
* `dw_events`: categorized errors, reparse exclusions, journal fallbacks and rename observations, including system error codes when available.
* `dw_signatures`: Ed25519 signature and raw public key. **No private signing key.**

Indexes support scan/path, scan/object and scan/status lookups. Temporary journal/object tables are disk-backed. Each completed file insert participates in bounded batches. Status is RUNNING, COMPLETED, CANCELLED, FAILED or INTERRUPTED. COMPLETED means the collector finished its policy, **not** that every selected byte was accessible. Inspect manifest `coverage_complete`, skipped/errors/unstable counts and default-stream policy.

Compressed `original_path`, `created_utc`, `modified_utc`, `accessed_utc`, `scan_time` remain zlib UTF-8 text. Nanosecond integers are the exact comparison timestamps; compressed ISO display timestamps may have lower precision. In anonymized scans the original-path blob contains the keyed identifier, never a reversible original path. HMAC-SHA-256 identifiers include the complete canonical path; the same external 32+ byte random key and roots/policy are required for deterministic comparison. A hash of the key identifies configuration but cannot recover the key.

## Verification provenance

`FULL_DUAL_HASH` establishes both digests from the same read. `FULL_BLAKE3` reads content and carries an established matching SHA-256. `BLAKE3_CHANGED_SHA256` reads BLAKE3, detects a difference and rereads to establish SHA-256. `USN_INCREMENTAL` carries both digests only after continuity, dirty-ID, identity, metadata and current per-file-USN checks pass. `CARRIED_FORWARD` can identify same-scan stable hard-link reuse or a deletion tombstone. UNVERIFIED, UNSTABLE and ERROR outcomes are explicit and never masquerade as stable hashes.

`sha256_provenance` is RECALCULATED, CARRIED_FORWARD or SAME_SCAN_OBJECT. `sha256_origin_scan` points to the scan that actually established that digest. Windows object identity is a 64-bit volume serial plus 128-bit FILE_ID_INFO, represented as hexadecimal. Volume discovery/journal descriptors also contain the Win32 32-bit volume serial; those are separate API fields. File IDs may be reused after deletion and are not cryptographic identities.

## DW-MERKLE-V1

The canonicalizer is `dw.evidence.canonical_json`: ASCII JSON, sorted object keys, no insignificant whitespace, `ensure_ascii=True`, no NaN/Infinity. JSON escaping and arrays/objects are explicit field boundaries; no concatenated ambiguous strings. Digests are lowercase hex in canonical leaves; absent values are JSON null. Native timestamps/sizes/attributes are integer values. No accidental dictionary ordering is used.

Paths are absolute, with Windows extended prefixes removed and separators changed to `/`. Selected roots resolve once using `realpath`; traversal does not follow reparse entries. Actual filename case is preserved to support case-sensitive Windows directories. **No Unicode normalization** is performed: normalizing NFC/NFD would alias distinct legal filenames. UTF-8 byte ordering over canonical path, then volume serial and file ID, defines leaf order. UTF-8 databases use the native BINARY index; older UTF-16 databases use an explicit UTF-8 comparison collation to produce the same order. Anonymized paths use their HMAC identifiers for the same ordering.

The content leaf is an object containing scheme, canonical path, volume serial, file ID, logical size, BLAKE3, SHA-256, status and error category. ADDED/MODIFIED/UNCHANGED/RENAMED normalize to PRESENT; ERROR/UNSTABLE/UNVERIFIED remain explicit. Deletion tombstones are omitted from the content inventory. The metadata leaf includes those fields plus creation/modification/access nanoseconds, attributes, verification method, SHA-256 provenance/origin, hard-link count, decompressed original/display path and display timestamps, and error message. Deletion tombstones participate in the metadata tree.

Leaf = `SHA256(0x00 || canonical_leaf_bytes)`.

Parent = `SHA256(0x01 || left_32_bytes || right_32_bytes)`.

At each level, an odd unpaired node is promoted unchanged. Empty tree = `SHA256(0x02 || ASCII("DW-MERKLE-V1"))`.

An O(log N) carry stack reduces a database-ordered cursor; right-edge subtrees are folded from lowest level upwards. The tests compare this streaming implementation with a conventional level-by-level tree, including odd leaf counts. No inventory-sized hash list is required.

`scan_root = SHA256(ASCII("DRIVEWITNESS-SCAN-V1") || content_root_binary || metadata_root_binary)`.

This is a logical inventory/metadata commitment, **not a database-file checksum**. Operational event logs, database layout and all container bytes are outside these roots. SHA-256 provenance is part of metadata integrity; content roots can remain equal across unchanged verification passes while metadata roots change.

## Manifests, signing and clocks

Completed scans store a canonical manifest and export `<db>.manifest.json` atomically. The export envelope holds the manifest and optional algorithm/public-key/base64 signature. Ed25519 signs exactly the canonical **manifest bytes**, excluding the envelope/signature. Encrypted PKCS8 PEM keys are supported; keys remain external. CLI password input comes from a named environment variable, and GUI passwords remain session-only.

`verify --db` recomputes roots from stored inventory and checks signatures when present. To authenticate a signer, provide an externally trusted 32-byte raw Ed25519 public key using `--public-key`; an embedded public key alone does not establish trust. Unsigned roots must be retained separately under trusted custody because an attacker who rewrites the database can also replace unsigned roots/manifests. Live verification is a distinct `verify --live` pass.

System UTC and optional HTTP network-time observations are ordinary clock information. They are not cryptographic timestamp proofs. `TimestampProvider` accepts SHA-256 of canonical manifest bytes and must validate message imprint and provider trust before returning a proof. No RFC 3161 provider ships configured. Timestamping failure prevents completion and records TIMESTAMP_ERROR. Trust anchors, private-key access and endpoint integrity are external responsibilities.

## USN checkpoint policy

Check volume serial, journal ID, FirstUsn/LowestValidUsn and checkpoint <= current NextUsn. Recreated/rolled-off/unavailable/malformed journals trigger full verification. Changed V2/V3 file IDs are spooled to SQLite. Names are found by the normal bounded namespace walk, which also detects new paths, directory renames and removals. Quick carry-forward requires a current per-file USN below the start snapshot and unchanged object/size/modification metadata. A final journal query records continuity. The start checkpoint, not the completion checkpoint, is retained so changes during collection are reconsidered next time. Verify/Forensic do not rely on journal content claims.
