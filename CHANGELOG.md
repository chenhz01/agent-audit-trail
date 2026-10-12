# Changelog

## [0.1.1] - 2026-10-11

### Changed (round-2 iteration after first-draft self-audit)

- **Robustness:** fixed a crash the expanded suite exposed — a JSONL line holding a valid-JSON *array* (e.g. `[1,2,3]`) parsed into a list and blew up `verify` with `AttributeError` instead of being reported; non-object lines now surface as `non-object JSON line` errors. Round 2 also hardened the CLI test harness against argparse's `SystemExit(2)` on invalid choices, so the suite survives its own failure-path tests.
- **Test rigor (+10%):** suite grew 40 → 44 checks; new cases pin the two failure dimensions apart (prev_hash-only tamper vs payload-only tamper both detected), ts-rewrite detection (timestamps are inside the hash body), extract on a missing trail, and identical-payload chaining (hash differs via seq).
- **Docs:** README why-not-X now names the one-layer differences against both same-name anchors (schema validation + gap/reorder discrimination vs opaque records).

## [0.1.0] - 2026-10-11

### Added

- `audittrail.py`: canonical-JSON event hashing (sha256 over prev_hash + sorted-keys body), append with type/rollback-ref validation, full-chain verify discriminating tamper / gap / reorder / duplicate seq / unknown type / unparseable lines, per-type stats, type-filtered extract.
- `cli.py`: `append` / `verify` (--json) / `stats` / `extract` subcommands; exit codes 0/1/2.
- `self_test.py`: three families — functional, error paths, extreme edges (200-event chains, 100KB payloads, unicode/emoji, CRLF, duplicate seq, deep nesting).
- MIT LICENSE (zhengming contributors), README, initial ALIGNMENT audit.
