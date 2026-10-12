# Alignment Audit (Rules 85-100 / 16 items) — agent-audit-trail

| # | Check | Status | Evidence |
|---|-------|--------|----------|
| 1 | Safety/Ethics section | N/A | Integrity tooling, no security research content; Limits covers tamper-evidence misreadings honestly. |
| 2 | Privacy/keys | PASS | No keys/tokens/real names; payloads in tests are placeholders; zero network. |
| 3 | Copyright boundary | PASS | Same-name anchors referenced factually (name, stars as of 2026-10-11, one-layer differences); no anchor text copied; MIT LICENSE shipped. |
| 4 | Fact-check numbers | PASS | 44/44 checks measured, repro command given; threat-model adequacy marked [estimated]. |
| 5 | Confidence grading | PASS | README: High (85%) event-model coverage, Medium (55%) trust-model fit, each with basis sentence. |
| 6 | Minimal Fallback | PASS | "Minimal Fallback (PLAN B)": one-paragraph spec + ~40-line verifier recipe in any language; canonical-JSON is the contract. |
| 7 | Quickstart timing | PASS | Quickstart labelled ~2 min, staged (self-test → record loop → audit). |
| 8 | Conflict arbitration | PASS | "Design Trade-offs": verifiability > expressiveness > throughput, with named rejections (free payload, linear verify, caller timestamps). |
| 9 | Changelog ≥2 iterations | PASS | v0.1.0 → v0.1.1: non-object-line crash fixed, SystemExit-hardened harness, 40→44 tests. |
| 10 | Exemption (session rule) | N/A | Session-level governance item; static repo not applicable. |
| 11 | Knowledge cutoff | PASS | Anchor landscape dated "as of 2026-10-11" in Problem. |
| 12 | Explicit assumptions | PASS | `[Core Assumptions]` lists 4 premises (trusted appender, four-type sufficiency, canonical-JSON stability, linear verify acceptable). |
| 13 | Three-part self-test | PASS | functional (16) + error paths (10) + extreme edges (18) = 44/44 PASS. |
| 14 | Socratic FAQ | PASS | "When NOT to use this?" — hostile appenders, PII payloads, security-boundary mis-expectation. |
| 15 | Pareto iteration | PASS | Round 2: robustness dimension (crash fix + harness hardening) plus +10% tests (40→44); CHANGELOG-traceable. |
| 16 | ≤60-word opening | PASS | First paragraph is 58 words ending with a judgment sentence ("a replayable file question, not a memory contest"). |

Additional: **Second-order effects** — "Limits & Second-order Effects" covers rechainable forgeries, non-redactability vs GDPR, semantic smuggling into payload, and verify-cost avoidance pressure.
