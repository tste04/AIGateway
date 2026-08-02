# Contributing to AIGateway

Thank you for considering a contribution — issues, ideas and pull requests are welcome.

## Licensing of contributions

AIGateway is licensed under the [Apache License 2.0](LICENSE). By submitting a
contribution you agree that it is provided under the same license as the project
(inbound = outbound, per section 5 of the license). You keep your copyright;
there is no CLA to sign.

## Practical notes

- Build: `swift build` (Swift 5.7+, macOS 12+ / Linux). Release: `swift build -c release`.
- Tests: `swift test` — everything runs in-process, no network and no credentials
  required; they must stay that way. Narrow the run with
  `swift test --filter InputFirewallTests` (target), `--filter PIIRoundTripTests`
  (class) or
  `--filter InputFirewallTests.PIIRoundTripTests/testMaskThenUnmaskRestoresOriginal`
  (single test).
- CI builds and tests every push and pull request on Ubuntu and macOS
  (`.github/workflows/ci.yml`). Both platforms run, because the code branches on
  `canImport(Darwin)` for the socket write path and for `FoundationNetworking`;
  one run leaves the other branch unchecked. A red run blocks a merge — the
  suite is fast and needs no network, so there is no reason to tolerate one.
- There is no linter. The executable target is `aigatewayd` (`--config <path>`,
  template in `docs/aigatewayd.example.json`); as a library, `GatewayService` is
  started by a host program (example in the README).
- Tests must stay deterministic. Beware of reading anything Swift does not
  promise to order: `Dictionary.first(where:)` reseeds per process and once made
  a passing test into a coin flip that only CI caught.
- The design rationale lives in [`docs/DECISIONS.md`](docs/DECISIONS.md). It is
  binding, not descriptive: changing a decision recorded there means amending that
  file with a reason and a date, in the same PR.

## Hard invariants

PRs violating these will be declined regardless of usefulness.

- **`Foundation` is the only dependency.** Adding a package dependency breaks the
  design, not just a guideline.
- **Audit events never carry payload.** Rule IDs, categories, sizes, times — never
  the prompt, never match excerpts, not even temporarily for debugging.
  `AuditEvent(decision:principal:)` is the only intended path and drops the payload
  on purpose.
- **Rule IDs are stable.** `INJ-001`, `SEC-002`, `PII-004`, `SAN-003`, `ANO-001`,
  `GW-001`, `GW-002`, `GW-003`, `PII-900`. Suppressions, SIEM rules and dashboards bind to them; changing
  one is a breaking change. Adding is fine, and `message` text is free to reword.
- **Scanners detect, the policy decides.** A `ContentScanner` returns findings and a
  score; it never decides to block. Logic of the form "block above score X" must not
  move into a scanner — thresholds have to stay changeable without touching a
  detection rule.
- **Pipeline order is fixed** (see `docs/DECISIONS.md`): rate guard → size guard →
  malware → injection → PII masking → DLP → semantic cache → upstream. Masking
  must stay *before* cache key construction, and the cache lookup must stay
  *after* the firewall.
- **Normalization is for comparison only.** `TextNormalizer` builds a detection
  surface; what gets forwarded is always the merely sanitized text. Folding
  homoglyphs in the payload would destroy legitimate non-Latin content.
- **Fail-closed stays fail-closed.** An unknown source type resolves to `untrusted`,
  not `neutral` — do not "fix" that default.
- **PII findings do not block.** They carry weight 0 and yield `.allowModified`; the
  density guard with `onDensityExceeded: "abstain"` is the single exception.
- **No hand-written TLS or crypto.** The server binds to loopback by default and
  termination is the operator's job via a reverse proxy.
- **Identity claims are never believed on their own.** The default
  `PrincipalResolver` ignores the identity headers rather than honouring them,
  so no caller can select a cache partition. A claim presented without a valid
  credential is answered with 401, never with a silent fallback to anonymous.
- **The cache stores masked responses.** What goes into `SemanticCache` still
  carries placeholders; the de-masked text belongs to one requester only.
  Storing the unmasked answer would turn the cache into a PII leak between
  users of the same partition.
- **The cache never blocks a request.** It is a cost lever, not a protection
  stage: its only legitimate failure is a miss. It is exempt from the
  fail-closed budget and must not mark a decision `degraded` — that word is
  reserved for an incomplete *security* verdict.
- **Payload leaves the process through the quarantine or not at all.**
  `QuarantineSink` is the one path allowed to retain content, and it is off by
  default with three levels and a hard retention. Do not widen it silently: if
  `masked` is asked for and no PII stage is configured, the entry drops to
  `counts` rather than storing raw text, and `QuarantineSample.detail` always
  states what was actually kept.
- **Masking sessions are never written to disk and never guessed.**
  `MaskingSessionStore` holds cleartext mappings, so it stays in memory; a
  lookup that finds nothing returns `nil` and the caller falls back to
  `MaskingSession.empty`, which sends the answer out with placeholders
  standing. Resolving from the global vault instead would be the
  multi-tenant-unsafe return path the session type exists to avoid.

## Conventions

- Every source file starts with `// Copyright (c) 2026 Tommy Stellmacher` and
  `// SPDX-License-Identifier: Apache-2.0`.
- Comments are German and transliterated without umlauts in source files
  (`Groessen`, `aendern`); Markdown under `docs/` and the README use real umlauts.
- Comments explain **why**, not what — match the existing tone rather than
  annotating the obvious.
- Tests are XCTest, grouped by behaviour rather than one class per type. PII tests
  run with `baseDirectory: nil` (in-memory vault, deterministic).
- Concurrent state lives in actors; everything publicly visible is `Sendable`.
