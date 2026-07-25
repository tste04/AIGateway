# Contributing to AIGateway

Thank you for considering a contribution — issues, ideas and pull requests are welcome.

## The one rule: the CLA

AIGateway is **dual-licensed** (free for noncommercial use under PolyForm Noncommercial,
commercial licenses sold separately). For that model — and for the project's ability to
ever change its licensing or transfer the codebase as a whole — the maintainer must
hold sufficient rights to *all* of the code.

Therefore every contribution requires agreeing to the
**[Contributor License Agreement](docs/CLA.md)**. Short version: you keep the copyright
to your contribution, and you grant the maintainer a perpetual, irrevocable,
transferable license to use, relicense and sublicense it under any terms.

Agreement is expressed per pull request: add this line to your PR description —

```
I have read docs/CLA.md and I agree to it for this and all my future contributions.
```

PRs without it can't be merged, no exceptions — this protects the project's chain of
title.

## Practical notes

- Build: `swift build` (Swift 5.7+, macOS 12+ / Linux). Release: `swift build -c release`.
- Tests: `swift test` — everything runs in-process, no network and no credentials
  required; they must stay that way. Narrow the run with
  `swift test --filter InputFirewallTests` (target), `--filter PIIRoundTripTests`
  (class) or
  `--filter InputFirewallTests.PIIRoundTripTests/testMaskThenUnmaskRestoresOriginal`
  (single test).
- There is no linter, no CI configuration and no executable target — `GatewayService`
  is started by a host program (example in the README).
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
  `GW-001`, `PII-900`. Suppressions, SIEM rules and dashboards bind to them; changing
  one is a breaking change. Adding is fine, and `message` text is free to reword.
- **Scanners detect, the policy decides.** A `ContentScanner` returns findings and a
  score; it never decides to block. Logic of the form "block above score X" must not
  move into a scanner — thresholds have to stay changeable without touching a
  detection rule.
- **Pipeline order is fixed** (see `docs/DECISIONS.md`): size guard → injection →
  PII masking → DLP → semantic cache → upstream. Masking must stay *before* cache
  key construction, and the cache lookup must stay *after* the firewall.
- **Normalization is for comparison only.** `TextNormalizer` builds a detection
  surface; what gets forwarded is always the merely sanitized text. Folding
  homoglyphs in the payload would destroy legitimate non-Latin content.
- **Fail-closed stays fail-closed.** An unknown source type resolves to `untrusted`,
  not `neutral` — do not "fix" that default.
- **PII findings do not block.** They carry weight 0 and yield `.allowModified`; the
  density guard with `onDensityExceeded: "abstain"` is the single exception.
- **No hand-written TLS or crypto.** The server binds to loopback by default and
  termination is the operator's job via a reverse proxy.

## Conventions

- Every source file starts with `// Copyright (c) 2026 Tommy Stellmacher` and
  `// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0`.
- Comments are German and transliterated without umlauts in source files
  (`Groessen`, `aendern`); Markdown under `docs/` and the README use real umlauts.
- Comments explain **why**, not what — match the existing tone rather than
  annotating the obvious.
- Tests are XCTest, grouped by behaviour rather than one class per type. PII tests
  run with `baseDirectory: nil` (in-memory vault, deterministic).
- Concurrent state lives in actors; everything publicly visible is `Sendable`.
