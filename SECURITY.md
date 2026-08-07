# Security Policy

AIGateway is itself a security component — an input firewall in front of a
language model. Vulnerability reports are taken seriously and handled with
priority.

## Reporting a vulnerability

Please do **not** open a public issue for security-relevant findings.

- Preferred: report privately via GitHub —
  [Security → Report a vulnerability](https://github.com/tste04/AIGateway/security/advisories/new).
- Alternatively by mail: **hello@tstellmacher.com**.

Include what you would want to receive yourself: affected component
(scanner, pipeline stage, HTTP server, daemon), a minimal reproduction,
and the impact you see. A proof-of-concept request body is worth more than
a long description.

You can expect an acknowledgement within a few days. Please allow a
reasonable window for a fix before any public disclosure; coordinated
disclosure is appreciated and will be credited unless you prefer otherwise.

## Scope

In scope, in rough order of severity:

- **Bypass of a detection stage** — an input that demonstrably defeats
  injection, secret, PII, DLP or malware detection *by construction*
  (encoding tricks, normalization gaps, parser differentials), not merely a
  pattern the rule set does not know yet.
- **Payload leaving the box where it must not** — cleartext PII or secrets
  in audit events, logs, the semantic cache, or the quarantine beyond the
  configured detail level.
- **Cross-tenant effects** — cache answers or masking sessions reaching a
  principal they do not belong to.
- **Transport weaknesses** in `HTTPServer`/`UpstreamClient` (request
  smuggling, resource exhaustion beyond the documented limits).

Out of scope: findings that require the operator to ignore the documented
deployment model (loopback bind or reverse proxy in front), missing rule
patterns for new attack phrasings (open a normal issue for those — the rule
set is expected to grow), and denial of service by sheer volume against an
instance without the documented rate limit enabled.

## Supported versions

The `main` branch is the supported version. Fixes land there; there are no
long-lived release branches.
