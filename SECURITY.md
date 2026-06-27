# Security policy

Carapax (package `@openclaw/carapace`) is a memory-integrity firewall, so the security of the project itself matters. Thank you for helping keep it sound.

## Reporting a vulnerability

Please do not open a public issue for security problems.

Report privately by either:

- Opening a GitHub private vulnerability report via the repository "Security" tab ("Report a vulnerability"), or
- Emailing joe@joepro.ai with the subject line "carapax security".

Include a description of the issue, the affected version or commit, and a minimal reproduction if you have one. We aim to acknowledge reports within 3 business days and to provide a remediation plan or fix timeline within 10 business days.

## Scope

In scope:

- The core library in `src/` (trust model, promotion gate, ledger, detectors).
- The hosted Worker in `worker/` (input validation, rate limiting, Durable Object ledger).

Out of scope:

- The model arm's detection recall. The model detector raises a signal only; the promotion gate decides on provenance. A model miss is a known limitation, not a vulnerability.
- Issues that require a compromised host, a malicious dependency you introduced, or physical access.

## Supported versions

This project is pre-1.0. Only the latest published version on the `main` branch receives security fixes.
