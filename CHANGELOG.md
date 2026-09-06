# Changelog

All notable changes to this project are documented here. The format is based on Keep a Changelog, and this project aims to follow Semantic Versioning.

## [Unreleased]

## [0.1.2] - 2026-09-06

### Added

- `npx carapax@0.1.2 demo` with human-readable and JSON output, three computed decisions, and a verified local ledger. No model, API key, or personal data required.
- Installed-package CLI smoke tests and demo regression tests.
- A standalone Mem0 example with untrusted defaults, explicit provenance, an opt-in hosted path, and pinned-SDK mocked-transport tests in CI.

### Changed

- Package homepage now points to `https://carapax.moltagent.run/`.
- README starts with a no-account trial and links to integration help.

## [0.1.1] - 2026-09-04

### Added

- A compiled JavaScript package with bundled TypeScript declarations for standard Node consumers.
- A package smoke test that installs the packed artifact and imports both public entry points.
- npm discovery metadata and a direct installation quickstart.
- `SECURITY.md` with a private vulnerability disclosure path.
- `CONTRIBUTING.md` with the setup and verify gate.
- `.github/workflows/publish.yml` to publish the package to npm on a `v*` tag.
- `files` allowlist and `publishConfig.access` in `package.json` for clean public publishing.
- GitHub issue templates and a pull request template.

### Changed

- Upgraded the test toolchain to remove known vulnerable development dependencies.
- Renamed the npm package from `@openclaw/carapace` to `carapax` to match the product brand. Code identifiers (`createCarapace`, `withCarapace`, `CARAPACE_MODEL_ID`) keep the `carapace` spelling for now.

## [0.1.0]

Initial public baseline.

### Added

- Five-plane memory-integrity firewall (Ingress, Recall, Promotion, Soul, Egress) with a hash-chained ledger.
- Heuristic injection and exfiltration detectors in the zero-dependency core library.
- Hosted Cloudflare Worker with a Workers AI model detector (`@cf/meta/llama-guard-3-8b`, configurable via `CARAPACE_MODEL_ID`) composed behind the `Detector` interface; the promotion gate still decides on provenance.
- Per-tenant Durable Object ledger with a `verify()` race fix (`blockConcurrencyWhile`).
- Worker endpoint hardening: strict input validation, bounded body size, per-tenant rate limiting.
- Measured before/after detection recall: attack recall 14/30 (46.7%) heuristic-only to 19/30 (63.3%) heuristic+model, benign false-positive rate 1/25 (4.0%) unchanged.
