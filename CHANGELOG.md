# Changelog

All notable changes to this project are documented here. The format is based on Keep a Changelog, and this project aims to follow Semantic Versioning.

## [Unreleased]

### Added

- `SECURITY.md` with a private vulnerability disclosure path.
- `CONTRIBUTING.md` with the setup and verify gate.
- `.github/workflows/publish.yml` to publish `@openclaw/carapace` to npm on a `v*` tag.
- `files` allowlist and `publishConfig.access` in `package.json` for clean public publishing.

### Changed

- Product brand presented as Carapax in documentation. The npm package and code identifiers keep the `carapace` name to avoid breaking installs.

## [0.1.0]

Initial public baseline.

### Added

- Five-plane memory-integrity firewall (Ingress, Recall, Promotion, Soul, Egress) with a hash-chained ledger.
- Heuristic injection and exfiltration detectors in the zero-dependency core library.
- Hosted Cloudflare Worker with a Workers AI model detector (`@cf/meta/llama-guard-3-8b`, configurable via `CARAPACE_MODEL_ID`) composed behind the `Detector` interface; the promotion gate still decides on provenance.
- Per-tenant Durable Object ledger with a `verify()` race fix (`blockConcurrencyWhile`).
- Worker endpoint hardening: strict input validation, bounded body size, per-tenant rate limiting.
- Measured before/after detection recall: attack recall 14/30 (46.7%) heuristic-only to 19/30 (63.3%) heuristic+model, benign false-positive rate 1/25 (4.0%) unchanged.
