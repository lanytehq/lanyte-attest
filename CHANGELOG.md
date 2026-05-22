# Changelog

All notable changes to lanyte-attest are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file carries the most-recent ~10 releases in reverse chronological
order. Older entries are archived under `docs/releases/vX.Y.Z.md`.

## [Unreleased]

_No changes yet — open the next release's [Unreleased] section here._

## [0.1.0] — 2026-05-22

First public release of `lanyte-attest`. Establishes the session
attestation boundary that downstream lanytehq tools (starting with
`stashvoy`) enforce.

### Added

- **CLI surface** — `keygen`, `begin`, `verify`, `end`, `revoke`.
  - `keygen` generates an Ed25519 signing key, encrypts the 32-byte
    seed with `seclusor-crypto`, and writes key material under
    `~/.lanyte/attest/` (public key as base64 in `signing-key.pub`;
    private key as age ciphertext in `signing-key.age`).
  - `begin` mints a session token, records session state in
    `sessions.db`, and either emits shell export code or execs a
    child command with `LANYTE_SESSION_TOKEN` set.
  - `verify` validates JWT shape, Ed25519 signature, expiry, issuer,
    and optional role/scope expectations, then emits claims as JSON
    on stdout.
  - `end` and `revoke` transition tracked sessions in SQLite through
    a shared canonical status path used by `verify` as well.
- **Library surface** — `cargo check --no-default-features
  --features verify` is the intended downstream-consumer boundary.
  Reusable mint/verify helpers exposed for direct linkage; `stashvoy`
  consumes this rather than re-implementing token verification.
- **Trust model** — issuer trust loaded from
  `~/.lanyte/attest/trust.toml`, not runtime env. HOME-trusted-paths
  for admin operations; `ctx_hash` is currently a reserved claim
  with enforced structural shape (consumer-side runtime context
  matching is a follow-on; the field is structurally future-safe).
- **JWT claims** — `iss`, `sub` (supervisor), `sid` (session UUID,
  stable across re-attestation), `role`, `scope`, `iat`, `exp`,
  `jti` (per-token), `ctx_hash` (reserved).
- **Crypto dependency** pinned to `seclusor-crypto v0.1.1` with the
  `signing` feature (Ed25519). No shelling-out — `seclusor-crypto`
  linked as a library.
- **License files** — canonical MIT and Apache-2.0 license texts
  restored at repo root.
- **Dependency license policy baseline** under `.goneat/` for
  release-cycle license-compliance gating.

### Release infrastructure

- `Makefile` with build / check / install + release-cycle targets
  (`release-prep`, `release-preflight`, `release-sign`,
  `release-verify`, `release-upload`, `release-undraft`,
  `release-upload-all`, `release-notes`, `version-check`,
  `version-sync`, `version-patch` / `-minor` / `-major` / `-set`).
- `scripts/` with sign / verify / checksums / upload / download /
  export-keys / verify-public-keys helpers for the manual-signing
  flow (signing keys are NEVER in CI; the release author runs the
  signing targets locally).
- `RELEASE_CHECKLIST.md` documenting the canonical release sequence
  end-to-end, including external-adopter verification commands.
- `docs/releases/v0.1.0.md` archive entry; `RELEASE_NOTES.md` carries
  the latest release surface.
- `SECURITY.md` documenting issuer-side security posture (key
  handling, JWT verification, supported versions).
- `CONTRIBUTING.md` documenting the PR workflow, agent attribution
  format, and MSRV policy.
- `keys/expected-fingerprints.txt` with TBD placeholders — populated
  once the lanytehq release-signing keypair is provisioned.

### Notes

- **MSRV**: Rust 1.85.0.
- **Signing keys**: not yet provisioned at the v0.1.0 cut. The
  v0.1.0 release artifacts will ship signed once the lanytehq
  minisign + GPG keypair lands; the machinery is in place to do so
  via `make release-sign` + `make release-verify` against
  `keys/expected-fingerprints.txt`. Until then, downloads from the
  GitHub draft release are unsigned and should be treated as
  pre-publication artifacts.

[Unreleased]: https://github.com/lanytehq/lanyte-attest/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lanytehq/lanyte-attest/releases/tag/v0.1.0
