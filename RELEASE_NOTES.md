# Release Notes

**Content policy**: This file carries the most-recent 3 releases
(reverse chronological). Older releases are archived under
`docs/releases/vX.Y.Z.md`.

## v0.1.0 (May 2026)

**First public release** — `lanyte-attest` mints and verifies signed
session tokens for supervised agent sessions. CLI + library surface,
Ed25519 signing via `seclusor-crypto`, HOME-trusted-paths for admin
operations, sqlite-backed session lifecycle (active / ended / revoked),
and shared `verify` API consumed directly by `stashvoy`.

- **CRT-012 foundational PR** — `keygen` / `begin` / `verify` / `end`
  / `revoke` CLI; public `verify` library surface; trust loaded from
  `~/.lanyte/attest/trust.toml`; sqlite `sessions.db` tracking;
  Ed25519 signing via `seclusor-crypto v0.1.1`.
- **License policy baseline** — `.goneat/` dependency license rules,
  canonical MIT and Apache-2.0 license texts at repo root.
- **Release infrastructure** — Makefile + scripts implementing the
  manual-signing release flow (minisign per-binary + GPG over
  `checksums.txt`; signing keys never in CI); `RELEASE_CHECKLIST.md`
  is the source of truth for release sequencing; `SECURITY.md`
  documents the issuer-side trust posture.

**Operator-visible defaults**:
- attest root: `~/.lanyte/attest/`
- issuer trust config: `~/.lanyte/attest/trust.toml`
- session registry: `~/.lanyte/attest/sessions.db`
- signing key (encrypted at rest): `~/.lanyte/attest/signing-key.age`
- public key: `~/.lanyte/attest/signing-key.pub`

**Known follow-ons (not blocking v0.1.0)**:
- `ctx_hash` consumer-side runtime context matching (claim is
  reserved + structurally enforced; matching deferred)
- v2 token injection via UDS daemon (ssh-agent pattern) — v0.1.0
  uses env-var injection (`LANYTE_SESSION_TOKEN`)
- Release-signing key provisioning — v0.1.0 binaries are unsigned
  draft artifacts until the lanytehq minisign + GPG keypair lands

See `docs/releases/v0.1.0.md` for full notes.

_(Older releases archived in `docs/releases/`. This file is kept short
per project convention.)_
