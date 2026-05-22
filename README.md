# lanyte-attest

[![CI](https://github.com/lanytehq/lanyte-attest/actions/workflows/check.yml/badge.svg?branch=main)](https://github.com/lanytehq/lanyte-attest/actions/workflows/check.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.85.0-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/github/v/tag/lanytehq/lanyte-attest?label=version&sort=semver)](https://github.com/lanytehq/lanyte-attest/releases)

`lanyte-attest` is the session attestation CLI and library for
supervised Lanyte agent sessions. It mints and verifies signed session
tokens (Ed25519 JWTs), stores revocation state locally in sqlite, and
provides the attestation boundary that downstream tools — starting
with [`stashvoy`](https://github.com/lanytehq/stashvoy) — enforce.

Sessions get a stable identity that downstream tools can verify
without re-implementing crypto: a single shared `verify` library
surface, one canonical issuer-trust config under HOME-trusted-paths,
and a sqlite-backed lifecycle (active → ended/revoked) that
verification reads through.

## Status

`lanyte-attest` v0.1.x.

What's shipped:

- **CLI** — `keygen`, `begin`, `verify`, `end`, `revoke`. Mint a
  signed token, exec a child command with `LANYTE_SESSION_TOKEN` in
  its environment (or emit shell export code), inspect claims, and
  retire sessions.
- **Library** — shared `verify` API consumed directly by `stashvoy`.
  `cargo check --no-default-features --features verify` is the
  downstream-consumer boundary.
- **Crypto** — Ed25519 signing via
  [`seclusor-crypto`](https://github.com/3leaps/seclusor) v0.1.1
  (`signing` feature), private seed age-encrypted at rest, in-memory
  hygiene via `zeroize`.
- **Trust model** — issuer trust loaded from
  `~/.lanyte/attest/trust.toml`. JWT claims cover
  `iss`, `sub`, `sid`, `role`, `scope`, `iat`, `exp`, `jti`, and a
  reserved `ctx_hash`.
- **Session registry** — `sessions.db` (sqlite) tracks active, ended,
  and revoked sessions through a single canonical status path read
  by `verify`.

Roadmap follow-ons (deferred):

- `ctx_hash` consumer-side runtime context matching (the claim is
  reserved and structurally enforced today; matching is the next
  meaningful lift).
- v2 token injection via UDS daemon (ssh-agent pattern). v0.1.x ships
  the env-var injection path.

## Install

From a tagged release:

```bash
cargo install --git https://github.com/lanytehq/lanyte-attest --tag v0.1.0
```

From a local checkout:

```bash
git clone https://github.com/lanytehq/lanyte-attest
cd lanyte-attest
make install   # installs to ~/.local/bin/lanyte-attest
```

## Commands

```text
lanyte-attest keygen [--output <dir>] [--issuer <instance>]
lanyte-attest begin --role <role> --scope <scope> [--ttl <duration>] [--supervisor <handle>] [--emit-env | -- <child-cmd> ...]
lanyte-attest verify <token>
lanyte-attest end
lanyte-attest revoke <jti>
```

`lanyte-attest --help` lists every flag.

## End-to-end proof

Example local proof flow with `stashvoy` as the downstream consumer:

```bash
# 1. Generate key material + trusted issuer config
lanyte-attest keygen --issuer lanyte-attest

# 2. Start an attested session and export the token into the shell
eval "$(lanyte-attest begin --role devlead --scope lanytehq --emit-env)"

# 3. Verify the token directly
lanyte-attest verify "$LANYTE_SESSION_TOKEN"

# 4. Checkpoint through stashvoy (which calls the shared verify API)
stashvoy checkpoint --role devlead --scope lanytehq --file path/to/STATE.json

# 5. End the session
lanyte-attest end

# 6. A later checkpoint with the old token now fails verification
stashvoy checkpoint --role devlead --scope lanytehq --file path/to/STATE.json
```

Expected behavior:

- Step 3 succeeds and prints claims JSON.
- Step 4 succeeds; `sessions.db` records the session ref as a hash,
  not the raw token.
- Step 6 fails because the session is no longer active — the shared
  `verify` API reads the same canonical status path.

## Library use

Downstream consumers depend on `lanyte-attest` with default features
disabled and the `verify` feature on:

```toml
[dependencies]
lanyte-attest = { version = "0.1", default-features = false, features = ["verify"] }
```

This pulls in the verification surface (signature check, claim shape,
sqlite session-status read) without the mint-side dependencies
(`clap`, `rpassword`, `env_logger`). The full CLI surface is gated
behind the default `cli` / `issue` features.

## Verifying downloaded binaries

Released binaries ship with per-binary minisign signatures and a GPG
signature over the `checksums.txt` manifest. Public-key fingerprints
are pinned in `keys/expected-fingerprints.txt` and reproduced in
[`RELEASE_CHECKLIST.md`](./RELEASE_CHECKLIST.md) so external adopters
can verify a download without an org-side trust path.

The canonical verification commands and stable key fingerprints are
in [`RELEASE_CHECKLIST.md`](./RELEASE_CHECKLIST.md) §"Verification
commands for external adopters."

> The v0.1.0 release ships with `keys/expected-fingerprints.txt`
> populated as `TBD` pending lanytehq release-signing keypair
> provisioning. Until that lands and the fingerprints file is filled
> in, v0.1.0 binaries are unsigned draft artifacts. The release
> machinery is in place; only the keys themselves are pending.

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the contributor's
guide, [`AGENTS.md`](./AGENTS.md) for the agent-session conventions,
and [`SECURITY.md`](./SECURITY.md) for the vulnerability reporting
path. Repository conventions and the never-commit list live in
[`REPOSITORY_SAFETY_PROTOCOLS.md`](./REPOSITORY_SAFETY_PROTOCOLS.md).
