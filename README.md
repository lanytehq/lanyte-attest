# lanyte-attest

`lanyte-attest` is the session attestation CLI and library for supervised Lanyte sessions.

It mints and verifies signed session tokens, stores revocation state locally, and provides the
attestation boundary that downstream tools like `lanyte-ctx` enforce.

## Current status

CRT-012 implementation checkpoint is in place.

- repo scaffolded as a standalone Rust package
- command-line surface defined for `keygen`, `begin`, `verify`, `end`, and `revoke`
- local path resolution for `~/.lanyte/attest/` implemented
- `keygen` now generates an Ed25519 signing key, encrypts the 32-byte seed with `seclusor-crypto`, and writes key material under the attest root
- public key storage uses base64 text in `signing-key.pub`; private key storage uses age ciphertext in `signing-key.age`
- reusable token mint/verify helpers are implemented with Ed25519 signatures via `seclusor-crypto`
- a public `verify` library surface now exists for downstream consumers, and `cargo check --no-default-features --features verify` passes as the intended consumer boundary
- `verify` now validates JWT shape, signature, expiry, issuer, and optional role/scope expectations, then emits claims as JSON on stdout
- `sessions.db` now tracks active, ended, and revoked sessions through a shared canonical status path used by `verify`, `end`, and `revoke`
- `begin` now mints a token, records session state, and either emits shell export code or execs a child command with `LANYTE_SESSION_TOKEN` set
- `end` and `revoke` now transition tracked sessions in SQLite
- crypto dependency now targets `seclusor-crypto` `v0.1.1`
- issuer trust is now loaded from trusted attestation config at `~/.lanyte/attest/trust.toml`, not runtime env
- `lanyte-ctx` now consumes the shared `verify` API rather than copying token verification logic
- `ctx_hash` is currently a reserved claim with enforced structural shape; consumer-side runtime context matching is not enforced yet

Remaining closeout work is end-to-end proof capture, repo/PR hygiene, and any follow-on UX refinements.

## Install

```sh
cargo build
```

## Commands

```text
lanyte-attest keygen [--output <dir>] [--issuer <instance>]
lanyte-attest begin --role <role> --scope <scope> [--ttl <duration>] [--supervisor <handle>]
lanyte-attest verify <token>
lanyte-attest end
lanyte-attest revoke <jti>
```

## End-to-end proof

Example local proof flow with `lanyte-ctx`:

```sh
# 1. Generate key material + trusted issuer config
cargo run -- keygen --issuer lanyte-attest

# 2. Start an attested session and export the token into the shell
eval "$(cargo run -- begin --role devlead --scope lanytehq --emit-env)"

# 3. Verify the token directly
cargo run -- verify "$LANYTE_SESSION_TOKEN"

# 4. Checkpoint through lanyte-ctx (from ../lanyte-ctx)
(cd ../lanyte-ctx && cargo run -- checkpoint --role devlead --scope lanytehq --file path/to/STATE.json)

# 5. End the session
cargo run -- end

# 6. A later checkpoint with the old token now fails
(cd ../lanyte-ctx && cargo run -- checkpoint --role devlead --scope lanytehq --file path/to/STATE.json)
```

Expected behavior:

- step 3 succeeds and prints claims JSON
- step 4 succeeds and writes only hashed `session_ref`
- step 6 fails because the session is no longer active
