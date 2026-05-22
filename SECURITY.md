# Security Policy

`lanyte-attest` mints and verifies signed session tokens for supervised
agent sessions. It holds Ed25519 signing key material (age-encrypted at
rest), enforces an issuer-trust config under HOME-trusted-paths, and is
consumed as a library by downstream tools that gate behavior on its
verification output. We take security issues seriously.

## Reporting a Vulnerability

**Please do not report security vulnerabilities via public GitHub issues.**

Instead, please report them privately to:

- **Email**: security@3leaps.net
- **Preferred contact**: @3leapsdave on GitHub (with "Security Issue" in the subject)

When reporting, please include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigation

We will acknowledge receipt within 48 hours and aim to provide a
timeline for remediation.

## Supported Versions

We provide security updates for the latest stable release and the
active in-development release branch/PR line. Security fixes use
private coordination until disclosure is appropriate.

## Security-Sensitive Pull Requests

Do not put signing-key material, age-encrypted blobs, real session
tokens, real `jti` values, real `sid` values from live deployments, or
trust-config files from operator hosts into public PR text, commit
messages, logs, fixtures, screenshots, or CI artifacts. See
[`REPOSITORY_SAFETY_PROTOCOLS.md`](./REPOSITORY_SAFETY_PROTOCOLS.md)
for the full never-commit list and permission contract.

For changes to key handling, claim validation, JWT minting/verification,
trust-config loading, or the sqlite session lifecycle:

- Run `make pr-final` before pushing a PR branch.
- Request normal correctness review (`devrev`).
- Request security review (`secrev`) before merge.
- Verify errors, logs, and CLI output do not disclose private key
  material, decrypted session secrets, raw JWT payloads from live
  deployments, or operator-host paths.

## Verifying Release Binaries

`lanyte-attest` distributes signed binaries via GitHub Releases. To
verify a download, follow the published procedure in
[`RELEASE_CHECKLIST.md`](./RELEASE_CHECKLIST.md) at the repository root.

The release procedure publishes, alongside each release:

- The release binary for each supported platform
- A checksum file (SHA-256) over the binaries
- A signature file (minisign per-binary + GPG over the checksum manifest)
- The signing public keys with stable fingerprints

The checklist documents the exact verification commands and the
canonical signing-key fingerprints to compare against. Public-key
material attached to releases is the authoritative source; check the
fingerprints against the checked-in expected values
(`keys/expected-fingerprints.txt`) rather than trusting the uploaded
key file alone.

## Trust Boundary

`lanyte-attest`'s runtime trust boundary is the local Unix account.
The attest root (`~/.lanyte/attest/`) holds signing material, trust
config, and the session registry — all under HOME-trusted-paths with
the permission contract documented in
[`REPOSITORY_SAFETY_PROTOCOLS.md`](./REPOSITORY_SAFETY_PROTOCOLS.md).

We do not protect against same-user attackers in local-mode. Any
process running as the owning Unix account can read the attest root
and use the keys exactly as `lanyte-attest` itself does. The
age-encryption-at-rest is a defense against off-box theft of disk
images, not a defense against a co-tenant process. Multi-user /
multi-tenant deployments require a key-broker boundary above
`lanyte-attest` that this crate does not provide.

We do not accept patches that loosen the permission contract or
silently degrade trust posture inside local-mode.

## Security-Issue Classes

The following are considered `lanyte-attest` security issues. Please
report them via the channel above:

- **Signing-key leaks in commits, logs, or error output.** Private key
  material, decrypted seed bytes, age ciphertext, or passphrase
  material appearing in repository content, CI artifacts, or runtime
  logs.
- **Trust-config tampering paths.** Any code path that reads
  `trust.toml` from somewhere other than the HOME-trusted-paths root,
  or that loads issuer trust state from an unauthenticated env var,
  CLI arg, or working-directory file.
- **Claim-validation bypass.** A `verify` code path that returns
  success for a token with an invalid signature, expired `exp`,
  unknown `iss`, or otherwise out-of-policy claims.
- **JWT replay against ended/revoked sessions.** A path where `verify`
  succeeds for a token whose `(sid, jti)` is in `sessions.db` with
  status `ended` or `revoked`.
- **Permission-mask regressions.** Changes that loosen the directory
  or file permission contract on the attest root, `trust.toml`,
  `signing-key.age`, or `sessions.db`.
- **Age-encryption regression.** A change that writes signing material
  in cleartext, weakens the cipher choice, or removes the `zeroize`
  contract on in-memory private-key lifetimes.
- **Library-surface trust regression.** A change that exposes a public
  API which lets a downstream consumer accept an unverified token
  while believing it has been verified.

## Upstream Dependencies

`lanyte-attest` depends on:

- [`seclusor-crypto`](https://github.com/3leaps/seclusor) — Ed25519
  signing + age-encryption-at-rest. Linked as a library; no shelling
  out.
- [`rusqlite`](https://crates.io/crates/rusqlite) (bundled) — session
  registry storage.
- [`zeroize`](https://crates.io/crates/zeroize) — memory hygiene on
  private-key lifetimes.

We monitor these projects for security updates. The release procedure
runs cargo-audit + cargo-deny against the crate before tagging; known
unmaintained-but-non-exploitable advisories are documented in
`deny.toml` if any apply.

## Disclosure Policy

We follow responsible disclosure:

- We work with reporters to understand and fix the issue.
- We publish patches as soon as reasonably possible.
- We credit reporters in the release notes (unless anonymity is requested).

Thank you for helping keep `lanyte-attest` and its users secure.
