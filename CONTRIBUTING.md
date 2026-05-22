# Contributing to lanyte-attest

Thanks for helping build **lanyte-attest** — the session attestation
CLI and library for supervised Lanyte agent sessions.

This repo aims to be:

- **agent-first** (the daily user is an autonomous agent issuing
  tokens for itself or a child process; human operators are a
  secondary audience),
- **cross-platform** (Linux + macOS today; Windows when the install
  convention proves out),
- **license-clean** (dual MIT OR Apache-2.0, no copyleft dependencies),
- **public-readable** (every committed file, including this one, is
  written assuming a public adopter is the reader).

If you are new to `lanyte-attest` as an operator or downstream
consumer, start at [`README.md`](./README.md). This file covers the
contributor's side.

## Quick start (contributors)

1. Install Rust and the repo toolchain (MSRV is **1.85.0**):

   - `rustup toolchain install 1.85.0`
   - `rustup component add rustfmt clippy`

2. Run the full local quality loop:

   - `cargo fmt --all`
   - `cargo clippy --all-targets -- -D warnings`
   - `cargo test --all-targets`

   Or use the Makefile:

   - `make pr-final` — CI-exact final gate before pushing a PR branch
   - `make check` — fast loop (fmt + clippy + test)
   - `make install` — installs the release binary into `$LOCAL_BIN`
     (default `~/.local/bin` on Linux/macOS,
     `$USERPROFILE\bin` on Windows)

## Repo layout

```
.
├── src/
│   ├── lib.rs              public library + run() entry
│   ├── main.rs             binary wrapper (cli feature)
│   ├── cli.rs              clap surface
│   ├── token.rs            JWT mint / verify / claim model
│   ├── verify.rs           public verify-feature API (downstream consumer boundary)
│   ├── key_material.rs     Ed25519 keygen, age encryption at rest
│   ├── trust.rs            trust.toml loader + issuer policy
│   ├── session_registry.rs sqlite session lifecycle (active/ended/revoked)
│   ├── paths.rs            HOME-trusted-paths root resolution
│   ├── naming.rs           role / scope / sid / jti naming policy
│   └── error.rs            typed error envelope
├── docs/                   user-facing and contributor-facing documentation
│   └── decisions/          ADRs / decision records
├── scripts/                release-cycle helpers (sign / verify / upload / etc.)
└── tests/                  integration tests (if present)
```

## Feature flags

`lanyte-attest`'s downstream-consumer boundary is the `verify` feature
on its own:

- `cargo check --no-default-features --features verify`

This is the surface `stashvoy` consumes. The `issue` and `cli`
features pull in additional crates (clap, rpassword, env_logger) and
the mint-side code paths. Library consumers should depend on
`lanyte-attest` with `default-features = false, features = ["verify"]`.

## Branching model

All feature work happens on branches and lands via pull requests.

### Branch naming

- `feat/<slug>` — new features
- `fix/<slug>` — bug fixes
- `docs/<slug>` — documentation changes
- `chore/<slug>` — build, CI, dependency updates
- `release/<vX.Y.Z>` — release-cycle prep PRs

For automation-driven work (LLM-assisted agents), prefer the
role-prefixed shape `<type>/<slug>-<role>-<YYYYMMDD>` (e.g.,
`release/v0.1.0-alfa-devlead-20260521`). This is the convention used
by the supervised-commit chain that drives much of this repository's
work.

### Workflow

1. Create a branch from `main`
2. Develop and commit locally
3. Run `make pr-final`
4. Push the feature branch to origin
5. Open a PR against `main` (`gh pr create`)
6. CI runs automatically on the PR (once `.github/workflows/check.yml` lands)
7. Address review feedback
8. Merge after required review and green CI

## Commit attribution

`lanyte-attest` is built by a mix of human contributors and supervised
AI agents. Both follow the same attribution shape — commits land
under the supervising human's git identity, with the agent identified
in the trailer block:

```
Role: <role-slug>
Committer-of-Record: @<human-supervisor-handle>

Co-authored-by: <Model Name> (<Agentic Tool>) <noreply@lanytehq.dev>
```

For human-only contributions, the `Role:` and `Committer-of-Record:`
lines are optional; the `Co-authored-by:` line is the load-bearing
attribution.

The same convention applies to PR bodies — agent-drafted PRs include
a `Drafted-By: <Model Name> (<Agentic Tool>)` line at the bottom for
provenance. Human-drafted PRs need no special footer.

See [`AGENTS.md`](./AGENTS.md) for the agent-session conventions on
top of this baseline.

## Test discipline

Tests should exercise the real `lanyte-attest` library and binary
against synthetic key material in a temporary directory. Use
[`tempfile`](https://crates.io/crates/tempfile) for the attest root;
never write to the real `~/.lanyte/attest/` from a test.

When adding tests:

- Use synthetic role / scope / supervisor identifiers (`role-test`,
  `scope-test`, `@test-supervisor`).
- Mint keys per-test inside a `tempfile::TempDir`; never commit
  precomputed key material.
- Use `--ttl 30s` or similarly short TTLs for verify-then-expire
  flows; do not commit tokens whose `exp` reaches into a real time
  window.
- Never commit fixtures that contain real signing material, real
  `sid` values, real `jti` values, or real trust-config files. See
  [`REPOSITORY_SAFETY_PROTOCOLS.md`](./REPOSITORY_SAFETY_PROTOCOLS.md)
  for the never-commit list.

## Reviewer routing

Reviewer routing for `lanyte-attest` work follows the role-shaped
review chain established across lanytehq repos:

- **devrev** — correctness, test discipline, CLI surface shape
- **secrev** — security-sensitive changes (key handling, claim
  validation, JWT minting/verification, trust-config loading, session
  registry lifecycle, age-encryption surface)
- **entarch** — architectural changes (public types in the `verify`
  library surface, JWT claim shape, trust-config schema, session
  registry schema, downstream-consumer contract surfaces)

Smaller changes only need devrev. Because `lanyte-attest`'s entire
surface area is security-load-bearing, secrev review is the default
for anything that touches `src/token.rs`, `src/verify.rs`,
`src/key_material.rs`, `src/trust.rs`, or `src/session_registry.rs`.
Reviewer pings are by GitHub handle; the maintainer (`@3leapsdave`)
is the final merge gate.

## Code of conduct

We commit to a respectful, welcoming environment for everyone:
contributors, users, agent operators, downstream adopters, and
security researchers.

Be respectful. Critique work, not people. Disagreement is fine;
hostility, harassment, and discrimination are not — and will be
treated as conduct issues regardless of the technical content of the
disagreement.

If you experience or witness behavior that conflicts with this
posture, contact the maintainer (`@3leapsdave` on GitHub, or via the
private channel documented in [`SECURITY.md`](./SECURITY.md) for
serious matters).

A formal `CODE_OF_CONDUCT.md` (likely the Contributor Covenant) may
land if real-world governance need surfaces; until then, the
paragraph above is the operative posture.

## Reporting a security issue

Please report security issues privately. See
[`SECURITY.md`](./SECURITY.md) for the reporting path, response SLA,
and disclosure policy.

## Further reading

- [`README.md`](./README.md) — project overview, status, quick start
- [`AGENTS.md`](./AGENTS.md) — agent-session conventions
- [`REPOSITORY_SAFETY_PROTOCOLS.md`](./REPOSITORY_SAFETY_PROTOCOLS.md) — never-commit list, permission contract
- [`SECURITY.md`](./SECURITY.md) — vulnerability reporting + verification
- [`RELEASE_CHECKLIST.md`](./RELEASE_CHECKLIST.md) — release-cycle procedure
- [`docs/decisions/`](./docs/decisions/) — ADRs / decision records
