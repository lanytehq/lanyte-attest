# AI Agent Guide — lanyte-attest

Start every session with:

1. `/Users/davethompson/dev/lanytehq/AGENTS.md`
2. `/Users/davethompson/dev/lanytehq/lanyte-crucible/docs/guides/dev-warmup.md`
3. This repo's `REPOSITORY_SAFETY_PROTOCOLS.md`

## Working rules

- This repo is standalone. Do not add dependencies on any crate in `/Users/davethompson/dev/lanytehq/lanyte`.
- Follow CRT-012 at `/Users/davethompson/dev/lanytehq/lanyte-productbook-internal/content/projmgmt/core-runtime/CRT-012-session-attestation.md`.
- Follow ADR-0012 stdout purity: stdout is only for programmatic output; diagnostics go to stderr.
- Keep the CLI synchronous (`rusqlite`, no `tokio`).
- Keep Rust MSRV at `1.85.0`.
- Treat crypto and secret-handling changes as security-sensitive and pause for four-eyes review at working checkpoints.
