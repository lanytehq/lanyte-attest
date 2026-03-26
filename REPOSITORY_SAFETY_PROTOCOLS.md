# REPOSITORY SAFETY PROTOCOLS

This repository handles session attestation, signing keys, and provenance checks. Treat it as security-sensitive.

## Never Commit

- secrets (API keys, tokens, credentials)
- private signing keys or decrypted signing seeds
- real passphrases or passphrase files
- customer data / PII

## Core Constraints

- Use `seclusor-crypto` for age encryption and Ed25519 signing rather than building a parallel crypto stack.
- Do not leak token values, signing-key bytes, or decrypted plaintext in logs or error messages.
- Stdout is reserved for programmatic output only; diagnostics and confirmations go to stderr.
- `lanyte-attest` remains standalone and must not depend on crates from `/Users/davethompson/dev/lanytehq/lanyte`.

## Required Reviews

- Pause for four-eyes review after working checkpoints with passing tests.
- Escalate to `secrev` for crypto boundary or secret-handling changes.
- Escalate to `entarch` if the reusable verification API for downstream consumers changes materially.
