# lanyte-attest Release Checklist

Canonical step-by-step procedure for cutting a `vX.Y.Z` lanyte-attest
release. This file lives at the repo root and is **public-readable**
so external adopters can verify a downloaded binary against the stable
key fingerprints below without needing org access.

Release model: **manual signing**, mirroring the lanytehq + 3leaps
Rust-crate convention.
- A draft GitHub release is produced on tag push — for v0.1.0 the
  draft is created manually (see §6); a CI `release.yml` workflow is
  a planned follow-on.
- The release author runs `make release-download` → `release-sign` →
  `release-verify` → `release-upload` → `release-undraft` **locally**.
- Signing keys never touch CI.

Canonical release sequence (top-to-bottom; each numbered section
below corresponds to one step):

```
make release-prep       → release-preflight
git tag → git push      → draft release created (manual or CI)
make release-download   → release-checksums → release-export-keys
make release-sign       → release-verify
make release-upload     → release-undraft
release announcement → #ops-updates note
```

---

## 1. Pre-release verification

- [ ] All feature PRs for this release are merged to `main`
- [ ] `main` CI is green
- [ ] Working tree is clean (`git status` empty)
- [ ] `VERSION` matches `Cargo.toml` version (`make version-check`)
- [ ] Release notes exist at `docs/releases/vX.Y.Z.md` (must inline
      fingerprints + verification commands OR hard-pointer to this file)
- [ ] All planned briefs / PRs for this release are at "done" status

## 2. `make release-prep` (commit-cycle gate)

Runs the full per-PR gate plus license / security / SBOM scans.

```bash
make release-prep
```

Expects: `pr-final ✓` (clippy + tests + MSRV `--locked` + workflow-lint),
`license-check ✓`, `security-scan ✓` (0 high / 0 critical), SBOM
generated under `sbom/`.

## 3. `make release-preflight` (pre-tag readiness gate)

Pre-tag, non-draft-dependent gate. Validates clean tree, version sync,
no conflicting tag/release, tooling on PATH, signing keys present.

```bash
export LANYTE_ATTEST_MINISIGN_KEY=/path/to/minisign-secret-key
export LANYTE_ATTEST_PGP_KEY_ID=ABC123...
make release-preflight
```

Checks (each fails fast with a clear hint):
- `make release-prep` green
- Working tree clean (`git status` empty)
- `VERSION` + `Cargo.toml` consistent
- No conflicting `vX.Y.Z` tag locally OR on origin
- No published GitHub release for this version
- `gh`, `minisign`, `gpg` available on PATH
- `LANYTE_ATTEST_MINISIGN_KEY` set and points at an existing file
- `LANYTE_ATTEST_PGP_KEY_ID` set and present in the GPG keyring
  (GPG signature over `checksums.txt` is mandatory for the lanytehq
  trust posture)
- `docs/releases/vX.Y.Z.md` exists

**This step does NOT inspect a draft release** — none exists yet.
Post-draft checks live in §6 `release-download` + §7 `release-verify`.

## 4. Tag push

Only proceed if §2 / §3 are green.

```bash
VERSION=$(cat VERSION)
git tag -a "v${VERSION}" -m "v${VERSION}"
git push origin "v${VERSION}"
```

## 5. Draft release creation

Until a CI `release.yml` lands, drafts are created manually. Build
the binaries locally with `--locked` and the release profile, then
publish to a draft GitHub release.

```bash
VERSION=$(cat VERSION)
TAG="v${VERSION}"

# 5.1 — Build locally (single platform for v0.1.0; multi-platform
#        matrix lands when CI workflow is added)
make build-release

# 5.2 — Rename the built binary to the platform-tagged convention
#        used by sign / verify / upload scripts. Adjust the arch
#        suffix to your build host (e.g., macos-aarch64, linux-x86_64,
#        linux-aarch64).
mkdir -p "release/${TAG}"
cp target/release/lanyte-attest "release/${TAG}/lanyte-attest-${TAG}-$(uname -s | tr 'A-Z' 'a-z')-$(uname -m)"

# 5.3 — Create the draft release with notes from docs/releases/
gh release create "${TAG}" \
  --repo lanytehq/lanyte-attest \
  --draft \
  --title "lanyte-attest ${TAG}" \
  --notes-file "docs/releases/${TAG}.md"

# 5.4 — Attach the binary to the draft (signing happens in §7)
gh release upload "${TAG}" --repo lanytehq/lanyte-attest \
  "release/${TAG}/lanyte-attest-${TAG}-"*
```

> **CI follow-on**: when the `release.yml` workflow lands (planned
> follow-on after v0.1.0), §5 collapses to "push tag, monitor `gh run
> watch`," and the binary-build + draft-create steps above are
> superseded.

## 6. `make release-download`

Pull the draft assets into the local working directory consumed by
the rest of the flow. This is idempotent and works whether the draft
was created in §5 manually or by a future CI workflow.

```bash
make release-download    # writes release/vX.Y.Z/
```

## 7. Local signing flow

All steps run locally. Idempotent: any step can be re-run safely.

```bash
# 7.1 — Regenerate checksums.txt locally (must byte-match what
#        the source draft produced)
make release-checksums

# 7.2 — Export public signing keys into the release dir
make release-export-keys

# 7.3 — Sign: minisign per binary + GPG over checksums.txt
make release-sign

# 7.4 — Verify signatures AND that exported public-key files
#        match keys/expected-fingerprints.txt
make release-verify

# 7.5 — Attach signed artifacts + public keys to the draft
#        release (atomic — does NOT flip draft state)
make release-upload

# 7.6 — Flip the GitHub release from draft → published
#        (atomic — does NOT touch assets)
make release-undraft

# Or, the composite for the end-to-end publish step:
# make release-upload-all
```

If any step fails, fix the underlying issue and re-run. Don't skip
ahead with a half-signed release.

## 8. Release announcement

Post the release-published notice to the appropriate lanytehq channel.
Include:
- Release URL
- SHA-256 checksums (top of `release/vX.Y.Z/checksums.txt`)
- The verification commands from §10 below
- Download URLs for each binary

## 9. `#ops-updates` note

Post the operational notification to `#ops-updates`. If a per-tool
version-notes pin convention exists for this repo, follow it (unpin
the prior version's note first, then pin the new one).

---

## 10. Verification commands for external adopters

These commands run **after** download from the published GitHub
release. No lanyte-attest clone or org access required — keys +
signatures are attached to the release.

```bash
# Verify a downloaded binary against its minisign signature
minisign -Vm lanyte-attest-vX.Y.Z-linux-x86_64 -p lanyte-attest-minisign.pub

# Verify the checksums manifest against the GPG signature
gpg --verify checksums.txt.asc checksums.txt

# Verify the downloaded binary matches the checksum in the manifest
sha256sum -c checksums.txt --ignore-missing
```

### Stable key fingerprints

External adopters should pin against these fingerprints. They change
only via a documented key-rotation announcement.

| Algorithm | Fingerprint |
|---|---|
| minisign | `TBD — pinned at impl time once lanytehq keypair is provisioned` |
| GPG | `TBD — pinned at impl time once lanytehq keypair is provisioned` |

The same values are checked into `keys/expected-fingerprints.txt` so
`make release-verify-keys` asserts an exported
`lanyte-attest-minisign.pub` /
`lanyte-attest-release-signing-key.asc` matches them.

---

## Troubleshooting

### `release-preflight` fails on "VERSION ($A) != Cargo.toml ($B)"
Run `make version-sync` to bring `Cargo.toml` in line with `VERSION`,
or `make version-set V=X.Y.Z` to set both atomically.

### `release-preflight` fails on "LANYTE_ATTEST_MINISIGN_KEY not set" or "LANYTE_ATTEST_PGP_KEY_ID not set"
Source the env file that exports your signing-key paths. Both are
mandatory for the lanytehq trust posture — silent skip of GPG would
let a release ship without manifest-level authenticity:
```bash
export LANYTE_ATTEST_MINISIGN_KEY=$HOME/.minisign/lanyte-attest-secret.key
export LANYTE_ATTEST_PGP_KEY_ID=ABC123...
```

### `release-verify-keys` fails on "TBD placeholder"
The expected fingerprints in `keys/expected-fingerprints.txt` are
still the pre-provisioning placeholders. Fill in the real values
after the lanytehq release-signing keypair is provisioned, and
cross-reference the same values into the §10 fingerprint table above
in the same PR.

### `release-checksums` fails on "no lanyte-attest-v*-* binaries found"
You ran the target before `make release-download` populated the
working dir, or `RELEASE_DIR` is pointing at a different path.
Default: `release/v$(cat VERSION)/`.

### `release-upload-all` partially failed
The atomic split means you can re-run just the failing half:
- `make release-upload` re-attaches assets (idempotent via `--clobber`)
- `make release-undraft` re-flips draft state (idempotent — no-op if
  already published)
