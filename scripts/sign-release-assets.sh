#!/usr/bin/env bash
# Produce minisign + GPG signatures over lanyte-attest release assets.
#
# Signature model:
#   - minisign signs each binary individually (one .minisig per binary)
#     → external operators can verify any single download
#   - GPG signs checksums.txt (single .asc over the manifest)
#     → operators can verify the whole asset set via the manifest
#
# Signing keys are NEVER in CI. The manual-signing baseline is:
# the release author runs this locally; the keys have passphrases;
# nothing touches GHA runners.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: sign-release-assets.sh <release-tag> <release-dir>

  release-tag   GitHub release tag (e.g., v0.1.0)
  release-dir   Directory containing lanyte-attest binaries + checksums.txt

Environment:
  LANYTE_ATTEST_MINISIGN_KEY   Path to minisign secret key (required)
  LANYTE_ATTEST_PGP_KEY_ID     GPG key ID for checksums.txt signature
                               (required — GPG signature over the manifest
                               is mandatory for the lanytehq trust posture)
  LANYTE_ATTEST_GPG_HOMEDIR    Optional GPG homedir override

Produces:
  <release-dir>/lanyte-attest-v*-*.minisig   one per binary (minisign)
  <release-dir>/checksums.txt.asc            single (GPG over the manifest)

Example:
  LANYTE_ATTEST_MINISIGN_KEY=~/.minisign/lanyte-attest.key \
  LANYTE_ATTEST_PGP_KEY_ID=ABC123... \
    scripts/sign-release-assets.sh v0.1.0 release/v0.1.0
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    usage
    exit 0
fi

if [ "$#" -ne 2 ]; then
    usage >&2
    exit 1
fi

release_tag="$1"
release_dir="$2"
minisign_key="${LANYTE_ATTEST_MINISIGN_KEY:-}"
pgp_key_id="${LANYTE_ATTEST_PGP_KEY_ID:-}"
gpg_homedir="${LANYTE_ATTEST_GPG_HOMEDIR:-}"

if [ -z "$minisign_key" ]; then
    echo "error: LANYTE_ATTEST_MINISIGN_KEY is required" >&2
    exit 1
fi

if [ -z "$pgp_key_id" ]; then
    echo "error: LANYTE_ATTEST_PGP_KEY_ID is required" >&2
    echo "       GPG signature over checksums.txt is mandatory for the" >&2
    echo "       lanytehq release trust posture." >&2
    exit 1
fi

if ! command -v minisign >/dev/null 2>&1; then
    echo "error: minisign is required" >&2
    exit 1
fi

if ! command -v gpg >/dev/null 2>&1; then
    echo "error: gpg is required" >&2
    exit 1
fi

if [ ! -f "${release_dir}/checksums.txt" ]; then
    echo "error: missing ${release_dir}/checksums.txt" >&2
    echo "       run 'make release-checksums' first" >&2
    exit 1
fi

# minisign each binary individually.
binaries=()
while IFS= read -r path; do
    binaries+=("$path")
done < <(find "$release_dir" -maxdepth 1 -type f -name 'lanyte-attest-v*-*' \
    ! -name '*.minisig' ! -name '*.asc' | sort)

if [ "${#binaries[@]}" -eq 0 ]; then
    echo "error: no lanyte-attest-v*-* binaries found in ${release_dir}" >&2
    exit 1
fi

for binary in "${binaries[@]}"; do
    minisign -S -s "$minisign_key" -m "$binary" -x "${binary}.minisig"
done

# GPG sign checksums.txt (manifest-level signature). Mandatory.
gpg_args=(--batch --yes --armor --local-user "$pgp_key_id")
if [ -n "$gpg_homedir" ]; then
    gpg_args+=(--homedir "$gpg_homedir")
fi
gpg "${gpg_args[@]}" \
    --output "${release_dir}/checksums.txt.asc" \
    --detach-sign "${release_dir}/checksums.txt"

echo "[ok] signed ${#binaries[@]} binaries + checksums.txt manifest for ${release_tag}"
