#!/usr/bin/env bash
# Export public signing keys into the release working directory so
# `verify-public-keys.sh` and `verify-signatures.sh` can consume them,
# and so `upload-release-assets.sh` can attach them to the GitHub draft
# release (operators with no lanyte-attest context can verify a download
# using the keys + commands from RELEASE_CHECKLIST.md).
#
# Public material only. Never touches private keys.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: export-release-keys.sh <release-dir>

  release-dir  Directory to write lanyte-attest-minisign.pub and
               lanyte-attest-release-signing-key.asc into

Environment:
  LANYTE_ATTEST_MINISIGN_PUB  Path to minisign public key
                              (copied verbatim to <release-dir>/lanyte-attest-minisign.pub)
  LANYTE_ATTEST_PGP_KEY_ID    GPG key ID to export
                              (written ASCII-armored to lanyte-attest-release-signing-key.asc)
  LANYTE_ATTEST_GPG_HOMEDIR   Optional GPG homedir override

Example:
  LANYTE_ATTEST_MINISIGN_PUB=keys/lanyte-attest-minisign.pub \
  LANYTE_ATTEST_PGP_KEY_ID=ABC123... \
    scripts/export-release-keys.sh release/v0.1.0
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    usage
    exit 0
fi

if [ "$#" -ne 1 ]; then
    usage >&2
    exit 1
fi

release_dir="$1"
mkdir -p "$release_dir"

minisign_pub="${LANYTE_ATTEST_MINISIGN_PUB:-}"
pgp_key_id="${LANYTE_ATTEST_PGP_KEY_ID:-}"
gpg_homedir="${LANYTE_ATTEST_GPG_HOMEDIR:-}"

if [ -n "$minisign_pub" ]; then
    if [ ! -f "$minisign_pub" ]; then
        echo "error: minisign public key not found at ${minisign_pub}" >&2
        exit 1
    fi
    cp "$minisign_pub" "${release_dir}/lanyte-attest-minisign.pub"
    echo "[ok] exported lanyte-attest-minisign.pub"
else
    echo "[--] LANYTE_ATTEST_MINISIGN_PUB not set; skipping minisign public key export"
fi

if [ -n "$pgp_key_id" ]; then
    if ! command -v gpg >/dev/null 2>&1; then
        echo "error: gpg is required when LANYTE_ATTEST_PGP_KEY_ID is set" >&2
        exit 1
    fi
    gpg_args=(--armor --export "$pgp_key_id")
    if [ -n "$gpg_homedir" ]; then
        gpg_args=(--homedir "$gpg_homedir" "${gpg_args[@]}")
    fi
    gpg "${gpg_args[@]}" >"${release_dir}/lanyte-attest-release-signing-key.asc"
    echo "[ok] exported lanyte-attest-release-signing-key.asc"
else
    echo "[--] LANYTE_ATTEST_PGP_KEY_ID not set; skipping GPG public key export"
fi
