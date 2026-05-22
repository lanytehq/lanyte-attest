#!/usr/bin/env bash
# Verify minisign + GPG signatures on release assets locally before
# upload. Run by `make release-verify-signatures`; composite gate
# `make release-verify` chains this with verify-public-keys.sh.
#
# Verification model:
#   - For each lanyte-attest-v*-* binary, expect a .minisig and verify
#     against the bundled lanyte-attest-minisign.pub
#   - For checksums.txt, expect a .asc and verify against the GPG
#     keyring (or LANYTE_ATTEST_GPG_HOMEDIR override)
#
# Fails on any missing signature or mismatch.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: verify-signatures.sh <release-dir>

  release-dir  Directory containing binaries + signatures + lanyte-attest-minisign.pub

Environment:
  LANYTE_ATTEST_MINISIGN_PUB   Path to minisign public key
                               (default: <release-dir>/lanyte-attest-minisign.pub)
  LANYTE_ATTEST_GPG_HOMEDIR    Optional GPG homedir override

Example:
  scripts/verify-signatures.sh release/v0.1.0
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
minisign_pub="${LANYTE_ATTEST_MINISIGN_PUB:-${release_dir}/lanyte-attest-minisign.pub}"
gpg_homedir="${LANYTE_ATTEST_GPG_HOMEDIR:-}"

if [ ! -f "$minisign_pub" ]; then
    echo "error: minisign public key not found at ${minisign_pub}" >&2
    exit 1
fi

if ! command -v minisign >/dev/null 2>&1; then
    echo "error: minisign is required" >&2
    exit 1
fi

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
    sig="${binary}.minisig"
    if [ ! -f "$sig" ]; then
        echo "error: missing minisign signature ${sig}" >&2
        exit 1
    fi
    minisign -V -p "$minisign_pub" -m "$binary" -x "$sig"
done

# GPG signature over checksums.txt is MANDATORY for the lanytehq trust
# posture. External-adopter verification relies on both minisign-per-binary
# AND `gpg --verify checksums.txt.asc`; an opt-out path would let a
# release ship without manifest-level authenticity.
asc="${release_dir}/checksums.txt.asc"
if [ ! -f "$asc" ]; then
    echo "error: missing GPG signature over checksums.txt: ${asc}" >&2
    echo "       run 'make release-sign' with LANYTE_ATTEST_PGP_KEY_ID set" >&2
    exit 1
fi
if ! command -v gpg >/dev/null 2>&1; then
    echo "error: gpg is required to verify ${asc}" >&2
    exit 1
fi
gpg_args=(--verify "$asc" "${release_dir}/checksums.txt")
if [ -n "$gpg_homedir" ]; then
    gpg_args=(--homedir "$gpg_homedir" "${gpg_args[@]}")
fi
gpg "${gpg_args[@]}"

echo "[ok] signature verification passed (${#binaries[@]} binaries + checksums.txt manifest)"
