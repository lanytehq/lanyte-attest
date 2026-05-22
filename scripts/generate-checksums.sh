#!/usr/bin/env bash
# Generate SHA-256 checksums.txt over downloaded lanyte-attest binaries.
# Matches the algorithm and filename used by any draft-creation flow
# (CI workflow or manual draft) so an operator's local re-checksum
# independently produces byte-identical content to what shipped.
#
# Filename / hash-algorithm conventions:
#   - checksums.txt (single SHA-256 manifest)
#   - sorted by filename for deterministic ordering
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: generate-checksums.sh <release-dir>

  release-dir  Directory containing lanyte-attest-v*-* binaries

Generates:
  <release-dir>/checksums.txt  — SHA-256 hashes (one line per binary,
                                 sorted by filename)

Example:
  scripts/generate-checksums.sh release/v0.1.0
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
if [ ! -d "$release_dir" ]; then
    echo "error: release dir not found: ${release_dir}" >&2
    exit 1
fi

artifacts=()
while IFS= read -r path; do
    artifacts+=("$path")
done < <(find "$release_dir" -maxdepth 1 -type f -name 'lanyte-attest-v*-*' \
    ! -name '*.minisig' ! -name '*.asc' | sort)

if [ "${#artifacts[@]}" -eq 0 ]; then
    echo "error: no lanyte-attest-v*-* binaries found in ${release_dir}" >&2
    exit 1
fi

(
    cd "$release_dir"
    files=()
    for f in "${artifacts[@]}"; do
        files+=("$(basename "$f")")
    done
    shasum -a 256 "${files[@]}" >checksums.txt
)

echo "[ok] wrote ${release_dir}/checksums.txt (${#artifacts[@]} binaries)"
