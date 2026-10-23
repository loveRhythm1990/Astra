#!/usr/bin/env bash
set -euo pipefail
[ "$(uname -s)" = Darwin ]
[ "$(uname -m)" = arm64 ]
version="$(sw_vers -productVersion)"
[ "${version%%.*}" -ge 15 ]
available="$(df -Pk "$GITHUB_WORKSPACE" | awk 'NR==2 {print $4}')"
[[ "$available" =~ ^[0-9]+$ ]] && [ "$available" -ge 31457280 ]
# Record capacity without host identity, network information or credentials.
printf 'macOS=%s arch=arm64 free_disk_KiB=%s\n' "$version" "$available"
sysctl -n hw.ncpu hw.memsize
rustc --version
