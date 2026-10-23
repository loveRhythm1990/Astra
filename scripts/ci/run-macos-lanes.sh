#!/usr/bin/env bash
# Canonical commands shared by hosted jobs and the protected migration workflow.
set -euo pipefail
lane="${1:?lane required}"
lane_workspace="$PWD"
observe_git() {
  python3 - "$lane_workspace" <<'PYTHON'
import os, subprocess, sys, time
started = time.monotonic()
subprocess.run(["/usr/bin/git", "-C", sys.argv[1], "-c", "core.fsmonitor=false",
                "-c", "core.untrackedCache=false", "rev-parse", "--show-toplevel"],
    env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C",
         "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
         "GIT_CONFIG_SYSTEM": os.devnull, "GIT_OPTIONAL_LOCKS": "0",
         "GIT_TERMINAL_PROMPT": "0"}, check=True, timeout=60)
print(f"System Git observation initialized in {time.monotonic() - started:.3f}s")
PYTHON
}
case "$lane" in
  default-reader)
    cargo test --locked -p astra-cli --lib tui::terminal_startup -- --test-threads=2
    if [ "$(uname -s)" = Darwin ]; then
      observe_git
      cargo test --locked --manifest-path Cargo.toml -p astra-cli \
        --lib edge_tools::shell::tests::bash_echo_returns_output -- --exact
    fi
    ;;
  reflow)
    cargo build --locked -p astra-cli --bin astra
    npm ci --ignore-scripts --prefix scripts/tui-reflow
    ASTRA_TEST_BINARY="${CARGO_TARGET_DIR:-$PWD/target}/debug/astra" npm test --prefix scripts/tui-reflow
    ;;
  coordination)
    cargo clippy --locked --manifest-path Cargo.toml -p astra-tools --all-targets -- -D warnings
    observe_git
    cargo test --locked --manifest-path Cargo.toml -p astra-tools \
      workspace_observation::tests:: -- --test-threads=1
    ;;
  all)
    bash "$0" default-reader
    bash "$0" reflow
    bash "$0" coordination
    ;;
  *) echo "Unknown macOS lane" >&2; exit 2 ;;
esac
