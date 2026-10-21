#!/usr/bin/env python3
"""Exercise core's actual build script with offline Cargo/Git fixtures."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class BuildMetadataTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.repo = self.root / "source"
        self.repo.mkdir()
        # Keep local build overrides, Git configuration, and compiler caches out
        # of the fixture. No network, credentials, or workspace dependencies.
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("ASTRA_", "GIT_", "CARGO_", "RUSTC_"))
            and key not in ("RUSTFLAGS", "RUSTDOCFLAGS", "RUSTUP_TOOLCHAIN")
        }
        self.env.update({
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "CI Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "CI Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "CARGO_TARGET_DIR": str(self.repo / "target"),
            "CARGO_INCREMENTAL": "0",
            "CARGO_NET_OFFLINE": "true",
            "RUSTC_WRAPPER": "",
            "RUSTC_WORKSPACE_WRAPPER": "",
        })
        (self.repo / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["crates/core", "crates/app"]\nresolver = "2"\n'
        )
        shutil.copyfile(ROOT / "rust-toolchain.toml", self.repo / "rust-toolchain.toml")
        (self.repo / ".gitignore").write_text("/target/\n")
        for path in ("README.md", "docs/notes.md", "web/app.js"):
            tracked = self.repo / path
            tracked.parent.mkdir(parents=True, exist_ok=True)
            tracked.write_text("fixture\n")
        for name in ("core", "app"):
            package = self.repo / "crates" / name
            (package / "src").mkdir(parents=True)
            manifest = f'[package]\nname = "fixture_{name}"\nversion = "0.1.0"\nedition = "2024"\n'
            if name == "app":
                manifest += '[dependencies]\nfixture_core = { path = "../core" }\n'
            (package / "Cargo.toml").write_text(manifest)
        shutil.copyfile(ROOT / "crates/core/build.rs", self.repo / "crates/core/build.rs")
        (self.repo / "crates/core/src/lib.rs").write_text('''
pub fn identity() -> [&'static str; 3] {
    [env!("ASTRA_BUILD_GIT_SHA"), env!("ASTRA_BUILD_GIT_DIRTY"),
     env!("ASTRA_BUILD_ATTESTATION_NONCE")]
}
''')
        (self.repo / "crates/app/src/main.rs").write_text('''
fn main() { println!("{:?}", fixture_core::identity()); }
''')
        self.run_command("cargo", "generate-lockfile", "--offline")
        self.git("init", "-b", "main")
        self.git("config", "core.logAllRefUpdates", "false")
        self.git("add", ".")
        self.git("commit", "-m", "fixture")

    def run_command(self, *args):
        result = subprocess.run(args, cwd=self.repo, env=self.env, text=True,
                                capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def git(self, *args):
        return self.run_command("git", *args).stdout.strip()

    def build(self, *, fresh=False, fresh_core=False, expected=None):
        result = self.run_command("cargo", "run", "--locked", "--offline", "--verbose",
                                  "-p", "fixture_app")
        if fresh or fresh_core:
            self.assertIn("Fresh fixture_core", result.stderr)
            self.assertNotIn("Compiling fixture_core", result.stderr)
        if fresh:
            self.assertIn("Fresh fixture_app", result.stderr)
            self.assertNotIn("Compiling fixture_", result.stderr)
        identity = json.loads(result.stdout)
        if expected is not None:
            self.assertEqual(identity, expected)
        return identity

    def test_cold_detached_checkout_reuses_second_and_third_build(self):
        # packed-refs absent reproduces A; present isolates the index refresh B.
        for packed in (False, True):
            with self.subTest(packed=packed):
                source = self.repo
                clone = self.root / f"clone-{packed}"
                self.git("clone", "--no-local", str(source), str(clone))
                self.repo = clone
                self.env["CARGO_TARGET_DIR"] = str(clone / "target")
                try:
                    self.git("checkout", "--detach")
                    if packed:
                        self.git("pack-refs", "--all")
                    else:
                        (clone / ".git/packed-refs").unlink(missing_ok=True)
                    shutil.rmtree(clone / ".git/logs", ignore_errors=True)
                    # Force stale stat data without changing content. Do not run
                    # git status/refresh before Cargo: the build must be read-only
                    # even on the very first checkout build.
                    tracked = clone / "crates/core/src/lib.rs"
                    stat = tracked.stat()
                    os.utime(tracked, ns=(stat.st_atime_ns, stat.st_mtime_ns - 10_000_000_000))
                    index = clone / ".git/index"
                    before = (index.read_bytes(), index.stat().st_mtime_ns)
                    expected = [self.git("rev-parse", "HEAD"), "false", "absent"]
                    self.build(expected=expected)
                    self.assertTrue(
                        (index.read_bytes(), index.stat().st_mtime_ns) == before,
                        "The first build must not rewrite the checkout's index",
                    )
                    self.build(fresh=True, expected=expected)
                    self.build(fresh=True, expected=expected)
                finally:
                    self.repo = source
                    self.env["CARGO_TARGET_DIR"] = str(source / "target")

    def test_packed_symbolic_ref_and_linked_worktree_follow_new_commits(self):
        for linked in (False, True):
            with self.subTest(linked=linked):
                source = self.repo
                if linked:
                    worktree = self.root / "linked"
                    self.git("worktree", "add", "-b", "linked", str(worktree))
                    self.repo = worktree
                    self.env["CARGO_TARGET_DIR"] = str(worktree / "target")
                try:
                    self.git("pack-refs", "--all", "--prune")
                    expected = [self.git("rev-parse", "HEAD"), "false", "absent"]
                    self.build(expected=expected)
                    self.build(fresh=True, expected=expected)
                    # Fetch-like loose remote/tag updates must not invalidate
                    # a packed local branch, including in linked worktrees.
                    remote_sha = self.git("commit-tree", "HEAD^{tree}", "-p", "HEAD", "-m", "remote")
                    for ref in ("refs/remotes/origin/main", "refs/tags/fixture"):
                        for sha in (expected[0], remote_sha):
                            self.git("update-ref", ref, sha)
                            self.build(fresh=True, expected=expected)
                    # Move only the ref (no checkout/index refresh/reflog). This
                    # creates a loose ref for a previously packed branch.
                    new_sha = self.git("commit-tree", "HEAD^{tree}", "-p", "HEAD", "-m", "empty")
                    self.git("update-ref", self.git("symbolic-ref", "HEAD"), new_sha)
                    expected[0] = new_sha
                    self.build(expected=expected)
                    self.build(fresh=True, expected=expected)
                    self.git("pack-refs", "--all", "--prune")
                    self.build(expected=expected)
                    self.build(fresh=True, expected=expected)
                finally:
                    self.repo = source
                    self.env["CARGO_TARGET_DIR"] = str(source / "target")

    def test_detached_head_staged_changes_and_nonce_invalidate_identity(self):
        self.git("checkout", "--detach")
        sha = self.git("rev-parse", "HEAD")
        self.build(expected=[sha, "false", "absent"])
        (self.repo / "tracked.txt").write_text("changed\n")
        self.git("add", "tracked.txt")
        self.build(expected=[sha, "true", "absent"])
        self.build(fresh=True, expected=[sha, "true", "absent"])
        self.git("commit", "-m", "tracked change")
        sha = self.git("rev-parse", "HEAD")
        self.build(expected=[sha, "false", "absent"])
        for nonce in ("a" * 64, "b" * 64, "invalid"):
            self.env["ASTRA_BUILD_ATTESTATION_NONCE"] = nonce
            expected = [sha, "false", nonce if len(nonce) == 64 else "absent"]
            self.build(expected=expected)
            self.build(fresh=True, expected=expected)

    def test_source_archive_keeps_explicit_identity_and_unknown_fallback(self):
        shutil.rmtree(self.repo / ".git")
        for sha, dirty in (("a" * 40, "false"), ("b" * 64, "true"), ("invalid", "invalid")):
            self.env["ASTRA_BUILD_SOURCE_GIT_SHA"] = sha
            self.env["ASTRA_BUILD_SOURCE_GIT_DIRTY"] = dirty
            expected = [sha, dirty, "absent"] if dirty != "invalid" else ["unknown", "true", "absent"]
            self.build(expected=expected)
            self.build(fresh=True, expected=expected)

    def test_non_attested_builds_do_not_rebuild_for_unrelated_tracked_edits(self):
        paths = [self.repo / name for name in ("README.md", "docs/notes.md", "web/app.js")]
        downstream = self.repo / "crates/app/src/main.rs"
        source = downstream.read_text()
        sha = self.git("rev-parse", "HEAD")
        for nonce in (None, "invalid", "g" * 64):
            with self.subTest(nonce=nonce):
                for path in paths:
                    path.write_text("fixture\n")
                downstream.write_text(source)
                if nonce is not None:
                    self.env["ASTRA_BUILD_ATTESTATION_NONCE"] = nonce
                expected = [sha, "false", "absent"]
                self.build(expected=expected)
                for path in paths:
                    path.touch()
                    self.build(fresh=True, expected=expected)
                    path.write_text("first edit\n")
                    self.build(fresh=True, expected=expected)
                    path.write_text("already dirty, edited again\n")
                    self.build(fresh=True, expected=expected)
                downstream.write_text(source + "\n// downstream-only edit\n")
                self.build(fresh_core=True, expected=expected)

    def test_attestation_rechecks_dirty_state_with_the_same_valid_nonce(self):
        sha = self.git("rev-parse", "HEAD")
        self.build(expected=[sha, "false", "absent"])
        readme = self.repo / "README.md"
        readme.write_text("unstaged edit before attestation\n")
        self.build(fresh=True, expected=[sha, "false", "absent"])
        nonce = "a" * 64
        self.env["ASTRA_BUILD_ATTESTATION_NONCE"] = nonce
        self.build(expected=[sha, "true", nonce])
        readme.write_text("fixture\n")
        self.build(expected=[sha, "false", nonce])
        tracked = self.repo / "crates/app/src/main.rs"
        original = tracked.read_text()
        tracked.write_text(original + "\n// local change\n")
        # Reusing an attestation nonce must still detect unstaged downstream
        # edits without git add/status or an index refresh.
        self.build(expected=[sha, "true", nonce])
        self.build(fresh=True, expected=[sha, "true", nonce])
        tracked.write_text(original)
        self.build(expected=[sha, "false", nonce])
        self.build(fresh=True, expected=[sha, "false", nonce])
        tracked = self.repo / ".gitignore"
        original = tracked.read_text()
        tracked.unlink()
        self.build(expected=[sha, "true", nonce])
        tracked.write_text(original)
        self.build(expected=[sha, "false", nonce])
        self.build(fresh=True, expected=[sha, "false", nonce])
        # Leaving attestation mode must remove the broad source watches.
        del self.env["ASTRA_BUILD_ATTESTATION_NONCE"]
        self.build(expected=[sha, "false", "absent"])
        readme.write_text("ordinary development again\n")
        self.build(fresh=True, expected=[sha, "false", "absent"])


if __name__ == "__main__":
    unittest.main()
