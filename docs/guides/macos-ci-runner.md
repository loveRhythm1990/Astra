# Self-hosted macOS CI

This guide owns the rollout of the three Mac CI lanes tracked in
[issue #1106](https://github.com/matrixorigin/Astra/issues/1106).
The implementation is opt-in. A merged workflow is not evidence that the Mac
is configured, admitted, compatible, or faster than hosted runners.

## Workload and routing

The migrated unit runs default-reader PTYs and the CLI Bash regression, reflow,
and workspace coordination. It runs sequentially on one runner and reuses its
build directory. This avoids scheduling three simultaneous Rust builds on a
single small machine. The canonical commands live in
`scripts/ci/run-macos-lanes.sh` and are shared with ordinary hosted CI.

| Event | Execution |
| --- | --- |
| Confirmed matrixorigin member PR, current verified merge, admitted idle Mac | Self-hosted ARM Mac |
| Confirmed member, Mac unavailable or admission/platform failure before tests | Protected hosted macOS fallback |
| Non-member, membership API failure, or unknown identity | Ordinary `pull_request` hosted workflow |
| Main push before isolated main account is accepted | Ordinary hosted workflow |
| Main push with accepted separate main account/group | Admitted main Mac runner; protected hosted fallback |
| Other branches/events | Existing hosted routing |

macOS dev-tty and vendored terminal units remain hosted, as do Linux and release
builds. Path selection calls the existing `ci_scope.classify` on the verified
base-to-merge comparison. Unknown/truncated comparisons select the lanes.

A PR author is identified by the actual GitHub PR record, including user ID.
Only `GET /orgs/matrixorigin/members/{author}` returning 204 qualifies. The
credential must see private membership. Fork ownership, actor, association and
public profiles are not substituted. Qualifying members vouch for their PR's
contents, including collaborators' changes; this does not prove every writer is
a member.

## Control and required results

`macos-trusted.yml` is base-owned `pull_request_target` control. Only confirmed
members execute PR code through that event. The controller independently reads
the current base B, head H and merge M and requires exactly two ordered parents
`M^1=B` and `M^2=H`. It checks out immutable M. Null/stale merges, force-pushes,
base advancement or changed repository identity cannot silently select another
revision.

A dedicated GitHub App publishes three contexts on H:

- `Mac CI: default reader`
- `Mac CI: reflow`
- `Mac CI: coordination`

All three must be required with their source bound to that App. Control checks
this source binding before dispatch. Its private key and installation token
remain on GitHub-hosted Ubuntu control jobs, never on PR execution machines.
Store the private key only in the `astra-macos-control` GitHub Environment,
restricted by a custom branch rule to branch `main` alone (no tag rule).
Do not duplicate it as a repository/organization secret: same-repository PRs
could otherwise request it. PR refs and feature-branch dispatches must be denied
by the environment policy. Control verifies that exact policy before dispatch.
The publisher reads actual GitHub run/job/step results; it does not accept PR
artifacts or shell-supplied success flags. A successful combined job satisfies
all three contexts; any actual test failure fails them conservatively.

The ordinary `pull_request` workflow reads App-owned authorization as a
best-effort deduplication hint. Delegated copies use cheap Ubuntu notification
jobs. The hint cannot publish or replace the three required App checks. Missing
hints preserve hosted execution, so a control race can cause duplicate work,
not missing coverage. A forged hint leaves the member's trusted checks pending.

Non-members retain ordinary fork approval. `macos-results.yml` observes the
completed Test Suite through `workflow_run`, reads GitHub metadata only, and
publishes the ordinary path's actual three hosted results. It never downloads
artifacts or executes PR code. Approval-pending, missing, stale, cancelled or
failed execution cannot become a successful skip. This retains the pre-existing
PR-modifiable test-definition limitation for non-member hosted tests.

Both privileged-event workflows explicitly restrict remote cache tokens with
`cache-mode: read` or `none`. Disabling a client upload is not the authorization
boundary. Actionlint 1.7.12 does not parse this GitHub-supported key: the config
filters only that exact unsupported-key diagnostic for these two files. Other
workflow errors remain checked. Remove that narrow filter when actionlint gains
support. See [GitHub cache permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#cache-mode).

## Mandatory runner-side admission

Use a dedicated `astra-macos-pr` group, selecting only Astra, allowing its public
repository, restricted to exactly:

```text
matrixorigin/Astra/.github/workflows/macos-trusted.yml@refs/heads/main
```

Remove every unrestricted registration/path to this same execution identity.
Labels and repository restrictions alone do not protect against PR YAML changing
`runs-on`. The group must enforce the workflow and protected ref. If the actual
GitHub plan cannot enforce that restriction, do not enable this design.

Runner labels are `self-hosted`, `macOS`, `ARM64`, `mac-arm64-mini` and
`astra-macos-admitted`. Add the last label only after admission and acceptance
have actually passed. The runner's physical name/location is not part of the
public configuration.

Install a root-owned job-started hook before accepting jobs. The PR runner must
be a non-admin account named `astra-ci-pr` without general sudo rights. A
separate non-login `astra-ci-admission` account owns a read-only API credential
with private Members read, organization runners/groups read, Actions read,
contents/pull-request/checks read. It must not publish checks or write contents.
No credential is readable by the runner account.

Install these reviewed files outside all runner-writable paths:

| Source | Root-owned destination |
| --- | --- |
| `scripts/ci/macos_runner.py`, `scripts/ci/ci_scope.py` | `/opt/astra-ci/lib/` |
| `scripts/ci/macos-runner-admit` | `/opt/astra-ci/bin/admit` |
| `scripts/ci/macos-job-started.sh` | `/opt/astra-ci/bin/job-started.sh` |
| `scripts/ci/macos-runner-preflight.sh` | `/opt/astra-ci/bin/preflight` |

Use a root-managed Python 3.11+ installation at `/opt/astra-ci/python`, with no
runner-writable executable, library or parent directory. The small hook itself
uses system Python for JSON only; the policy helper uses isolated Python mode.
The fixed sudo target accepts no command arguments and selects a root-owned
policy by sudo's verified invoking user, not by JSON supplied by a PR. Configure
sudoers for exactly this command with no arguments and no environment override:

```text
astra-ci-pr ALL=(astra-ci-admission) NOPASSWD: /opt/astra-ci/bin/admit ""
```

No general shell, Python, environment-preserving sudo, or arbitrary config-path
invocation is permitted. Protect every installed parent directory and config.
Set `ACTIONS_RUNNER_HOOK_JOB_STARTED=/opt/astra-ci/bin/job-started.sh` in the runner's
service environment, then restart that runner through its reviewed operations
process. Changing repository YAML does not install this hook.

Example `/etc/astra-ci/pr.json` (root-owned, readable only by admission owner):

```json
{
  "app_id": 12345,
  "kind": "pr",
  "group_id": 123,
  "runner_name": "<registered runner name>",
  "token_file": "/etc/astra-ci/admission-token"
}
```

The helper has a 90-second deadline; the hook client also bounds the privileged
subprocess at 100 seconds. The `.sh` extension on the installed hook is required
by GitHub's hook launcher.

The helper reads the publisher App's authorization from GitHub, validates the
actual workflow/repository/event/current attempt and active job on the expected
runner/group, rechecks the current tuple and private membership, and only then
admits. This runs for individual and failed-only reruns even when the previous
hosted router job was successful. Caller-controlled JSON cannot supply policy,
credentials, an API host or an arbitrary command. Hook rejection fails the job;
the workflow separately authorizes hosted handoff.

## Host state and platform acceptance

Keep main hosted by default. PR job artifacts/npm cache use a private per-run
scratch directory and are removed afterward. Persistent user state, including
HOME, Cargo/rustup, tool binaries, Git config/helpers, keychains, launchd agents,
background processes and writable shares, is still under the PR account's trust.
A clean checkout or scratch target does not erase those effects.

Prefer disposable VMs per job. To enable main migration, use an independently
installed runner under a different non-admin OS account `astra-ci-main`, separate
home/toolchain/caches, and group `astra-macos-main` with the same workflow/ref
restriction. Provide `/etc/astra-ci/main.json` with kind `main`, the main runner
name/group, and add only the same fixed sudo command for that account. Two runner
registrations under the same OS account do not qualify: the fixed helper maps
the PR identity only to PR policy. Validate filesystem/process isolation and
harmless pollution sentinels for all state above before accepting main. Separate
accounts retain shared-kernel/host compromise risk; they are not disposable VMs.

The installed preflight requires macOS 15+, native ARM64 and at least 30 GiB
free on the workspace filesystem. It records OS, CPU count, RAM and free disk
without host identity. A machine name containing `macos-13` is not proof of its
current OS. Upgrade/replace an older installation through its normal reviewed
process before assigning the admission label. Preinstall the repository's pinned
Rust toolchain, Node/action runtime dependencies and working system Git. The
runner must support the current `cache-mode` token enforcement.

Before rollout measure cold/warm full-lane runs, queue delay, peak RSS/disk and
competing work. Start with one registration and serial combined execution;
do not multiply runner processes to hide capacity issues. Record acceptable
queue p50/p95 and job duration limits against observed PR arrival bursts. These
measurements have not been performed by the application PR.

An online/idle API observation is not a reservation. A runner can disappear
between dispatch and start; queued self-hosted work remains pending. An operator
can cancel the stale run and use `workflow_dispatch` with its PR number for a
fresh protected hosted run. That dispatch always selects hosted execution.
Failed-only hosted retries are refused when they reuse an older successful
admission job; rerun all jobs for new hosted authorization. Membership revocation
or a stale tuple blocks privileged-event execution; a fresh plan can choose the
ordinary approved hosted path. Genuine test failures are never hidden by the
infrastructure fallback.

## Enable, verify and roll back

1. Merge the reviewed implementation while migration remains disabled.
2. Configure the dedicated publisher App, groups, isolated credential owner,
   root-owned hook/helper and platform described above. Validate direct-label
   bypass, fork/member/unknown routing, revoked-member reruns, tuple changes,
   cache write denial, pollution isolation and capacity on disposable fixtures.
3. Create GitHub Environment `astra-macos-control`, allowing only branch `main`
   via its custom deployment branch policy, with no allowed tags or wildcards.
   After verifying that PR refs and feature dispatches cannot access it, store
   `ASTRA_MACOS_APP_PRIVATE_KEY` only as that environment's secret. Set repository
   variable `ASTRA_MACOS_APP_ID` and `ASTRA_MACOS_GROUP_ID` to the App/PR group IDs.
   The App needs repository Actions/contents/PR read, administration read,
   checks write and environments read; organization Members and self-hosted
   runners/groups read.
4. Make the three contexts required with source pinned to the App. Preserve the
   existing protected checks. The migration control refuses dispatch until this
   binding is visible through the rules/protection APIs.
5. Set `ASTRA_MACOS_MIGRATION_ENABLED=true` only after the preceding acceptance.
   For main, separately set `ASTRA_MACOS_MAIN_GROUP_ID` and
   `ASTRA_MACOS_MAIN_ISOLATED=true` after its isolation acceptance.
6. Verify actual job runner names/groups and reduced hosted Mac jobs. Record
   hosted displacement, Mac execution and total elapsed time independently.

Activation needs organization/repository administration and runner-host access.
The application PR does not modify live groups, secrets, branch protection,
remote clusters or runner services. Current caller API queries for runners and
groups returned 403; none of those settings is claimed verified or enabled.

For rollback, keep required result publication working until in-flight PRs are
settled. Remove the three new App-required contexts through reviewed policy
change, disable `ASTRA_MACOS_MIGRATION_ENABLED`, then remove/disable the admitted
runner registration as needed. Ordinary hosted execution is retained throughout
when no valid delegation hint exists. Do not turn missing App results into pass.
