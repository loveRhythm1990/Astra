# Repository Automation

This guide records the maintainer-owned GitHub settings that cannot be fully
expressed in the repository. The versioned configuration in
[`.github/mergify.yml`](../../.github/mergify.yml) remains the source of truth
for merge behavior.

## Merge queue contract

Astra uses a serial, in-place Mergify queue with GitHub's strict branch
protection enabled. A pull request enters the queue only after the required
checks and owner approval pass. If `main` advanced, Mergify updates the pull
request and waits for the required checks on the resulting head. If it is
already current, Mergify can reuse its passed checks before squash-merging it.

The queue settings are explicit rather than relying on service defaults:

- `batch_size: 1`, `max_checks_retries: 0`, `mode: serial`, and
  `max_parallel_checks: 1` keep validation on the original pull request.
- `update_method: merge` updates eligible fork branches without rewriting
  their history.
- `branch_protection_injection_mode: queue` makes Mergify enforce GitHub's
  branch-protection requirements when a pull request enters the queue and when
  it merges, while the required check list remains owned by GitHub.

Do not add a separate rule that automatically updates every open pull request.
The queue already updates an approved pull request when necessary. Updating
all stale branches creates avoidable CI runs and writes to contributor forks.

## Required GitHub App access

Mergify requests a fixed permission set for its products. Do not trim that set
to this table: these are the permissions most directly involved in Astra's
queue path. The installation must include `matrixorigin/Astra` in its selected
repository access—or cover all organization repositories—and retain Mergify's
requested permissions, including:

| Permission | Access | Why |
| --- | --- | --- |
| Contents | Read and write | Update the queued branch and merge the pull request |
| Pull requests | Read and write | Inspect approvals and manage queue state |
| Checks | Read and write | Publish queue and rule results |
| Workflows | Read and write | Update a Git ref when the incoming `main` commits include `.github/workflows/*` |
| Administration | Read | Read branch-protection requirements |

The current full permission set and its feature-level rationale are maintained
in [Mergify's security reference](https://docs.mergify.com/security/#github-app-required-permissions).

`Workflows: read and write` does not make workflow changes part of a
documentation pull request. GitHub checks the complete ref update: if `main`
advanced through a workflow change while a pull request was open, merging
`main` into that pull request also carries the workflow commit into its head.
GitHub rejects that ref update unless the app has the Workflows permission.

When Mergify requests new permissions, an organization owner must approve the
installation update. Selecting the permission in the app UI is not sufficient
until the organization installation reports the new effective access.

For a pull request from a personal fork, the author must also select **Allow
edits from maintainers**. GitHub labels this **Allow edits and access to secrets
by maintainers** when the fork contains Actions workflows. This is the author's
security choice; if it is disabled, ask the author to update the branch instead
of bypassing protection. See [GitHub's fork collaboration
guide](https://docs.github.com/en/pull-requests/how-tos/work-with-forks/allowing-changes-to-a-pull-request-branch-created-from-a-fork).

## Protection settings

Keep the following `main` branch-protection invariants aligned with the queue:

- pull requests and the configured approving review are required;
- required status checks are enabled;
- **Require branches to be up to date before merging** remains enabled;
- direct pushes are restricted, with Mergify as the automation app allowed to
  complete reviewed queue merges;
- administrators do not use bypass as the normal delivery path.

Required check names must not begin with `@`. Mergify uses that prefix for a
GitHub-App-qualified check (`@github-actions/<check-name>`), so a required
workflow job named `@astra/sdk ...` cannot be matched by the injected branch
protection condition even when GitHub reports the check as successful. The SDK
job is therefore named `Astra SDK (typecheck, test+coverage, build)`.

When this name changes, update the required status-check list in `main`
branch protection in the same maintenance window: remove
`@astra/sdk (typecheck, test+coverage, build)` and add
`Astra SDK (typecheck, test+coverage, build)`. Keep the old entry until the new
workflow check has appeared once, then remove it so a missing legacy check does
not block every pull request.

After changing the Mergify installation or branch protection, verify the
effective state rather than relying on the settings form:

```bash
gh api repos/matrixorigin/Astra/branches/main/protection \
  --jq '{strict: .required_status_checks.strict,
         mergify: [.restrictions.apps[] | select(.slug == "mergify") |
                    .permissions]}'
```

The result must show `strict: true`; the Mergify permissions must include
`administration: "read"` plus `checks`, `contents`, `pull_requests`, and
`workflows` set to `"write"`. Requeue one approved, behind pull request after
any permission change to exercise the same path external contributors use.

## Failure diagnosis

If a queue entry says that the pull request cannot be updated, classify it
before rerunning CI:

1. A message naming `.github/workflows/...` and missing `workflows` permission
   is an installation-permission failure, not a test failure.
2. A message saying the fork branch cannot be updated without a missing app
   permission can mean maintainer edits are disabled; the author must update
   the branch or opt in.
3. A merge conflict requires the contributor or maintainer to resolve the
   branch; increasing app permissions does not help.
4. A required check failure after Mergify updates the branch is a real CI
   result on the current `main` integration and should be debugged normally.

This separation prevents permission failures from being treated as flaky CI
and keeps external-fork behavior part of the repository's delivery contract.

## Self-hosted macOS tests

Test Suite routes default reader/Bash, dev-tty reader, reflow, workspace
coordination and vendored terminal units by PR author ID. IDs in
`MACOS_RUNNER_AUTHORS` in `scripts/ci/ci_scope.py` use runners matching
`[self-hosted, macOS, ARM64, mac-arm64-mini]`; other or unknown authors use hosted
`macos-15`. The list includes Dependabot. Numeric IDs remain stable across login
renames; login strings in the list are review annotations. The author is
`pull_request.user.id`, not the sender or re-run actor. Pushes on main/develop
also use the self-hosted labels. Existing required-check
names retain their `macos-15` label for compatibility; inspect each job's actual
runner for execution provenance. Linux execution and release workflows retain
their existing platforms.

This uses the ordinary `pull_request`/`push` workflow, GitHub's existing fork
approval and read-only workflow token. No App, organization membership query,
custom result contexts, routing flag or hook is required by this implementation.
If scope output is missing, Mac jobs use hosted `macos-15` and still run tests. The selected runner must be available to Astra, including public
repository access when applicable, and have the exact labels above. Confirm its
OS/toolchain support for the pinned Actions/Rust/Node versions and at least
30 GiB workspace disk before assigning work. CI bootstraps rustup when missing,
adds Cargo binaries to PATH and installs the repository-pinned Rust toolchain.
The shared Rust setup reports low or unreadable disk as a failure on self-hosted runners, without running the
hosted-image sudo cleanup. Approved PR code executes on that
runner when the author is allowlisted; operators accept that persistent-host
access and resource exposure.

One registration executes one job at a time. The five macOS jobs queue on a
single Mac; adding registrations on the same machine changes resource contention
and does not create extra capacity. Reader feature builds remain separate jobs.
For allowlisted PRs and pushes, a busy/offline runner leaves jobs queued; there
is no automatic availability-based hosted fallback.
Measure queue delay and actual job duration before claiming an elapsed-time gain.

If the earlier controller design was staged, remove its unused custom App
required contexts and retire its installed admission hook through the reviewed
operations process; this workflow no longer emits those contexts or App
admissions. Preserve the existing GitHub Actions required checks and fork
approval settings. Roll back execution by reverting the runner selectors in Test
Suite to the hosted matrix OS and `macos-15` coordination runner through a PR.
