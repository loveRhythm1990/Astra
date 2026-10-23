#!/usr/bin/env python3
"""Trusted macOS routing, admission and result publication (stdlib only).

No PR artifacts or shell-provided success results are used as evidence. The
same policy is installed read-only outside the runner account for job hooks.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import signal
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ci_scope import classify

REPO = "matrixorigin/Astra"
WORKFLOW = ".github/workflows/macos-trusted.yml"
WORKFLOW_REF = f"{REPO}/{WORKFLOW}@refs/heads/main"
CONTEXTS = ("Mac CI: default reader", "Mac CI: reflow", "Mac CI: coordination")
SHA = re.compile(r"^[0-9a-f]{40}$")
AUTHORIZATION_SECONDS = 3 * 60 * 60
HINT_WAIT_SECONDS = 90
SOURCE_ATTEMPTS = 12
RECOVERY_COOLDOWN_SECONDS = 30 * 60
HOSTED_LANES = ("default-reader", "reflow", "coordination")


class Unavailable(Exception):
    pass


class MergePending(Unavailable):
    pass


class StaleSource(Unavailable):
    pass


class PermissionDenied(Unavailable):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class API:
    def __init__(self, token):
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(self, path, data=None, method=None):
        if not path.startswith("/") or path.startswith("//"):
            raise Unavailable("invalid API path")
        req = urllib.request.Request("https://api.github.com" + path,
            data=None if data is None else json.dumps(data).encode(), method=method,
            headers={"Authorization": f"Bearer {self.token}",
                     "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28",
                     "Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=20) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            return error.code, None  # Never print provider responses or credentials.
        except (OSError, ValueError):
            raise Unavailable("GitHub API unavailable") from None

    def get(self, path):
        status, value = self.request(path)
        if status in (401, 403):
            raise PermissionDenied("API permission unavailable")
        if status != 200:
            raise Unavailable(f"GitHub API returned {status}")
        return value

    def pages(self, path, key=None):
        result = []
        for page in range(1, 101):
            value = self.get(path + ("&" if "?" in path else "?") + f"per_page=100&page={page}")
            rows = value[key] if key else value
            result.extend(rows)
            if len(rows) < 100:
                return result
        raise Unavailable("API pagination limit")


def member(api, login):
    if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", login):
        return False
    # A configured Members:read credential is required, including private members.
    try:
        return api.request(f"/orgs/matrixorigin/members/{login}")[0] == 204
    except Unavailable:
        return False


def pr_identity(api, number, expected_head=None):
    pr = api.get(f"/repos/{REPO}/pulls/{int(number)}")
    if (pr["state"] != "open" or pr["base"]["repo"]["full_name"] != REPO
            or pr["base"]["ref"] != "main"):
        raise Unavailable("PR is not an open main pull request")
    base = api.get(f"/repos/{REPO}/git/ref/heads/main")["object"]["sha"]
    head = pr["head"]["sha"]
    if not all(isinstance(s, str) and SHA.fullmatch(s) for s in (base, head)):
        raise Unavailable("invalid base/head revision")
    if expected_head is not None and head != expected_head:
        raise StaleSource("trigger head has been superseded")
    return {"kind": "pr", "pr": int(number), "base": base, "head": head,
            "merge": pr.get("merge_commit_sha"), "head_repository_id": pr["head"]["repo"]["id"],
            "author": pr["user"]["login"], "author_id": pr["user"]["id"]}


def source(api, number, *, attempts=1, expected_head=None):
    # GitHub computes the test merge asynchronously. Re-read the entire tuple on
    # each retry, never substitute a head from a newer synchronize event.
    for attempt in range(attempts):
        plan = pr_identity(api, number, expected_head)
        merge = plan["merge"]
        if isinstance(merge, str) and SHA.fullmatch(merge):
            status, commit = api.request(f"/repos/{REPO}/git/commits/{merge}")
            if status in (401, 403):
                raise PermissionDenied("merge API permission unavailable")
            if status == 200 and [p["sha"] for p in commit["parents"]] == [plan["base"], plan["head"]]:
                return plan
            if status not in (200, 404):
                raise Unavailable("merge API unavailable")
        if attempt + 1 < attempts:
            time.sleep(2)
    raise MergePending("merge revision not ready for current base/head")


def same_source(a, b):
    return all(a.get(k) == b.get(k) for k in
        ("kind", "pr", "base", "head", "merge", "head_repository_id", "author_id"))


def selected(api, plan):
    try:
        diff = api.get(f"/repos/{REPO}/compare/{plan['base']}...{plan['merge']}")
        files = diff.get("files")
        if files is None or len(files) >= 300:
            return True  # GitHub truncates compare's file inventory at 300.
        paths = [name for f in files for name in (f["filename"], f.get("previous_filename")) if name]
        scope = classify(paths)
        return scope["test_cli"] or scope["test_core"]
    except (Unavailable, KeyError, TypeError):
        return True


def require_check_sources(api, app_id):
    environment = api.get(f"/repos/{REPO}/environments/astra-macos-control")
    policy = environment.get("deployment_branch_policy") or {}
    if policy != {"protected_branches": False, "custom_branch_policies": True}:
        raise Unavailable("control environment must select only the main branch")
    branches = api.pages(f"/repos/{REPO}/environments/astra-macos-control/deployment-branch-policies", "branch_policies")
    if len(branches) != 1 or branches[0].get("name") != "main" or branches[0].get("type") != "branch":
        raise Unavailable("control environment allows an untrusted branch or tag")
    required = {}
    up_to_date = False
    for rule in api.get(f"/repos/{REPO}/rules/branches/main"):
        if rule["type"] == "required_status_checks":
            up_to_date |= rule["parameters"].get("strict_required_status_checks_policy") is True
            for check in rule["parameters"]["required_status_checks"]:
                required[check["context"]] = check.get("integration_id")
    status, protection = api.request(f"/repos/{REPO}/branches/main/protection")
    if status == 200:
        protected_checks = protection.get("required_status_checks") or {}
        up_to_date |= protected_checks.get("strict") is True
        for check in protected_checks.get("checks", []):
            required[check["context"]] = check.get("app_id")
    elif status != 404:
        raise Unavailable("cannot verify required-check source binding")
    if not up_to_date:
        raise Unavailable("main must require checks on an up-to-date branch")
    if any(required.get(name) != app_id for name in CONTEXTS):
        raise Unavailable("three Mac CI checks must be required from the dedicated App")


def group_ready(api, group_id, kind):
    group = api.get(f"/orgs/matrixorigin/actions/runner-groups/{int(group_id)}")
    if (group["name"] != f"astra-macos-{kind}" or not group.get("restricted_to_workflows")
            or group.get("selected_workflows") != [WORKFLOW_REF]
            or group.get("visibility") != "selected" or not group.get("allows_public_repositories")):
        raise Unavailable("runner group is not restricted to the protected workflow")
    repos = api.pages(f"/orgs/matrixorigin/actions/runner-groups/{group_id}/repositories", "repositories")
    if [r["full_name"] for r in repos] != [REPO]:
        raise Unavailable("runner group must select only Astra")
    runners = api.pages(f"/orgs/matrixorigin/actions/runner-groups/{group_id}/runners", "runners")
    labels = {"self-hosted", "macOS", "ARM64", "mac-arm64-mini", "astra-macos-admitted"}
    return any(r["status"] == "online" and not r["busy"] and
               labels <= {label["name"] for label in r["labels"]} for r in runners)


def checks(api, head):
    return api.pages(f"/repos/{REPO}/commits/{head}/check-runs", "check_runs")


def save_checks(api, plan, conclusion=None, summary="Awaiting verified execution", *, only_pending=False):
    existing = {name: [] for name in CONTEXTS}
    for check in checks(api, plan["head"]):
        if check["name"] in existing and check.get("app", {}).get("id") == plan["app_id"]:
            existing[check["name"]].append(check)
    for name in CONTEXTS:
        data = {"name": name, "head_sha": plan["head"],
                "external_id": f"astra-macos-v1:{plan['run_id']}:{plan['head']}",
                "status": "completed" if conclusion else "in_progress",
                "output": {"title": summary, "summary": summary, "text": json.dumps(plan, sort_keys=True)}}
        if conclusion:
            data["conclusion"] = conclusion
        previous = max(existing[name], key=lambda c: c["id"], default=None)
        if previous:
            if only_pending and previous["status"] == "completed":
                continue
            try:
                old = json.loads(previous["output"]["text"])
                if (old["run_id"], old["attempt"]) > (plan["run_id"], plan["attempt"]):
                    continue  # A late publisher cannot overwrite newer control.
                reuse = old["run_id"] == plan["run_id"] and old["attempt"] == plan["attempt"]
            except (ValueError, KeyError, TypeError):
                reuse = False
        else:
            reuse = False
        if reuse:
            data.pop("head_sha")
            status, _ = api.request(f"/repos/{REPO}/check-runs/{previous['id']}", data, "PATCH")
            expected = 200
        else:
            status, _ = api.request(f"/repos/{REPO}/check-runs", data)
            expected = 201
        if status != expected:
            raise Unavailable("could not publish dedicated App checks")


def authorization(api, head, run_id, app_id):
    found = {}
    for check in checks(api, head):
        if check["name"] not in CONTEXTS or check.get("app", {}).get("id") != app_id:
            continue
        try:
            plan = json.loads(check["output"]["text"])
        except (KeyError, TypeError, ValueError):
            continue
        if plan.get("schema") == 1 and plan.get("run_id") == run_id and plan.get("head") == head:
            if check["name"] not in found or found[check["name"]][0] < check["id"]:
                found[check["name"]] = (check["id"], plan)
    if len(found) != len(CONTEXTS):
        raise Unavailable("no complete App authorization")
    plans = [p for _, p in found.values()]
    if any(p != plans[0] for p in plans):
        raise Unavailable("inconsistent App authorization")
    return plans[0]


def validate_run(api, plan, attempt=None):
    run = api.get(f"/repos/{REPO}/actions/runs/{int(plan['run_id'])}")
    expected_events = ("pull_request_target", "workflow_dispatch") if plan["kind"] == "pr" else ("push",)
    if (run["event"] not in expected_events or run["path"] != WORKFLOW
            or run["repository"]["full_name"] != REPO
            or (attempt is not None and run["run_attempt"] != attempt)):
        raise Unavailable("unexpected workflow, repository, event or attempt")
    return run


def expired(plan):
    deadline = plan.get("expires_at")
    return not isinstance(deadline, int) or time.time() >= deadline


def require_unexpired(plan):
    if expired(plan):
        raise Unavailable("authorization expired; start fresh trusted control")


def refresh(api, plan):
    require_unexpired(plan)
    if plan["kind"] == "pr":
        identity = pr_identity(api, plan["pr"])
        if not same_source(identity, plan) or not member(api, identity["author"]):
            raise StaleSource("source changed or membership is not confirmed")
        try:
            current = source(api, plan["pr"])
        except MergePending:
            raise StaleSource("merge no longer matches current base/head") from None
        if not same_source(current, plan):
            raise StaleSource("source advanced during refresh")
    else:
        head = api.get(f"/repos/{REPO}/git/ref/heads/main")["object"]["sha"]
        if plan["head"] != head:
            raise StaleSource("main has advanced")


def admit(api, request, config):
    # Invoked by a root-owned job-started hook under a distinct credential owner.
    # No caller-supplied token, path, repository, API URL or command is accepted.
    if set(request) != {"run_id", "attempt", "head"} or not SHA.fullmatch(request["head"]):
        raise Unavailable("invalid admission request")
    plan = authorization(api, request["head"], int(request["run_id"]), int(config["app_id"]))
    if plan["route"] != "self-hosted" or plan["kind"] != config["kind"]:
        raise Unavailable("authorization is for another execution boundary")
    if int(config["group_id"]) != plan["group_id"]:
        raise Unavailable("runner group differs from the authorized group")
    group_ready(api, int(config["group_id"]), config["kind"])
    validate_run(api, plan, int(request["attempt"]))
    refresh(api, plan)  # Fresh private-membership check on every actual attempt.
    jobs = api.pages(f"/repos/{REPO}/actions/runs/{plan['run_id']}/attempts/{request['attempt']}/jobs", "jobs")
    if not any(j["name"] == "Migrated macOS lanes" and j["status"] == "in_progress"
               and j["runner_name"] == config["runner_name"]
               and j["runner_group_id"] == int(config["group_id"]) for j in jobs):
        raise Unavailable("no matching active job on the admitted runner")
    return plan


def verified_job(api, plan, name):
    run = validate_run(api, plan)
    jobs = api.pages(f"/repos/{REPO}/actions/runs/{run['id']}/jobs?filter=latest", "jobs")
    matching = [j for j in jobs if j["name"] == name]
    if len(matching) != 1:
        return "failure" if run.get("status") == "completed" else None
    job = matching[0]
    if job["conclusion"] != "success":
        return job["conclusion"] if job["status"] == "completed" else None
    steps = {s["name"]: s["conclusion"] for s in job["steps"]}
    expected_step = "Run all three macOS lanes" if name == "Migrated macOS lanes" else "Run macOS lane"
    if steps.get(expected_step) != "success":
        return "failure"
    if name.startswith("Fallback macOS:") and "macos-15" not in job.get("labels", []):
        return "failure"
    if name == "Migrated macOS lanes" and job["runner_group_id"] != plan["group_id"]:
        return "failure"
    return "success"


def can_fallback(api, plan):
    if plan["route"] == "hosted":
        return True
    jobs = api.pages(f"/repos/{REPO}/actions/runs/{plan['run_id']}/jobs?filter=latest", "jobs")
    primary = [j for j in jobs if j["name"] == "Migrated macOS lanes"]
    return (len(primary) == 1 and primary[0]["conclusion"] == "failure" and not any(
        s["name"] == "Run all three macOS lanes" and s["conclusion"] not in (None, "skipped")
        for s in primary[0]["steps"]))


def hosted_result(api, plan):
    runs = api.pages(f"/repos/{REPO}/actions/workflows/test.yml/runs?event=pull_request&head_sha={plan['head']}", "workflow_runs")
    for run in sorted(runs, key=lambda r: r["id"], reverse=True):
        if run["head_repository"]["id"] != plan["head_repository_id"]:
            continue
        refs = run.get("pull_requests", [])
        if not any(p["number"] == plan["pr"] and p["head"]["sha"] == plan["head"]
                   and p["base"]["sha"] == plan["base"] for p in refs):
            continue
        jobs = api.pages(f"/repos/{REPO}/actions/runs/{run['id']}/jobs?filter=latest", "jobs")
        wanted = {"Terminal: default-reader (macos-15)", "Terminal: reflow (macos-15)",
                  "macOS workspace coordination contracts"}
        actual = {j["name"]: j for j in jobs if j["name"] in wanted}
        if set(actual) != wanted or any(j["status"] != "completed" for j in actual.values()):
            # A completed run cannot later gain skipped/missing lane execution.
            return "failure" if run["status"] == "completed" else None
        return "success" if all(j["conclusion"] == "success" and "macos-15" in j["labels"]
                                 for j in actual.values()) else "failure"
    return None


def outputs(values):
    with open(os.environ["GITHUB_OUTPUT"], "a") as out:
        for key, value in values.items():
            out.write(f"{key}={json.dumps(value, separators=(',', ':')) if isinstance(value, dict) else value}\n")


def plan_command(api, event, app_id):
    if os.environ["GITHUB_REPOSITORY"] != REPO:
        raise Unavailable("wrong repository")
    require_check_sources(api, app_id)
    kind = "main" if os.environ["GITHUB_EVENT_NAME"] == "push" else "pr"
    unresolved = False
    if kind == "pr":
        number = event.get("number") or event.get("inputs", {}).get("pr_number")
        expected_head = event.get("pull_request", {}).get("head", {}).get("sha")
        try:
            plan = source(api, number, attempts=SOURCE_ATTEMPTS, expected_head=expected_head)
        except MergePending:
            plan = pr_identity(api, number, expected_head)
            plan["merge"] = ""
            unresolved = True
        trusted = member(api, plan["author"])
    else:
        head = event["after"]
        if event["ref"] != "refs/heads/main" or not SHA.fullmatch(head):
            raise Unavailable("unexpected push")
        plan = {"kind": "main", "pr": 0, "base": event["before"], "head": head, "merge": head}
        trusted = os.environ.get("ASTRA_MACOS_MAIN_ISOLATED") == "true"
    plan.update(schema=1, run_id=int(os.environ["GITHUB_RUN_ID"]), app_id=app_id,
                attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]), route="ordinary", group_id=0,
                expires_at=int(time.time()) + AUTHORIZATION_SECONDS)
    if unresolved:
        plan.update(route="unresolved", retryable=True)
        save_checks(api, plan, "failure", "Merge revision not ready; trusted reconciliation will retry")
    elif not selected(api, plan):
        plan["route"] = "unaffected"
        save_checks(api, plan, "success", "Canonical scope does not select these lanes")
    elif trusted:
        plan["route"] = "hosted"
        group_id = os.environ.get("ASTRA_MACOS_GROUP_ID" if kind == "pr" else "ASTRA_MACOS_MAIN_GROUP_ID", "")
        if os.environ["GITHUB_EVENT_NAME"] != "workflow_dispatch" and group_id.isdecimal():
            try:
                if group_ready(api, int(group_id), kind):
                    plan.update(route="self-hosted", group_id=int(group_id))
            except Unavailable:
                pass  # A member still receives protected hosted execution.
        save_checks(api, plan)
    elif kind == "pr":
        save_checks(api, plan)
    else:
        plan["route"] = "disabled"  # Keep main hosted until isolation is accepted.
    outputs({"plan": plan, "route": plan["route"], "merge": plan["merge"], "kind": kind})


def hint(api, event, app_id):
    if event.get("pull_request"):
        if event["pull_request"].get("base", {}).get("ref") != "main":
            return False
    elif event.get("ref") != "refs/heads/main":
        return False
    head = event.get("pull_request", {}).get("head", {}).get("sha") or event.get("after")
    number = event.get("number", 0)
    if not isinstance(head, str) or not SHA.fullmatch(head):
        return False
    deadline = time.monotonic() + HINT_WAIT_SECONDS
    for _ in range(HINT_WAIT_SECONDS // 2 + 1):
        try:
            rows = checks(api, head)
            run_ids = {int(c["external_id"].split(":")[1]) for c in rows
                       if c.get("app", {}).get("id") == app_id
                       and c.get("external_id", "").startswith("astra-macos-v1:")}
            for run_id in sorted(run_ids, reverse=True):
                plan = authorization(api, head, run_id, app_id)
                if plan["pr"] != number:
                    continue
                require_unexpired(plan)
                if plan["route"] in ("unresolved", "recovering"):
                    return False
                validate_run(api, plan)
                if number and not same_source(plan, source(api, number)):
                    continue
                # Once trusted control has chosen ordinary hosted execution,
                # there is no reason to keep delaying a non-member's scope job.
                if plan["route"] in ("ordinary", "unaffected", "disabled", "unresolved", "recovering"):
                    return False
                if plan["route"] in ("self-hosted", "hosted"):
                    return True
        except PermissionDenied:
            print("::notice::Mac CI hint lacks API access; retaining hosted execution.")
            return False
        except (Unavailable, ValueError, KeyError):
            pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(2, remaining))
    print("::notice::Mac CI routing hint unavailable within budget; retaining hosted execution.")
    return False


def finish(api, plan):
    if plan["route"] in ("disabled", "unaffected", "unresolved", "recovering"):
        return True
    require_unexpired(plan)
    try:
        if plan["route"] == "ordinary":
            if plan["kind"] != "pr" or not same_source(plan, pr_identity(api, plan["pr"])):
                raise StaleSource("hosted result is stale")
            try:
                current = source(api, plan["pr"])
            except MergePending:
                raise StaleSource("hosted merge is stale") from None
            if not same_source(current, plan):
                raise StaleSource("hosted source advanced during refresh")
            if member(api, plan["author"]):
                raise StaleSource("author now qualifies for protected execution")
            result = hosted_result(api, plan)
        else:
            refresh(api, plan)
            primary = verified_job(api, plan, "Migrated macOS lanes") if plan["route"] == "self-hosted" else None
            if primary == "success" or not can_fallback(api, plan):
                result = primary
            else:
                lanes = [verified_job(api, plan, "Fallback macOS: " + lane) for lane in HOSTED_LANES]
                result = (None if any(r is None for r in lanes) else
                          "success" if all(r == "success" for r in lanes) else "failure")
    except StaleSource:
        # Failure, rather than neutral/skipped, keeps required checks fail-closed.
        save_checks(api, {**plan, "retryable": True}, "failure",
                    "Stale macOS source or trust; trusted reconciliation will request fresh control")
        return True
    if result is not None:
        observed = {**plan, "attempt": validate_run(api, plan)["run_attempt"]}
        save_checks(api, observed, "success" if result == "success" else "failure", "Verified macOS execution: " + result)
        return True
    return False


def recover(api, pr, app_id, previous=None):
    """Only the protected metadata controller may dispatch fixed main control.

    A non-authorizing marker bounds duplicate dispatches (including lost API
    responses). A later real plan supersedes it by run id. No execution evidence
    or member authorization is manufactured here.
    """
    try:
        current = source(api, pr["number"], expected_head=pr["head"]["sha"])
    except MergePending:
        current = pr_identity(api, pr["number"], pr["head"]["sha"])
        marker = {**current, "schema": 1, "app_id": app_id, "run_id": 0,
                  "attempt": 0, "route": "unresolved", "group_id": 0,
                  "retryable": True, "expires_at": int(time.time()) + AUTHORIZATION_SECONDS}
        save_checks(api, marker, "failure", "Merge revision not ready; trusted reconciliation will retry")
        return
    if (previous and same_source(previous, current) and
            time.time() - previous.get("recovery_requested_at", 0) < RECOVERY_COOLDOWN_SECONDS):
        return
    marker = {**current, "schema": 1, "app_id": app_id,
              "run_id": previous["run_id"] if previous else 0,
              "attempt": previous["attempt"] if previous else 0,
              "route": "recovering", "group_id": 0, "retryable": True,
              "recovery_requested_at": int(time.time()),
              "expires_at": int(time.time()) + AUTHORIZATION_SECONDS}
    save_checks(api, marker, summary="Requesting fresh protected Mac CI control")
    # A real plan may have appeared since the scan. Do not dispatch over it.
    latest = {}
    for row in checks(api, current["head"]):
        if row["name"] in CONTEXTS and row.get("app", {}).get("id") == app_id:
            if row["name"] not in latest or row["id"] > latest[row["name"]]["id"]:
                latest[row["name"]] = row
    if any(json.loads(row["output"]["text"]) != marker for row in latest.values()):
        return
    status, _ = api.request(f"/repos/{REPO}/actions/workflows/macos-trusted.yml/dispatches",
                            {"ref": "main", "inputs": {"pr_number": str(pr["number"])}})
    if status not in (200, 204):
        raise Unavailable("could not request fresh trusted control")


def reconcile(api, app_id):
    """Recover absent plans/stale sources; close expired or lost results."""
    require_check_sources(api, app_id)
    prs = api.pages(f"/repos/{REPO}/pulls?state=open&base=main")
    for pr in prs:
        try:
            rows = checks(api, pr["head"]["sha"])
            latest = {}
            for row in rows:
                if row["name"] in CONTEXTS and row.get("app", {}).get("id") == app_id:
                    if row["name"] not in latest or row["id"] > latest[row["name"]]["id"]:
                        latest[row["name"]] = row
            if not latest:
                recover(api, pr, app_id)
                continue
            plan = json.loads(max(latest.values(), key=lambda c: c["id"])["output"]["text"])
            if (plan["schema"] != 1 or plan["app_id"] != app_id or plan["kind"] != "pr"
                    or plan["head"] != pr["head"]["sha"] or plan["pr"] != pr["number"]):
                continue
            if plan.get("retryable"):
                recover(api, pr, app_id, plan)
            elif len(latest) == len(CONTEXTS) and all(c["status"] == "completed" for c in latest.values()):
                continue
            elif expired(plan):
                save_checks(api, plan, "failure",
                    "Mac CI authorization expired; resolve approval/runner state and start fresh Mac CI control",
                    only_pending=True)
            else:
                finish(api, plan)
        except (Unavailable, KeyError, TypeError, ValueError):
            # Other PRs still get reconciliation during a transient per-PR failure.
            print("::notice::A pending Mac CI result could not be reconciled; no success published.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("plan", "hint", "finish", "refresh", "admit", "observe", "reconcile"))
    parser.add_argument("--plan")
    parser.add_argument("--config")
    args = parser.parse_args()
    try:
        if args.command == "admit":
            signal.alarm(90)  # Hooks themselves have no GitHub timeout.
            config = json.loads(Path(args.config).read_text())
            api = API(Path(config["token_file"]).read_text().strip())
            request = sys.stdin.read(4097)
            if len(request) > 4096:
                raise Unavailable("admission request too large")
            admit(api, json.loads(request), config)
            print("Runner admission accepted")
            return 0
        api = API(os.environ["GH_TOKEN"])
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        app_id = int(os.environ["ASTRA_MACOS_APP_ID"])
        if args.command == "plan":
            plan_command(api, event, app_id)
        elif args.command == "hint":
            outputs({"delegated": str(hint(api, event, app_id)).lower()})
        elif args.command == "reconcile":
            reconcile(api, app_id)
        elif args.command == "observe":
            run = api.get(f"/repos/{REPO}/actions/runs/{int(event['workflow_run']['id'])}")
            if run["event"] != "pull_request" or run["path"] != ".github/workflows/test.yml":
                return 0
            for pr in api.get(f"/repos/{REPO}/commits/{run['head_sha']}/pulls"):
                if pr["head"]["sha"] != run["head_sha"]:
                    continue
                current = source(api, pr["number"])
                rows = checks(api, current["head"])
                plans = []
                for row in rows:
                    if row.get("app", {}).get("id") == app_id and row["name"] == CONTEXTS[0]:
                        try:
                            p = json.loads(row["output"]["text"])
                            if p["route"] == "ordinary" and same_source(p, current):
                                plans.append((row["id"], p))
                        except (KeyError, TypeError, ValueError):
                            pass
                if plans:
                    finish(api, max(plans, key=lambda p: p[0])[1])
        else:
            plan = json.loads(args.plan)
            if args.command == "finish":
                finish(api, plan)
            else:
                refresh(api, plan)
                # Failed-only reruns cannot reuse a hosted authorization job.
                if int(os.environ["GITHUB_RUN_ATTEMPT"]) != plan["attempt"]:
                    raise Unavailable("rerun all jobs for a fresh hosted admission")
                outputs({"allowed": str(can_fallback(api, plan)).lower()})
        return 0
    except (Unavailable, KeyError, ValueError, TypeError, OSError):
        print("::error::Mac CI admission/result unavailable; retain hosted checks or rerun trusted control. No success published.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
