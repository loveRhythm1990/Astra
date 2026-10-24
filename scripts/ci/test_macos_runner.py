#!/usr/bin/env python3
"""Exercise routing/admission against GitHub-shaped API data and real shell dispatch."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import macos_runner as m
from test_release_build_shells import workflow_run_script

ROOT = Path(__file__).resolve().parents[2]
B, H, M = "b" * 40, "a" * 40, "c" * 40


def ordinary_run():
    return {"id": 200, "status": "completed", "event": "pull_request",
            "path": ".github/workflows/test.yml", "repository": {"full_name": m.REPO},
            "head_sha": H, "head_repository": {"id": 2}, "run_attempt": 1,
            "display_title": f"Test Suite PR 42 base={B} head={H} merge={M}",
            "pull_requests": [{"number": 42, "head": {"sha": H}, "base": {"sha": B}}]}


class FakeAPI(m.API):
    def __init__(self):
        self.data = {}
        self.status = {}
        self.calls = []
        self.writes = []
        self.checks = []

    def request(self, path, data=None, method=None):
        self.calls.append((path, method))
        if data is not None:
            self.writes.append(copy.deepcopy(data))
            if path.endswith("/dispatches"):
                return self.status.get(path, 204), None
            if method == "PATCH":
                row = next(c for c in self.checks if c["id"] == int(path.rsplit("/", 1)[1]))
                row.update(copy.deepcopy(data))
                return 200, row
            row = {**copy.deepcopy(data), "id": len(self.checks) + 1, "app": {"id": 5}}
            self.checks.append(row)
            return 201, row
        if path.endswith("/check-runs"):
            return 200, {"check_runs": copy.deepcopy(self.checks)}
        return self.status.get(path, 200 if path in self.data else 404), copy.deepcopy(self.data.get(path))

    def pages(self, path, key=None):
        value = self.get(path)
        return value[key] if key else value


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.api = a = FakeAPI()
        self.pr_path = f"/repos/{m.REPO}/pulls/42"
        a.data[self.pr_path] = {"state": "open", "number": 42,
            "base": {"repo": {"full_name": m.REPO}, "ref": "main"},
            "head": {"sha": H, "repo": {"id": 2}}, "merge_commit_sha": M,
            "user": {"login": "fixture-member", "id": 7}}
        a.data[f"/repos/{m.REPO}/git/ref/heads/main"] = {"object": {"sha": B}}
        a.data[f"/repos/{m.REPO}/git/commits/{M}"] = {"parents": [{"sha": B}, {"sha": H}]}
        a.data[f"/repos/{m.REPO}/compare/{B}...{M}"] = {"files": [{"filename": "crates/core/src/lib.rs"}]}
        a.status["/orgs/matrixorigin/members/fixture-member"] = 204
        self.group_path = "/orgs/matrixorigin/actions/runner-groups/9"
        a.data[self.group_path] = {"name": "astra-macos-pr", "restricted_to_workflows": True,
            "selected_workflows": [m.WORKFLOW_REF], "visibility": "selected", "allows_public_repositories": True}
        a.data[self.group_path + "/repositories"] = {"repositories": [{"full_name": m.REPO}]}
        a.data[self.group_path + "/runners"] = {"runners": [{"name": "fixture-arm", "status": "online", "busy": False,
            "labels": [{"name": n} for n in ("self-hosted", "macOS", "ARM64", "mac-arm64-mini", "astra-macos-admitted")]}]}
        a.data[f"/repos/{m.REPO}/rules/branches/main"] = [{"type": "required_status_checks", "parameters": {
            "strict_required_status_checks_policy": True,
            "required_status_checks": [{"context": c, "integration_id": 5} for c in m.CONTEXTS]}}]
        a.data[f"/repos/{m.REPO}/environments/astra-macos-control"] = {
            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}
        a.data[f"/repos/{m.REPO}/environments/astra-macos-control/deployment-branch-policies"] = {
            "branch_policies": [{"name": "main", "type": "branch"}]}
        self.run_path = f"/repos/{m.REPO}/actions/runs/100"
        a.data[self.run_path] = {"id": 100, "repository": {"full_name": m.REPO},
            "event": "pull_request_target", "path": m.WORKFLOW, "run_attempt": 1}
        self.active = {"name": "Migrated macOS lanes", "status": "in_progress", "conclusion": None,
                       "runner_name": "fixture-arm", "runner_group_id": 9, "steps": []}
        a.data[self.run_path + "/attempts/1/jobs"] = {"jobs": [self.active]}
        a.data[self.run_path + "/jobs?filter=latest"] = {"jobs": [self.active]}
        self.plan = {**m.source(a, 42), "schema": 1, "app_id": 5, "run_id": 100,
                     "attempt": 1, "route": "self-hosted", "group_id": 9,
                     "expires_at": int(time.time()) + m.AUTHORIZATION_SECONDS}
        self.config = {"app_id": 5, "kind": "pr", "group_id": 9, "runner_name": "fixture-arm"}
        self.request = {"run_id": 100, "attempt": 1, "head": H}

    def authorize(self):
        m.save_checks(self.api, self.plan)

    def test_merge_requires_current_base_head_and_exact_ordered_parents(self):
        for parents in ([H, B], [B], [B, H, M], [B, "d" * 40]):
            with self.subTest(parents=parents):
                self.api.data[f"/repos/{m.REPO}/git/commits/{M}"]["parents"] = [{"sha": p} for p in parents]
                with self.assertRaises(m.Unavailable):
                    m.source(self.api, 42)
        self.api.data[self.pr_path]["merge_commit_sha"] = None
        with self.assertRaises(m.Unavailable):
            m.source(self.api, 42)

    def test_wrong_repository_branch_closed_pr_and_unknown_head_fail(self):
        for mutate in (lambda p: p.update(state="closed"),
                       lambda p: p["base"].update(ref="develop"),
                       lambda p: p["base"]["repo"].update(full_name="fixture/other"),
                       lambda p: p["head"].update(sha="invalid")):
            with self.subTest(mutate=mutate):
                before = copy.deepcopy(self.api.data[self.pr_path])
                mutate(self.api.data[self.pr_path])
                with self.assertRaises(m.Unavailable):
                    m.source(self.api, 42)
                self.api.data[self.pr_path] = before

    def test_membership_redirect_and_failures_never_authorize(self):
        for status in (204, 302, 401, 403, 404, 429, 500):
            with self.subTest(status=status):
                self.api.status["/orgs/matrixorigin/members/fixture-member"] = status
                self.assertEqual(m.member(self.api, "fixture-member"), status == 204)
        self.assertFalse(m.member(self.api, "../fixture"))
        self.assertIsNone(m.NoRedirect().redirect_request(None, None, 302, None, None, None))

    def test_public_or_repo_only_runner_policy_cannot_authorize(self):
        for key, value in (("name", "Default"), ("restricted_to_workflows", False),
                           ("selected_workflows", [m.WORKFLOW_REF, "fixture/other@main"]),
                           ("visibility", "all"), ("allows_public_repositories", False)):
            with self.subTest(key=key):
                before = copy.deepcopy(self.api.data[self.group_path])
                self.api.data[self.group_path][key] = value
                with self.assertRaises(m.Unavailable):
                    m.group_ready(self.api, 9, "pr")
                self.api.data[self.group_path] = before
        self.api.data[self.group_path + "/repositories"]["repositories"].append({"full_name": "fixture/other"})
        with self.assertRaises(m.Unavailable):
            m.group_ready(self.api, 9, "pr")

    def test_offline_busy_or_unadmitted_runner_uses_hosted_route(self):
        runner = self.api.data[self.group_path + "/runners"]["runners"][0]
        for change in ({"status": "offline"}, {"busy": True}, {"labels": []}):
            with self.subTest(change=change):
                before = copy.deepcopy(runner)
                runner.update(change)
                self.assertFalse(m.group_ready(self.api, 9, "pr"))
                runner.update(before)

    def test_publisher_key_environment_cannot_allow_pr_refs_wildcards_or_tags(self):
        path = f"/repos/{m.REPO}/environments/astra-macos-control/deployment-branch-policies"
        for policies in ([], [{"name": "*", "type": "branch"}], [{"name": "main", "type": "tag"}],
                         [{"name": "main", "type": "branch"}, {"name": "develop", "type": "branch"}]):
            with self.subTest(policies=policies):
                self.api.data[path]["branch_policies"] = policies
                with self.assertRaises(m.Unavailable):
                    m.require_check_sources(self.api, 5)

    def test_required_contexts_must_bind_to_the_publisher_app(self):
        m.require_check_sources(self.api, 5)
        for source in (None, 0, 6):
            with self.subTest(source=source):
                self.api.data[f"/repos/{m.REPO}/rules/branches/main"][0]["parameters"]["required_status_checks"][0]["integration_id"] = source
                with self.assertRaises(m.Unavailable):
                    m.require_check_sources(self.api, 5)

    def test_up_to_date_branch_enforcement_is_required_for_tuple_bound_checks(self):
        self.api.data[f"/repos/{m.REPO}/rules/branches/main"][0]["parameters"]["strict_required_status_checks_policy"] = False
        with self.assertRaises(m.Unavailable):
            m.require_check_sources(self.api, 5)

    def test_private_member_personal_fork_is_admitted_and_each_attempt_rechecks(self):
        self.authorize()
        self.assertEqual(m.admit(self.api, self.request, self.config), self.plan)
        self.api.data[self.run_path]["run_attempt"] = 2
        self.api.data[self.run_path + "/attempts/2/jobs"] = {"jobs": [self.active]}
        self.request["attempt"] = 2
        self.assertEqual(m.admit(self.api, self.request, self.config), self.plan)
        self.api.status["/orgs/matrixorigin/members/fixture-member"] = 404
        with self.assertRaises(m.Unavailable):
            m.admit(self.api, self.request, self.config)
        self.assertGreaterEqual(sum(p.endswith("members/fixture-member") for p, _ in self.api.calls), 3)

    def test_forged_app_workflow_attempt_runner_and_event_are_rejected(self):
        self.authorize()
        cases = [lambda: self.api.checks[0]["app"].update(id=9),
                 lambda: self.api.data[self.run_path].update(path=".github/workflows/test.yml"),
                 lambda: self.api.data[self.run_path].update(event="pull_request"),
                 lambda: self.api.data[self.run_path].update(run_attempt=2),
                 lambda: self.active.update(runner_name="other"),
                 lambda: self.active.update(runner_group_id=1)]
        for mutate in cases:
            with self.subTest(mutate=mutate):
                snapshot = copy.deepcopy((self.api.data, self.api.checks))
                mutate()
                with self.assertRaises(m.Unavailable):
                    m.admit(self.api, self.request, self.config)
                self.api.data, self.api.checks = snapshot
                self.active = self.api.data[self.run_path + "/attempts/1/jobs"]["jobs"][0]

    def test_admission_cannot_cross_main_account_or_use_stale_source(self):
        self.authorize()
        with self.assertRaises(m.Unavailable):
            m.admit(self.api, self.request, {**self.config, "kind": "main"})
        self.api.data[self.pr_path]["user"]["id"] = 8
        with self.assertRaises(m.Unavailable):
            m.admit(self.api, self.request, self.config)
        self.api.data[self.pr_path]["user"]["id"] = 7
        self.api.data[f"/repos/{m.REPO}/git/ref/heads/main"]["object"]["sha"] = "d" * 40
        with self.assertRaises(m.Unavailable):
            m.admit(self.api, self.request, self.config)

    def test_scope_uses_canonical_classifier_and_truncation_is_full_scope(self):
        path = f"/repos/{m.REPO}/compare/{B}...{M}"
        self.api.data[path] = {"files": [{"filename": "docs/guide.md"}]}
        self.assertFalse(m.selected(self.api, self.plan))
        self.api.data[path] = {"files": [{"filename": "docs/guide.md", "previous_filename": "crates/core/src/lib.rs"}]}
        self.assertTrue(m.selected(self.api, self.plan))
        self.api.data[path] = {"files": [{"filename": "docs/a.md"}] * 300}
        self.assertTrue(m.selected(self.api, self.plan))
        self.api.status[path] = 403
        self.assertTrue(m.selected(self.api, self.plan))

    def test_ordinary_member_lookup_failure_and_resource_failure_choose_distinct_routes(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
            "GITHUB_REPOSITORY": m.REPO, "GITHUB_EVENT_NAME": "pull_request_target",
            "GITHUB_RUN_ID": "100", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_OUTPUT": str(Path(directory) / "outputs"), "ASTRA_MACOS_GROUP_ID": "9"}):
            for status, busy, expected in ((204, False, "self-hosted"), (204, True, "hosted"),
                                           (404, False, "ordinary"), (403, False, "ordinary"), (302, False, "ordinary")):
                with self.subTest(status=status, busy=busy):
                    self.api.status["/orgs/matrixorigin/members/fixture-member"] = status
                    self.api.data[self.group_path + "/runners"]["runners"][0]["busy"] = busy
                    m.plan_command(self.api, {"number": 42}, 5)
                    plan = json.loads(self.api.checks[-1]["output"]["text"])
                    self.assertEqual(plan["route"], expected)

    def test_recovery_dispatch_revalidates_members_and_uses_hosted_without_auto_approval(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
            "GITHUB_REPOSITORY": m.REPO, "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_RUN_ID": "100", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_OUTPUT": str(Path(directory) / "outputs"), "ASTRA_MACOS_GROUP_ID": "9"}):
            for membership, route in ((204, "hosted"), (404, "ordinary"), (403, "ordinary")):
                with self.subTest(membership=membership):
                    self.api.status["/orgs/matrixorigin/members/fixture-member"] = membership
                    m.plan_command(self.api, {"inputs": {"pr_number": "42"}}, 5)
                    self.assertEqual(json.loads(self.api.checks[-1]["output"]["text"])["route"], route)

    def test_real_test_failure_cannot_be_masked_by_a_successful_fallback(self):
        self.authorize()
        failed = {**self.active, "status": "completed", "conclusion": "failure",
                  "steps": [{"name": "Run all three macOS lanes", "conclusion": "failure"}]}
        fallbacks = [{**failed, "name": "Fallback macOS: " + lane, "conclusion": "success",
                      "labels": ["macos-15"],
                      "steps": [{"name": "Enforce current hosted authorization", "conclusion": "success"},
                                {"name": "Run macOS lane", "conclusion": "success"}]} for lane in m.HOSTED_LANES]
        self.api.data[self.run_path + "/jobs?filter=latest"] = {"jobs": [failed, *fallbacks]}
        self.assertFalse(m.can_fallback(self.api, self.plan))
        m.finish(self.api, self.plan)
        self.assertTrue(all(c["conclusion"] == "failure" for c in self.api.checks))
        failed["steps"] = []  # Admission failed before executing PR tests.
        self.assertTrue(m.can_fallback(self.api, self.plan))
        m.finish(self.api, self.plan)
        self.assertTrue(all(c["conclusion"] == "success" for c in self.api.checks))

    def test_success_requires_actual_test_step_and_expected_runner_group(self):
        self.authorize()
        self.active.update(status="completed", conclusion="success")
        self.assertEqual(m.verified_job(self.api, self.plan, "Migrated macOS lanes"), "failure")
        self.active["steps"] = [{"name": "Run all three macOS lanes", "conclusion": "success"}]
        self.assertEqual(m.verified_job(self.api, self.plan, "Migrated macOS lanes"), "success")
        self.active["runner_group_id"] = 1
        self.assertEqual(m.verified_job(self.api, self.plan, "Migrated macOS lanes"), "failure")

    def test_untrusted_ordinary_success_does_not_satisfy_member_results(self):
        plan = {**self.plan, "route": "ordinary"}
        self.authorize()
        self.assertTrue(m.finish(self.api, plan))
        self.assertTrue(all(c.get("conclusion") == "failure" for c in self.api.checks))

    def test_delayed_publication_cannot_overwrite_newer_attempt(self):
        self.authorize()
        newer = {**self.plan, "attempt": 2}
        m.save_checks(self.api, newer)
        count = len(self.api.writes)
        m.save_checks(self.api, self.plan, "success")
        self.assertEqual(len(self.api.writes), count)
        self.assertFalse(any(c.get("conclusion") == "success" for c in self.api.checks))

    def test_missing_hint_keeps_hosted_execution_and_app_hint_is_not_a_result(self):
        with patch.object(m.time, "sleep"):
            self.assertFalse(m.hint(self.api, {"number": 42, "pull_request": {"head": {"sha": H}, "base": {"ref": "main"}}}, 5))
            self.authorize()
            self.assertTrue(m.hint(self.api, {"number": 42, "pull_request": {"head": {"sha": H}, "base": {"ref": "main"}}}, 5))
            self.assertTrue(all(c["status"] == "in_progress" for c in self.api.checks))

    def test_ordinary_hosted_results_require_matching_source_all_three_jobs_and_real_macos(self):
        runs_path = f"/repos/{m.REPO}/actions/workflows/test.yml/runs?event=pull_request&head_sha={H}"
        self.api.data[runs_path] = {"workflow_runs": [ordinary_run()]}
        names = ("Terminal: default-reader (macos-15)", "Terminal: reflow (macos-15)",
                 "macOS workspace coordination contracts")
        jobs = [{"name": name, "status": "completed", "conclusion": "success", "labels": ["macos-15"]} for name in names]
        self.api.data[f"/repos/{m.REPO}/actions/runs/200/jobs?filter=latest"] = {"jobs": jobs}
        self.assertEqual(m.hosted_result(self.api, self.plan), "success")
        for key, value in (("status", "in_progress"), ("conclusion", "cancelled"), ("labels", ["ubuntu-latest"])):
            before = copy.deepcopy(jobs[0])
            jobs[0][key] = value
            self.assertNotEqual(m.hosted_result(self.api, self.plan), "success")
            jobs[0] = before
        jobs.pop()
        self.assertEqual(m.hosted_result(self.api, self.plan), "failure")
        self.api.data[runs_path]["workflow_runs"][0]["status"] = "in_progress"
        self.assertIsNone(m.hosted_result(self.api, self.plan))
        self.api.data[runs_path]["workflow_runs"][0]["pull_requests"][0]["base"]["sha"] = "d" * 40
        self.assertIsNone(m.hosted_result(self.api, self.plan))

    def test_hosted_result_cannot_accept_a_rerun_with_successful_cached_steps(self):
        plan = {**self.plan, "route": "hosted"}
        job = {"name": "Fallback macOS: default-reader", "status": "completed", "conclusion": "success",
               "labels": ["macos-15"], "steps": [
                   {"name": "Enforce current hosted authorization", "conclusion": "success"},
                   {"name": "Run macOS lane", "conclusion": "success"}]}
        self.api.data[self.run_path + "/jobs?filter=latest"] = {"jobs": [job]}
        self.assertEqual(m.verified_job(self.api, plan, job["name"]), "success")
        self.api.data[self.run_path]["run_attempt"] = 2
        self.assertEqual(m.verified_job(self.api, plan, job["name"]), "failure")
        self.api.data[self.run_path]["run_attempt"] = 1
        job["steps"].pop(0)
        self.assertEqual(m.verified_job(self.api, plan, job["name"]), "failure")

    def test_main_stays_hosted_without_explicit_isolation_acceptance(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
            "GITHUB_REPOSITORY": m.REPO, "GITHUB_EVENT_NAME": "push",
            "GITHUB_RUN_ID": "100", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_OUTPUT": str(Path(directory) / "outputs"), "ASTRA_MACOS_MAIN_ISOLATED": "false"}):
            m.plan_command(self.api, {"ref": "refs/heads/main", "before": B, "after": H}, 5)
            out = dict(line.split("=", 1) for line in Path(os.environ["GITHUB_OUTPUT"]).read_text().splitlines())
            self.assertEqual(out["route"], "disabled")
            self.assertEqual(self.api.writes, [])

    def test_hosted_failed_only_rerun_requires_new_admission_not_cached_router(self):
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            event.write_text("{}")
            output = Path(directory) / "outputs"
            with patch.dict(os.environ, {"GH_TOKEN": "fixture", "ASTRA_MACOS_APP_ID": "5",
                    "GITHUB_EVENT_PATH": str(event), "GITHUB_OUTPUT": str(output), "GITHUB_RUN_ATTEMPT": "2"}), \
                    patch.object(m, "API", return_value=self.api), \
                    patch.object(sys, "argv", ["macos_runner.py", "refresh", "--plan", json.dumps(self.plan)]):
                self.assertEqual(m.main(), 1)
                self.assertFalse(output.exists())

    def test_api_pagination_collects_all_pages_and_errors_are_fail_closed(self):
        api = m.API("fixture")
        pages = [(200, {"jobs": [{"id": i} for i in range(100)]}), (200, {"jobs": [{"id": 100}]})]
        with patch.object(api, "request", side_effect=pages) as request:
            self.assertEqual(len(api.pages("/fixture/jobs", "jobs")), 101)
            self.assertIn("page=2", request.call_args.args[0])
        with patch.object(api, "request", return_value=(403, None)):
            with self.assertRaises(m.Unavailable):
                api.pages("/fixture/jobs", "jobs")
        with self.assertRaises(m.Unavailable):
            api.request("https://fixture.invalid/token")

    def test_ordinary_hint_returns_without_sleep_and_permission_denial_is_immediate(self):
        event = {"number": 42, "pull_request": {"head": {"sha": H}, "base": {"ref": "main"}}}
        m.save_checks(self.api, {**self.plan, "route": "ordinary"})
        with patch.object(m.time, "sleep") as sleep:
            self.assertFalse(m.hint(self.api, event, 5))
            sleep.assert_not_called()
        self.api.checks.clear()
        self.authorize()
        self.api.status[self.run_path] = 403
        with patch.object(m.time, "sleep") as sleep:
            self.assertFalse(m.hint(self.api, event, 5))
            sleep.assert_not_called()

    def test_hint_waits_for_delayed_plan_and_exhausted_budget_keeps_hosted(self):
        event = {"number": 42, "pull_request": {"head": {"sha": H}, "base": {"ref": "main"}}}
        self.authorize()
        records = copy.deepcopy(self.api.checks)
        self.api.checks.clear()
        def publish_after_first_sleep(_seconds):
            self.api.checks = records
        with patch.object(m.time, "sleep", side_effect=publish_after_first_sleep) as sleep:
            self.assertTrue(m.hint(self.api, event, 5))
            self.assertEqual(sleep.call_count, 1)
        self.api.checks.clear()
        with patch.object(m.time, "sleep") as sleep, patch.object(m.time, "monotonic", side_effect=[0, 91]):
            self.assertFalse(m.hint(self.api, event, 5))
            sleep.assert_not_called()

    def test_expired_authorization_rejects_actual_rerun_and_publication(self):
        self.plan["expires_at"] = 1
        self.authorize()
        with self.assertRaises(m.Unavailable):
            m.admit(self.api, self.request, self.config)
        with self.assertRaises(m.Unavailable):
            m.finish(self.api, self.plan)
        self.assertTrue(all(c["status"] == "in_progress" for c in self.api.checks))

    def prepare_ordinary_reconciliation(self):
        self.api.status["/orgs/matrixorigin/members/fixture-member"] = 404
        self.plan["route"] = "ordinary"
        self.authorize()
        self.api.data[f"/repos/{m.REPO}/pulls?state=open&base=main"] = [
            {"number": 42, "head": {"sha": H}}]
        self.api.data[f"/repos/{m.REPO}/actions/workflows/test.yml/runs?event=pull_request&head_sha={H}"] = {
            "workflow_runs": [ordinary_run()]}
        self.jobs200 = f"/repos/{m.REPO}/actions/runs/200/jobs?filter=latest"
        self.api.data[self.jobs200] = {"jobs": [
            {"name": name, "status": "completed", "conclusion": "success", "labels": ["macos-15"]}
            for name in ("Terminal: default-reader (macos-15)", "Terminal: reflow (macos-15)",
                         "macOS workspace coordination contracts")]}

    def test_empty_fork_associations_complete_ordinary_checks(self):
        self.prepare_ordinary_reconciliation()
        run = self.api.data[f"/repos/{m.REPO}/actions/workflows/test.yml/runs?event=pull_request&head_sha={H}"]["workflow_runs"][0]
        run["pull_requests"] = []
        self.assertEqual(m.hosted_result(self.api, self.plan), "success")
        self.assertTrue(m.finish(self.api, self.plan))
        self.assertTrue(all(c["conclusion"] == "success" for c in self.api.checks))

    def test_empty_fork_associations_work_through_observer_and_scheduled_reconciliation(self):
        for entrypoint in ("observe", "reconcile"):
            with self.subTest(entrypoint=entrypoint):
                self.api.checks.clear()
                self.prepare_ordinary_reconciliation()
                run = self.api.data[f"/repos/{m.REPO}/actions/workflows/test.yml/runs?event=pull_request&head_sha={H}"]["workflow_runs"][0]
                run["pull_requests"] = []
                self.api.data[f"/repos/{m.REPO}/actions/runs/200"] = run
                # This endpoint is also empty for the real reviewed fork run.
                self.api.data[f"/repos/{m.REPO}/commits/{H}/pulls"] = []
                with tempfile.TemporaryDirectory() as directory:
                    event = Path(directory) / "event.json"
                    event.write_text(json.dumps({"workflow_run": {"id": 200}}))
                    with (
                        patch.dict(os.environ, {"GH_TOKEN": "fixture", "ASTRA_MACOS_APP_ID": "5",
                                                "GITHUB_EVENT_PATH": str(event)}),
                        patch.object(m, "API", return_value=self.api),
                        patch.object(sys, "argv", ["macos_runner.py", entrypoint]),
                    ):
                        self.assertEqual(m.main(), 0)
                self.assertTrue(all(c["conclusion"] == "success" for c in self.api.checks))
                self.assertFalse(any(path.endswith(f"/commits/{H}/pulls") for path, _ in self.api.calls))

    def test_ordinary_empty_links_retain_repository_event_workflow_and_merge_identity(self):
        self.prepare_ordinary_reconciliation()
        original = ordinary_run()
        original["pull_requests"] = []
        mutations = (
            lambda r: r.update(event="push"),
            lambda r: r.update(path=m.WORKFLOW),
            lambda r: r["repository"].update(full_name="fixture/other"),
            lambda r: r["head_repository"].update(id=99),
            lambda r: r.update(head_sha="d" * 40),
            lambda r: r.update(display_title=r["display_title"].replace(B, "d" * 40)),
            lambda r: r.update(display_title=r["display_title"].replace(H, "d" * 40)),
            lambda r: r.update(display_title=r["display_title"].replace(M, "d" * 40)),
            lambda r: r.update(display_title=r["display_title"].replace("PR 42", "PR 43")),
            lambda r: r.update(display_title="Historical title without source metadata"),
            lambda r: r.update(pull_requests=[{"number": 99, "head": {"sha": H}, "base": {"sha": B}}]))
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                run = copy.deepcopy(original)
                mutate(run)
                with self.assertRaises(m.Unavailable):
                    m.ordinary_source(self.api, run)
        # A plausible run title cannot replace validation of the immutable merge.
        self.api.data[f"/repos/{m.REPO}/git/commits/{M}"]["parents"] = [{"sha": H}, {"sha": B}]
        with self.assertRaises(m.Unavailable):
            m.ordinary_source(self.api, original)

    def test_completed_ordinary_run_without_source_tuple_fails_instead_of_pending(self):
        self.prepare_ordinary_reconciliation()
        run = self.api.data[f"/repos/{m.REPO}/actions/workflows/test.yml/runs?event=pull_request&head_sha={H}"]["workflow_runs"][0]
        run["pull_requests"] = []
        del run["display_title"]
        self.assertTrue(m.finish(self.api, self.plan))
        self.assertTrue(all(c["conclusion"] == "failure" for c in self.api.checks))

    def test_reconciliation_recovers_a_lost_completion_notification(self):
        self.prepare_ordinary_reconciliation()
        m.reconcile(self.api, 5)
        self.assertTrue(all(c["status"] == "completed" and c["conclusion"] == "success" for c in self.api.checks))
        writes = len(self.api.writes)
        m.reconcile(self.api, 5)
        self.assertEqual(len(self.api.writes), writes)

    def test_completed_run_with_missing_or_skipped_lanes_fails_instead_of_pending(self):
        for mode in ("missing", "skipped"):
            with self.subTest(mode=mode):
                self.api.checks.clear()
                self.prepare_ordinary_reconciliation()
                if mode == "missing":
                    self.api.data[self.jobs200]["jobs"].pop()
                else:
                    self.api.data[self.jobs200]["jobs"][0]["conclusion"] = "skipped"
                m.reconcile(self.api, 5)
                self.assertTrue(all(c["status"] == "completed" and c["conclusion"] == "failure" for c in self.api.checks))

    def test_approval_pending_expires_and_does_not_become_a_successful_skip(self):
        self.prepare_ordinary_reconciliation()
        self.api.data[f"/repos/{m.REPO}/actions/workflows/test.yml/runs?event=pull_request&head_sha={H}"]["workflow_runs"] = []
        m.reconcile(self.api, 5)
        self.assertTrue(all(c["status"] == "in_progress" for c in self.api.checks))
        with patch.object(m.time, "time", return_value=self.plan["expires_at"] + 1):
            m.reconcile(self.api, 5)
        self.assertTrue(all(c["status"] == "completed" and c["conclusion"] == "failure" for c in self.api.checks))
        self.assertTrue(all("expired" in c["output"]["summary"] for c in self.api.checks))

    def test_legacy_authorization_without_deadline_fails_closed_instead_of_staying_pending(self):
        self.prepare_ordinary_reconciliation()
        del self.plan["expires_at"]
        m.save_checks(self.api, self.plan)
        m.reconcile(self.api, 5)
        self.assertTrue(all(c["conclusion"] == "failure" for c in self.api.checks))
        with self.assertRaises(m.Unavailable):
            m.require_unexpired(self.plan)

    def test_one_unavailable_pr_does_not_starve_reconciliation_of_other_prs(self):
        self.prepare_ordinary_reconciliation()
        self.api.data[f"/repos/{m.REPO}/pulls?state=open&base=main"].insert(0,
            {"number": 43, "head": {"sha": "d" * 40}})
        pages = self.api.pages
        def flaky_pages(path, key=None):
            if path == f"/repos/{m.REPO}/commits/{'d' * 40}/check-runs":
                raise m.Unavailable("fixture unavailable")
            return pages(path, key)
        with patch.object(self.api, "pages", side_effect=flaky_pages):
            m.reconcile(self.api, 5)
        self.assertTrue(all(c["conclusion"] == "success" for c in self.api.checks))

    def test_expiry_reconciliation_does_not_downgrade_already_successful_results(self):
        self.prepare_ordinary_reconciliation()
        m.save_checks(self.api, self.plan, "success")
        with patch.object(m.time, "time", return_value=self.plan["expires_at"] + 1):
            m.reconcile(self.api, 5)
            m.save_checks(self.api, self.plan, "failure", only_pending=True)
        self.assertTrue(all(c["conclusion"] == "success" for c in self.api.checks))

    def test_merge_source_retries_null_and_old_parents_without_changing_trigger_head(self):
        for mode in ("null", "old-parents"):
            with self.subTest(mode=mode):
                original = copy.deepcopy(self.api.data)
                if mode == "null":
                    self.api.data[self.pr_path]["merge_commit_sha"] = None
                else:
                    self.api.data[f"/repos/{m.REPO}/git/commits/{M}"]["parents"][0]["sha"] = "d" * 40
                with patch.object(m.time, "sleep", side_effect=lambda _: self.api.data.update(original)) as sleep:
                    self.assertEqual(m.source(self.api, 42, attempts=3, expected_head=H)["merge"], M)
                    self.assertEqual(sleep.call_count, 1)
        self.api.data[self.pr_path]["head"]["sha"] = "e" * 40
        with patch.object(m.time, "sleep") as sleep, self.assertRaises(m.StaleSource):
            m.source(self.api, 42, attempts=3, expected_head=H)
        sleep.assert_not_called()

    def test_plan_exhaustion_publishes_retryable_failure_instead_of_missing_checks(self):
        self.api.data[self.pr_path]["merge_commit_sha"] = None
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
            "GITHUB_REPOSITORY": m.REPO, "GITHUB_EVENT_NAME": "pull_request_target",
            "GITHUB_RUN_ID": "100", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_OUTPUT": str(Path(directory) / "outputs")}), patch.object(m.time, "sleep"):
            m.plan_command(self.api, {"number": 42, "pull_request": {"head": {"sha": H}}}, 5)
        self.assertEqual(len(self.api.checks), 3)
        self.assertTrue(all(c["conclusion"] == "failure" for c in self.api.checks))
        self.api.data[self.pr_path]["merge_commit_sha"] = M
        self.api.data[f"/repos/{m.REPO}/pulls?state=open&base=main"] = [{"number": 42, "head": {"sha": H}}]
        m.reconcile(self.api, 5)
        self.assertEqual(self.api.writes[-1], {"ref": "main", "inputs": {"pr_number": "42"}})

    def test_zero_checks_recovery_is_bounded_and_never_authorizes_execution(self):
        self.api.data[f"/repos/{m.REPO}/pulls?state=open&base=main"] = [{"number": 42, "head": {"sha": H}}]
        m.reconcile(self.api, 5)
        self.assertEqual(sum(path.endswith("/dispatches") for path, _ in self.api.calls), 1)
        marker = json.loads(self.api.checks[-1]["output"]["text"])
        self.assertEqual(marker["route"], "recovering")
        with self.assertRaises(m.Unavailable):
            m.admit(self.api, self.request, self.config)
        m.reconcile(self.api, 5)
        self.assertEqual(sum(path.endswith("/dispatches") for path, _ in self.api.calls), 1)
        with patch.object(m.time, "time", return_value=marker["recovery_requested_at"] + m.RECOVERY_COOLDOWN_SECONDS):
            m.reconcile(self.api, 5)
        self.assertEqual(sum(path.endswith("/dispatches") for path, _ in self.api.calls), 2)
        self.authorize()  # Real plan replaces the non-authorizing marker.
        self.assertEqual(m.authorization(self.api, H, 100, 5), self.plan)

    def test_recovery_does_not_dispatch_over_a_real_plan_or_retry_test_failures(self):
        self.authorize()
        m.recover(self.api, {"number": 42, "head": {"sha": H}}, 5)
        self.assertFalse(any(path.endswith("/dispatches") for path, _ in self.api.calls))
        m.save_checks(self.api, self.plan, "failure", "Actual test failure")
        self.api.data[f"/repos/{m.REPO}/pulls?state=open&base=main"] = [{"number": 42, "head": {"sha": H}}]
        m.reconcile(self.api, 5)
        self.assertFalse(any(path.endswith("/dispatches") for path, _ in self.api.calls))

    def test_dispatch_permission_failure_is_throttled_and_recovers_after_cooldown(self):
        pr = {"number": 42, "head": {"sha": H}}
        path = f"/repos/{m.REPO}/actions/workflows/macos-trusted.yml/dispatches"
        self.api.status[path] = 403
        with self.assertRaises(m.Unavailable):
            m.recover(self.api, pr, 5)
        marker = json.loads(self.api.checks[-1]["output"]["text"])
        m.recover(self.api, pr, 5, marker)
        self.assertEqual(sum(p == path for p, _ in self.api.calls), 1)
        self.api.status[path] = 204
        with patch.object(m.time, "time", return_value=marker["recovery_requested_at"] + m.RECOVERY_COOLDOWN_SECONDS):
            m.recover(self.api, pr, 5, marker)
        self.assertEqual(sum(p == path for p, _ in self.api.calls), 2)

    def test_refresh_rejects_a_source_changed_during_its_second_api_read(self):
        with patch.object(m, "source", return_value={**self.plan, "head": "e" * 40}):
            with self.assertRaises(m.StaleSource):
                m.refresh(self.api, self.plan)

    def test_zero_checks_unresolved_merge_is_explicit_failure_and_does_not_dispatch(self):
        self.api.data[self.pr_path]["merge_commit_sha"] = None
        self.api.data[f"/repos/{m.REPO}/pulls?state=open&base=main"] = [{"number": 42, "head": {"sha": H}}]
        m.reconcile(self.api, 5)
        self.assertTrue(all(c["conclusion"] == "failure" for c in self.api.checks))
        self.assertFalse(any(path.endswith("/dispatches") for path, _ in self.api.calls))

    def test_stale_source_closes_immediately_and_reconciliation_requests_fresh_control(self):
        self.authorize()
        newer_base = "d" * 40
        self.api.data[f"/repos/{m.REPO}/git/ref/heads/main"]["object"]["sha"] = newer_base
        self.assertTrue(m.finish(self.api, self.plan))
        self.assertTrue(all(c["conclusion"] == "failure" and "Stale" in c["output"]["summary"] for c in self.api.checks))
        self.api.data[f"/repos/{m.REPO}/git/commits/{M}"]["parents"][0]["sha"] = newer_base
        self.api.data[f"/repos/{m.REPO}/pulls?state=open&base=main"] = [{"number": 42, "head": {"sha": H}}]
        m.reconcile(self.api, 5)
        self.assertEqual(self.api.writes[-1], {"ref": "main", "inputs": {"pr_number": "42"}})

    def test_stale_old_publisher_cannot_close_new_attempt(self):
        self.authorize()
        m.save_checks(self.api, {**self.plan, "attempt": 2})
        self.api.data[f"/repos/{m.REPO}/git/ref/heads/main"]["object"]["sha"] = "d" * 40
        writes = len(self.api.writes)
        self.assertTrue(m.finish(self.api, self.plan))
        self.assertEqual(len(self.api.writes), writes)

    def test_parallel_hosted_requires_every_real_lane_and_retains_failures(self):
        plan = {**self.plan, "route": "hosted"}
        jobs = [{"name": "Fallback macOS: " + lane, "status": "completed", "conclusion": "success",
                 "labels": ["macos-15"], "steps": [{"name": "Enforce current hosted authorization", "conclusion": "success"},
                                {"name": "Run macOS lane", "conclusion": "success"}]}
                for lane in m.HOSTED_LANES]
        self.api.data[self.run_path + "/jobs?filter=latest"] = {"jobs": jobs}
        m.save_checks(self.api, plan)
        for mutation in ("missing", "failed", "echo", "ubuntu", "success"):
            with self.subTest(mutation=mutation):
                before = copy.deepcopy(jobs)
                if mutation == "missing":
                    jobs.pop()
                elif mutation == "failed":
                    jobs[0]["conclusion"] = "failure"
                elif mutation == "echo":
                    jobs[0]["steps"] = []
                elif mutation == "ubuntu":
                    jobs[0]["labels"] = ["ubuntu-latest"]
                result = m.finish(self.api, plan)
                if mutation == "missing":
                    self.assertFalse(result)
                    self.api.data[self.run_path]["status"] = "completed"
                    self.assertTrue(m.finish(self.api, plan))
                    self.assertTrue(all(c["conclusion"] == "failure" for c in self.api.checks))
                    self.api.data[self.run_path].pop("status")
                else:
                    self.assertTrue(result)
                    self.assertTrue(all(c["conclusion"] == ("success" if mutation == "success" else "failure") for c in self.api.checks))
                jobs[:] = before




class LaneShellTests(unittest.TestCase):
    def test_canonical_commands_and_all_failures_propagate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("cargo", "npm"):
                path = root / name
                path.write_text(f"#!{sys.executable}\n" + '''
import json, os, sys
with open(os.environ["CALLS"], "a") as out: out.write(json.dumps([os.path.basename(sys.argv[0]), *sys.argv[1:]]) + "\\n")
failed = os.environ.get("FAIL") and os.environ["FAIL"] in " ".join(sys.argv[1:])
if not failed and os.path.basename(sys.argv[0]) == "cargo" and sys.argv[1] == "build":
    from pathlib import Path
    binary = Path(os.environ["CARGO_TARGET_DIR"]) / "debug/astra"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text("fixture binary")
if not failed and os.path.basename(sys.argv[0]) == "npm" and sys.argv[1] == "test":
    failed = not os.path.isfile(os.environ["ASTRA_TEST_BINARY"])
sys.exit(17 if failed else 0)
''')
                path.chmod(0o755)
            # Keep the real system Git observation, with a harmless synthetic repo.
            subprocess.run(["git", "init", str(root)], check=True, capture_output=True)
            for lane, failures in (("default-reader", ("", "tui::terminal_startup")),
                                   ("reflow", ("", "build", "ci", "test")),
                                   ("coordination", ("", "clippy", "workspace_observation::tests::"))):
                for fail in failures:
                    with self.subTest(lane=lane, fail=fail):
                        calls = root / "calls"
                        calls.unlink(missing_ok=True)
                        result = subprocess.run(["bash", str(ROOT / "scripts/ci/run-macos-lanes.sh"), lane],
                            cwd=root, env={**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                                          "CALLS": str(calls), "FAIL": fail, "GITHUB_WORKSPACE": str(root),
                                          "CARGO_TARGET_DIR": str(root / "scratch-target")},
                            capture_output=True, text=True)
                        self.assertEqual(result.returncode, 17 if fail else 0, result.stderr)
                        commands = [json.loads(line) for line in calls.read_text().splitlines()]
                        if not fail and lane == "coordination":
                            self.assertEqual(len(commands), 2)
                            self.assertIn("--test-threads=1", commands[-1])
                        if not fail and lane == "reflow":
                            self.assertEqual([c[:2] for c in commands], [["cargo", "build"], ["npm", "ci"], ["npm", "test"]])

    def test_hosted_execution_rejects_reused_outputs_before_any_candidate_command(self):
        workflow = (ROOT / ".github/workflows/macos-trusted.yml").read_text()
        hosted = workflow.split("\n  hosted:\n", 1)[1].split("\n  publish:\n", 1)[0]
        guard_name = "Enforce current hosted authorization"
        self.assertIn(f"- name: {guard_name}", hosted)
        self.assertLess(hosted.index(guard_name), hosted.index("path: _mac_source"))
        guard = workflow_run_script(".github/workflows/macos-trusted.yml", guard_name)
        execution = hosted.split("      - name: Run macOS lane\n", 1)[1].split("        run: ", 1)[1].splitlines()[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = root / "_mac_control/scripts/ci"
            control.mkdir(parents=True)
            for name in ("macos_runner.py", "ci_scope.py", "run-macos-lanes.sh"):
                (control / name).write_text((ROOT / "scripts/ci" / name).read_text())
            source = root / "_mac_source"
            source.mkdir()
            subprocess.run(["git", "init", str(source)], check=True, capture_output=True)
            cargo = root / "cargo"
            cargo.write_text('#!/bin/sh\ntouch "$CALLS"\n')
            cargo.chmod(0o755)
            for name, attempt, expiry, run_id, allowed, succeeds in (
                ("cached-successful-admission", "2", int(time.time()) + 3600, "100", "true", False),
                ("expired-before-start", "1", 1, "100", "true", False),
                ("another-run", "1", int(time.time()) + 3600, "101", "true", False),
                ("not-admitted", "1", int(time.time()) + 3600, "100", "false", False),
                ("fresh-full-rerun", "2", int(time.time()) + 3600, "100", "true", True)):
                with self.subTest(name=name):
                    plan = {"schema": 1, "kind": "pr", "route": "hosted", "head": H, "merge": M,
                            "run_id": 100, "attempt": 2 if succeeds else 1, "expires_at": expiry}
                    calls = root / "calls"
                    calls.unlink(missing_ok=True)
                    result = subprocess.run(["bash", "-euo", "pipefail", "-c", guard + '\ncd _mac_source\n' + execution],
                        cwd=root, env={**os.environ, "PLAN": json.dumps(plan), "PATH": f"{root}:{os.environ['PATH']}",
                            "CALLS": str(calls), "MACOS_LANE": "coordination", "GITHUB_REPOSITORY": m.REPO,
                            "GITHUB_EVENT_NAME": "pull_request_target", "GITHUB_RUN_ID": run_id,
                            "GITHUB_RUN_ATTEMPT": attempt, "ASTRA_MACOS_HOSTED_ADMITTED": allowed,
                            "GH_TOKEN": "", "ASTRA_MACOS_APP_ID": ""}, capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, succeeds, result.stderr)
                    self.assertEqual(calls.exists(), succeeds, "candidate Cargo ran before rejection")

    def test_hint_permissions_are_scoped_and_reconciliation_stays_metadata_only(self):
        workflow = (ROOT / ".github/workflows/test.yml").read_text()
        top = workflow.split("\non:", 1)[0]
        self.assertNotIn("actions: read", top)
        self.assertNotIn("checks: read", top)
        scope = workflow.split("\n  macos-routing:\n", 1)[1].split("\n  cli-test-build:\n", 1)[0]
        for permission in ("actions: read", "checks: read", "pull-requests: read", "contents: read"):
            self.assertIn(permission, scope)
        observer = (ROOT / ".github/workflows/macos-results.yml").read_text()
        self.assertIn("cron: '*/15 * * * *'", observer)
        self.assertIn("macos_runner.py reconcile", observer)
        self.assertIn("permission-actions: write", observer)
        self.assertIn("cancel-in-progress: false", observer)
        classifier = workflow.split("\n  scope:\n", 1)[1].split("\n  macos-routing:\n", 1)[0]
        self.assertNotIn("macos_runner.py hint", classifier)
        self.assertNotIn("actions: read", classifier)
        self.assertNotIn("_mac_source", observer)

    def test_credential_owner_and_cache_boundary_are_outside_pr_execution(self):
        workflow = (ROOT / ".github/workflows/macos-trusted.yml").read_text()
        for job, end in (("mini", "hosted-admission"), ("hosted", "publish")):
            execution = workflow.split(f"\n  {job}:\n", 1)[1].split(f"\n  {end}:\n", 1)[0]
            self.assertNotIn("secrets.", execution)
            self.assertNotIn("create-github-app-token", execution)
            self.assertNotIn("GH_TOKEN", execution)
            self.assertNotIn("environment:", execution)
        self.assertIn("cache-mode: read", workflow)
        self.assertNotIn("cache-mode: write", workflow)
        self.assertNotIn("workflow_call:", workflow)
        observer = (ROOT / ".github/workflows/macos-results.yml").read_text()
        self.assertNotIn("download-artifact", observer)
        self.assertNotIn("_mac_source", observer)
        self.assertIn("cache-mode: none", observer)
        hook = (ROOT / "scripts/ci/macos-runner-admit").read_text()
        self.assertIn('[ "$#" -eq 0 ]', hook)
        self.assertIn("SUDO_USER", hook)
        self.assertNotIn("eval", hook)


if __name__ == "__main__":
    unittest.main()
