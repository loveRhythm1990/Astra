#!/usr/bin/env python3
"""Exercise reviewed historical binaries against an explicitly disposable server.

No installer, user credentials, external model service or moving channel is used.
The same entrypoint runs against the PR router fixture and the candidate image.
Only categorical failures and artifact identities are written to the report.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from historical_clients import ArtifactError, baseline_document, prepare

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "load"))
import mock_openai_server as mock  # noqa: E402


class Failure(RuntimeError):
    def __init__(self, category, diagnostics=None):
        super().__init__(category)
        self.diagnostics = diagnostics


def deadline_exceeded(_signal, _frame):
    # Leave time inside the outer Rust/CI bound for each active scenario's
    # finally block to reap its own CLI/Edge/Server process group.
    raise Failure("driver_deadline_exceeded")


def require(condition, category):
    if not condition:
        raise Failure(category)


def begin_case(report, client, case):
    report["active_client"] = client
    report["active_case"] = case


def request(origin, path, token=None, payload=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None if payload is None else json.dumps(payload).encode()
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
            urllib.request.Request(origin + path, data=data, headers=headers), timeout=60
        ) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        # Response bodies may contain credentials or provider text.
        raise Failure("server_http_" + str(error.code)) from None


def child_environment(home, origin, token):
    # Explicit allowlist: never inherit developer native/runtime credentials.
    env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "LD_LIBRARY_PATH") if key in os.environ}
    env.update({
        "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"), "XDG_DATA_HOME": str(home / ".local/share"),
        "ASTRA_CLI_CREDENTIALS_DIR": str(home / ".astra"),
        "ASTRA_LOCAL_STATE_ROOT": str(home / ".astra"),
        "ASTRA_TOKEN": token,
        "ASTRA_API_URL": origin, "ASTRA_SERVER_URL": origin,
        "NO_COLOR": "1", "NO_PROXY": "*", "no_proxy": "*",
    })
    return env


def command(binary, env, home, args, timeout=120):
    try:
        return subprocess.run([str(binary), *args], env=env, cwd=home, capture_output=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise Failure("client_timeout") from None


def cli_base(origin, model):
    return ["--api-url", origin, "--profile", "compatibility", "--model", model, "--no-instructions"]


def one_shot_chat_base(origin, model):
    # Captured one-shot commands have neither a terminal nor an approval
    # channel. Use the published read-only mode; stdio approval journeys
    # retain prompt mode and exercise the real approval transport separately.
    return [*cli_base(origin, model), "chat", "--permission-mode", "plan"]


def authenticate_cli(binary, env, home, origin, username, password):
    # The stdio owner requires a bound profile even when one-shot commands
    # accept a bearer environment variable. Populate it through real login,
    # never by inventing a credential-file schema or reading developer state.
    result = command(binary, env, home, ["--api-url", origin, "--profile", "compatibility",
                     "admin", "login", "--username", username, "--password", password])
    require(result.returncode == 0, "client_profile_login_failed")


def result_json(result):
    try:
        body = json.loads(result.stdout)
    except (ValueError, UnicodeDecodeError):
        raise Failure("client_terminal_invalid") from None
    require(isinstance(body, dict), "client_terminal_shape")
    return body


def safe_error_summary(value):
    """Bound synthetic-journey errors without retaining credentials or locations."""
    if not isinstance(value, str):
        return None
    value = re.sub(r"(?i)\b(?:bearer|basic)\s+[^\s,;\"']+", "<credential>", value)
    value = re.sub(r"(?i)\b(?:access[_ -]?token|refresh[_ -]?token|api[_ -]?key|password|secret)"
                   r"[\"']?\s*[:=]\s*[\"']?[^\s,;\"']+", "<credential>", value)
    value = re.sub(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+", "<url>", value)
    value = re.sub(r"(?:[A-Za-z]:)?[/\\][^\s\"'<>]+", "<path>", value)
    value = re.sub(r"\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "<token>", value)
    value = re.sub(r"[A-Za-z0-9_-]{24,}", "<opaque>", value)
    return re.sub(r"[\x00-\x1f\x7f]", " ", value)[:1024]


def completed(result, expected):
    body = result_json(result)
    if result.returncode != 0 or body.get("success") is not True:
        diagnostics = {"exit_code": result.returncode,
                       "server_terminal_authoritative": body.get("server_terminal_authoritative") is True}
        # Retain only bounded machine classifications from the synthetic
        # journey, never free-form error messages or provider/client output.
        for field in ("error_kind", "error_code", "final_state"):
            value = body.get(field)
            if isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,79}", value):
                diagnostics[field] = value
        summary = safe_error_summary(body.get("error"))
        if summary:
            diagnostics["error_summary"] = summary
        raise Failure("client_chat_failed", diagnostics)
    require(body.get("final_state") == "completed", "client_terminal_not_completed")
    require(body.get("text") == expected, "client_answer_mismatch")
    require(bool(body.get("session_id")) and bool(body.get("run_id")), "client_terminal_identity_missing")
    require(body.get("server_terminal_authoritative") is True, "client_terminal_not_authoritative")
    return body


def paired_tool_result(messages, call_id, tool_name):
    """Match a real declaration/result pair despite later runtime user messages."""
    declarations = []
    for index, message in enumerate(messages):
        if message.get("role") != "assistant":
            continue
        calls = message.get("tool_calls")
        if calls is None:
            continue
        if not isinstance(calls, list) or any(not isinstance(call, dict) for call in calls):
            return None
        declarations.extend((index, call) for call in calls if call.get("id") == call_id)
    results = [(index, message) for index, message in enumerate(messages)
               if message.get("role") == "tool" and message.get("tool_call_id") == call_id]
    if len(declarations) != 1 or len(results) != 1:
        return None
    declaration_index, declaration = declarations[0]
    result_index, result = results[0]
    function = declaration.get("function")
    if (not isinstance(function, dict) or function.get("name") != tool_name
            or declaration_index >= result_index):
        return None
    return result


def identify_current(binary, env, home, report):
    build = command(binary, env, home, ["--build-info-json"])
    require(build.returncode == 0, "candidate_cli_identity_unavailable")
    metadata = result_json(build)
    require(metadata.get("git_sha") == report["server_source"], "candidate_cli_source_mismatch")
    version = command(binary, env, home, ["--version"])
    require(version.returncode == 0, "candidate_cli_version_unavailable")
    with binary.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    report["current_cli"] = {"sha256": digest, "source_sha": metadata["git_sha"],
                             "version": version.stdout.decode().strip()}


class Provider:
    """Reuse the repository OpenAI mock's wire writer; add finite tool/barrier cases."""

    def __init__(self):
        self.marker = "compatibility-" + uuid.uuid4().hex
        self.state = mock.ServerState(mock.MockConfig(
            model_name="compatibility", response_content=self.marker, prompt_tokens=10,
            completion_tokens=5, delay_ms=0, status=200, error_code="fixture",
            error_message="synthetic fixture", api_key="compatibility-fixture-only"))
        self.mode = "text"
        self.tool_name = "write_file"
        self.target = "compatibility-tool.txt"
        self.arrived = threading.Event()
        self.release = threading.Event()
        self.tool_result_seen = False
        self.require_readback = False
        self.readback_verified = False
        self.expected_model = None
        self.case = None
        self.claimed = set()
        self.errors = []
        self.lock = threading.Lock()
        base = mock.make_handler(self.state)
        owner = self

        class Handler(base):
            def do_POST(self):  # noqa: N802
                if urllib.parse.urlparse(self.path).path not in mock.COMPLETIONS_PATHS:
                    return super().do_POST()
                body = mock.read_json_body(self)
                case, mode = owner.case, owner.mode
                if owner.expected_model is not None and (
                        body.get("model") != owner.expected_model
                        or owner.marker not in json.dumps(body.get("messages", []))):
                    owner.errors.append("unexpected_inference")
                    return mock.write_json(self, mock.HTTPStatus.BAD_REQUEST,
                                           {"error": {"code": "fixture_unexpected_inference"}})
                if mode == "cancel":
                    if not owner.claim(case, "blocked_inference"):
                        return mock.write_json(self, mock.HTTPStatus.BAD_REQUEST,
                                               {"error": {"code": "fixture_duplicate_inference"}})
                    owner.arrived.set()
                    owner.release.wait(30)
                messages = body.get("messages", [])
                operation_id = "compat-operation-" + str(case)
                readback_id = "compat-readback-" + str(case)
                with owner.lock:
                    issued_operation = (case, operation_id) in owner.claimed
                    issued_readback = (case, readback_id) in owner.claimed
                tool_result = (paired_tool_result(messages, operation_id, owner.tool_name)
                               if issued_operation else None)
                desired_tool, call_id = owner.tool_name, operation_id
                if mode == "tool" and tool_result is not None:
                    owner.tool_result_seen = True
                    desired_tool = None
                    if owner.require_readback:
                        readback = (paired_tool_result(messages, readback_id, "read_file")
                                    if issued_readback else None)
                        if readback is None:
                            desired_tool, call_id = "read_file", readback_id
                        elif owner.marker not in json.dumps(readback.get("content")):
                            owner.errors.append("readback_content_missing")
                            return mock.write_json(self, mock.HTTPStatus.BAD_REQUEST,
                                                   {"error": {"code": "fixture_readback_content_missing"}})
                        else:
                            owner.readback_verified = True
                if mode == "tool" and desired_tool is not None:
                    names = {tool.get("function", {}).get("name") for tool in body.get("tools", [])}
                    tool = desired_tool if desired_tool in names else None
                    arguments = {"path": owner.target}
                    if tool == "write_file":
                        arguments["content"] = owner.marker + "\n"
                    search_id = "compat-search-" + desired_tool + "-" + str(case)
                    with owner.lock:
                        issued_search = (case, search_id) in owner.claimed
                    search_result = (paired_tool_result(messages, search_id, "tool_search")
                                     if issued_search else None)
                    if not tool and "tool_search" in names and search_result is None:
                        # Discover through the real admission owner, never inject a hidden tool.
                        tool = "tool_search"
                        arguments = {"query": "select:" + desired_tool}
                        call_id = search_id
                    if not tool:
                        owner.errors.append("tool_not_admitted")
                        return mock.write_json(self, mock.HTTPStatus.BAD_REQUEST,
                                               {"error": {"code": "fixture_tool_not_admitted"}})
                    if not owner.claim(case, call_id):
                        return mock.write_json(self, mock.HTTPStatus.BAD_REQUEST,
                                               {"error": {"code": "fixture_duplicate_tool_inference"}})
                    call = {"id": call_id, "type": "function", "function": {
                        "name": tool, "arguments": json.dumps(arguments)}}
                    if body.get("stream"):
                        self.send_response(200)
                        self.send_header("Content-Type", "text/event-stream")
                        self.send_header("Connection", "close")
                        self.end_headers()
                        for delta, finish in [({"role": "assistant", "tool_calls": [{"index": 0, **call}]}, None),
                                              ({}, "tool_calls")]:
                            value = {"id": "compat-tools", "object": "chat.completion.chunk",
                                     "created": 1, "model": body["model"], "choices": [
                                         {"index": 0, "delta": delta, "finish_reason": finish}]}
                            self.wfile.write(b"data: " + json.dumps(value).encode() + b"\n\n")
                        self.wfile.write(b"data: [DONE]\n\n")
                        self.wfile.flush()
                        return
                    response = mock.build_completion_payload(owner.state.config, body)
                    response["choices"][0].update({"message": {"role": "assistant", "content": None,
                                                                 "tool_calls": [call]}, "finish_reason": "tool_calls"})
                    return mock.write_json(self, mock.HTTPStatus.OK, response)
                if mode == "tool":
                    owner.tool_result_seen = tool_result is not None
                    if owner.tool_name == "read_file" and (
                            tool_result is None or owner.marker not in json.dumps(tool_result.get("content"))):
                        return mock.write_json(self, mock.HTTPStatus.BAD_REQUEST,
                                               {"error": {"code": "fixture_edge_read_content_missing"}})
                if not owner.claim(case, "answer"):
                    return mock.write_json(self, mock.HTTPStatus.BAD_REQUEST,
                                           {"error": {"code": "fixture_duplicate_answer"}})
                try:
                    if body.get("stream"):
                        mock.write_openai_stream(self, owner.state.config, body)
                    else:
                        mock.write_json(self, mock.HTTPStatus.OK, mock.build_completion_payload(owner.state.config, body))
                except (BrokenPipeError, ConnectionResetError):
                    pass  # The cancellation scenario deliberately closes this response.

        self.server = mock.CapacityMockOpenAiServer(("0.0.0.0", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def claim(self, case, phase):
        if case is None:
            return True  # Model-registration connectivity probes precede the journeys.
        with self.lock:
            key = (case, phase)
            if key in self.claimed:
                self.errors.append("duplicate_inference")
                return False
            self.claimed.add(key)
            return True

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class Rpc:
    def __init__(self, binary, env, home, origin, model):
        self.process = subprocess.Popen([str(binary), *cli_base(origin, model), "serve", "stdio"],
                                        env=env, cwd=home, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True, start_new_session=True)
        self.events = queue.Queue()
        self.pending = []
        self.next_id = 0

        def drain():
            for line in self.process.stdout:
                try:
                    self.events.put(json.loads(line))
                except ValueError:
                    self.events.put({"compatibility_protocol_invalid": True})
            self.events.put({"compatibility_eof": True})

        self.reader = threading.Thread(target=drain, daemon=True)
        self.reader.start()

    def wait(self, predicate, timeout=90):
        deadline = time.monotonic() + timeout
        while True:
            for index, event in enumerate(self.pending):
                if predicate(event):
                    return self.pending.pop(index)
            remaining = deadline - time.monotonic()
            require(remaining > 0, "stdio_timeout")
            try:
                event = self.events.get(timeout=remaining)
            except queue.Empty:
                raise Failure("stdio_timeout") from None
            require(not event.get("compatibility_eof"), "stdio_unexpected_eof")
            require(not event.get("compatibility_protocol_invalid"), "stdio_invalid_json")
            if predicate(event):
                return event
            self.pending.append(event)

    def send(self, method, params):
        self.next_id += 1
        value = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}
        self.process.stdin.write(json.dumps(value) + "\n")
        self.process.stdin.flush()
        response = self.wait(lambda event: event.get("id") == value["id"])
        require("error" not in response, "stdio_request_rejected_" + method.replace("/", "_"))
        return response["result"]

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGTERM)
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait()
        self.reader.join(timeout=5)


def session_runs(origin, token, session):
    snapshot = request(origin, "/sessions/" + session + "/runs", token)
    require(snapshot.get("session_id") == session and snapshot.get("truncated") is False,
            "server_run_snapshot_incomplete")
    require(isinstance(snapshot.get("runs"), list), "server_run_snapshot_invalid")
    return snapshot["runs"]


def session_root(origin, token, session, model):
    roots = [run for run in session_runs(origin, token, session)
             if run.get("depth") == 0 and run.get("parent_run_id") is None]
    require(len(roots) == 1, "server_run_ambiguous")
    root = roots[0]
    require(bool(root.get("run_id")), "server_run_identity_missing")
    require(root.get("runtime", {}).get("model_name") == model, "server_model_mismatch")
    return root


def settled_session_run(origin, token, session, model, expected_status, run_id=None):
    # Each journey has a fresh session; no other turn can supply its terminal.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        root = session_root(origin, token, session, model)
        require(run_id is None or run_id == root["run_id"], "server_run_identity_changed")
        run_id = root["run_id"]
        if root.get("status") == expected_status:
            return run_id
        require(root.get("status") not in ("completed", "failed", "cancelled", "interrupted", "delegated"),
                "server_run_terminal_mismatch")
        time.sleep(0.1)
    raise Failure("server_terminal_timeout")


def approvals(binary, env, home, origin, token, model, provider, report, client):
    begin_case(report, client, "approval_stdio_start")
    rpc = Rpc(binary, env, home, origin, model)
    try:
        rpc.send("initialize", {})
        for decision in ("allow_once", "deny"):
            begin_case(report, client, "tool_approval_" + decision)
            thread = rpc.send("thread/start", {})["thread"]["id"]
            require(not session_runs(origin, token, thread), "approval_session_not_fresh")
            provider.case = "approval-" + decision
            provider.mode = "tool"
            provider.tool_name = "write_file"
            provider.target = "compatibility-" + decision + ".txt"
            provider.tool_result_seen = False
            provider.require_readback = decision == "allow_once"
            provider.readback_verified = False
            turn = rpc.send("turn/start", {"threadId": thread,
                "input": [{"type": "text", "text": "Write the synthetic compatibility fixture: " + provider.marker}],
                "permissionMode": "prompt"})["turn"]["id"]
            approval = rpc.wait(lambda event: event.get("method") == "approval/requested")["params"]["approval"]
            require(approval["threadId"] == thread and approval["turnId"] == turn, "approval_identity_mismatch")
            target = home / provider.target
            require(not target.exists(), "tool_executed_before_approval")
            rpc.send("approval/respond", {"approvalId": approval["id"], "decision": decision})
            terminal = rpc.wait(lambda event: event.get("method") == "turn/completed"
                                and event.get("params", {}).get("turn", {}).get("id") == turn)
            content_matches = target.is_file() and target.read_bytes() == (provider.marker + "\n").encode()
            observations = {"file_exists": target.is_file(), "content_matches": content_matches,
                            "tool_result_seen": provider.tool_result_seen,
                            "readback_verified": provider.readback_verified}
            report.setdefault("approval_observations", {})[decision] = observations
            if terminal["params"]["status"] != "completed":
                raise Failure("approved_turn_failed", observations)
            answer = rpc.wait(lambda event: event.get("method") == "item/completed"
                              and event.get("params", {}).get("item", {}).get("type") == "agentMessage")
            require(answer["params"]["item"].get("text") == provider.marker, "approval_answer_mismatch")
            settled_session_run(origin, token, thread, model, "completed")
            require(provider.tool_result_seen, "tool_result_not_returned_to_model")
            if decision == "allow_once":
                require(content_matches, "approved_write_missing")
                require(provider.readback_verified, "approved_write_readback_missing")
            else:
                require(not target.exists(), "denied_write_executed")
    finally:
        provider.mode = "text"
        provider.require_readback = False
        rpc.close()


def cancellation(binary, env, home, origin, token, model, provider):
    provider.case = "cancellation"
    provider.mode = "cancel"
    provider.arrived.clear()
    provider.release.clear()
    rpc = Rpc(binary, env, home, origin, model)
    try:
        rpc.send("initialize", {})
        thread = rpc.send("thread/start", {})["thread"]["id"]
        require(not session_runs(origin, token, thread), "cancel_session_not_fresh")
        turn = rpc.send("turn/start", {"threadId": thread,
            "input": [{"type": "text", "text": "Wait until cancelled: " + provider.marker}]})["turn"]["id"]
        require(provider.arrived.wait(60), "cancel_run_not_admitted")
        run_id = session_root(origin, token, thread, model)["run_id"]
        interrupted = rpc.send("turn/interrupt", {"threadId": thread, "turnId": turn})
        require(interrupted.get("ok") is True, "cancel_not_acknowledged")
        terminal = rpc.wait(lambda event: event.get("method") == "turn/completed"
                            and event.get("params", {}).get("threadId") == thread
                            and event.get("params", {}).get("turn", {}).get("id") == turn)
        # 0.2.12 reports cancellation as a failed local turn. Durable Server
        # status, rather than that display label, proves cancellation settled.
        require(terminal["params"].get("status") == "failed", "cancel_client_terminal_mismatch")
        settled_session_run(origin, token, thread, model, "cancelled", run_id)
        return thread, run_id
    finally:
        provider.mode = "text"
        provider.release.set()
        rpc.close()


def edge_execution(home, origin, token, edge_id, model, provider, report, client):
    begin_case(report, client, "standalone_edge_tool_execution")
    provider.case = "standalone-edge"
    provider.mode = "tool"
    provider.tool_name = "read_file"
    provider.target = "compatibility-edge-input.txt"
    provider.tool_result_seen = False
    (home / provider.target).write_text(provider.marker)
    try:
        session = request(origin, "/sessions", token, {"title": "Historical Edge compatibility"})["session_id"]
        catalog = request(origin, "/models", token)
        rows = catalog if isinstance(catalog, list) else catalog["items"]
        offering = next(row["offering_id"] for row in rows if row["name"] == model)
        payload = {
            "session_id": session, "message": "Read the compatibility fixture: " + provider.marker,
            "model_selection": {"offering_id": offering}, "interaction_mode": "non_interactive",
            "allow_tools": ["read_file"], "edge_executor_id": edge_id,
            "workspace_binding": {"kind": "edge_workspace", "display_name": "Compatibility workspace",
                "root": str(home), "source": {"kind": "edge_path", "path": str(home)}, "authority": "read_write"},
            "executor_binding": {"kind": "edge_agent", "executor_id": edge_id,
                "display_name": "Historical Edge", "transport": "edge_ws", "status": "online"},
        }
        wire = urllib.request.Request(origin + "/chat/stream", data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
        events = []
        done = False
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(wire, timeout=90) as response:
            for raw in response:
                if raw.startswith(b"data: "):
                    data = raw[6:].strip()
                    require(not done, "edge_events_after_done")
                    if data == b"[DONE]":
                        require(events and events[-1].get("type") == "turn_complete", "edge_done_before_terminal")
                        done = True
                    else:
                        events.append(json.loads(data))
        terminals = [(index, event) for index, event in enumerate(events) if event.get("type") == "run_finished"]
        require(len(terminals) == 1, "edge_terminal_not_unique")
        terminal_index, terminal = terminals[0]
        require(terminal.get("status") == "completed" and terminal.get("run_id"), "edge_execution_not_completed")
        starts = [event for event in events if event.get("type") == "session_info"]
        require(len(starts) == 1 and starts[0].get("session_id") == session
                and starts[0].get("run_id") == terminal["run_id"], "edge_run_identity_mismatch")
        require(not any(event.get("type") in ("error", "run_error") for event in events), "edge_run_error")
        require(all(event.get("type") in ("turn_complete", "ping") for event in events[terminal_index + 1:]),
                "edge_work_after_terminal")
        require(events[-1].get("type") == "turn_complete"
                and events[-1].get("continuation_owner") == "server"
                and events[-1].get("assistant_text") == provider.marker, "edge_authoritative_answer_mismatch")
        persisted = request(origin, "/chat/runs/" + terminal["run_id"], token)
        require(persisted.get("run_id") == terminal["run_id"] and persisted.get("session_id") == session
                and persisted.get("status") == "completed", "edge_persisted_terminal_mismatch")
        require(provider.tool_result_seen, "edge_tool_result_not_returned")
        require(any(event.get("type") == "turn_complete" for event in events), "edge_authoritative_turn_missing")
    finally:
        provider.mode = "text"
        provider.tool_name = "write_file"


def edge_case(binary, env, home, origin, token, version, model, provider, report):
    begin_case(report, version, "edge_schema1_rejection" if version == "0.2.10" else "edge_handshake")
    edge_id = "compat-edge-" + version.replace(".", "-")
    with tempfile.TemporaryFile() as diagnostics:
        process = subprocess.Popen([str(binary), "--server-url", origin, "--workspace-dir", str(home),
                                    "--edge-id", edge_id, "--reconnect", "false"], env=env, cwd=home,
                                   stdout=subprocess.DEVNULL, stderr=diagnostics, start_new_session=True)
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                edges = request(origin, "/edges/status", token).get("edges", [])
                online = any(edge.get("edge_agent_id") == edge_id for edge in edges)
                if version == "0.2.12" and online:
                    edge_execution(home, origin, token, edge_id, model, provider, report, version)
                    return
                if process.poll() is not None:
                    diagnostics.seek(0)
                    detail = diagnostics.read().decode(errors="replace")
                    require(version == "0.2.10" and process.returncode != 0 and not online
                            and "schema v1" in detail and "upgrade" in detail.lower(), "edge_rejection_not_classified")
                    return
                time.sleep(0.1)
            raise Failure("edge_handshake_timeout")
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()


def bootstrap(origin, provider, provider_host):
    user = "compatibility_" + uuid.uuid4().hex
    password = uuid.uuid4().hex + "Aa9!"
    registered = request(origin, "/admin/register", payload={"username": user,
        "email": user + "@example.test", "password": password, "display_name": "CI compatibility"})
    token = registered["access_token"]
    model = "compatibility-" + uuid.uuid4().hex
    request(origin, "/models", token, {"name": model, "provider": "openai", "api_key": "synthetic-only",
        "base_url": "http://" + provider_host + ":" + str(provider.server.server_port) + "/v1",
        "context_window": 128000, "max_completion_tokens": 1024, "supported_parameters": ["tools"],
        "tags": ["chat", "code"], "quirks": {"thinking_protocol": "unknown"}})
    provider.expected_model = model
    return token, model, user, password


def rollback(args, artifacts, report):
    """The archived 0.2.12 CLI embeds that release's real HTTP Server owner."""
    begin_case(report, "candidate", "released_server_startup")
    require(bool(args.rollback_database), "rollback_database_required")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    origin = "http://127.0.0.1:" + str(port)
    keys = ("PATH", "LANG", "LC_ALL", "MATRIXONE_HOST", "MATRIXONE_PORT", "MATRIXONE_USER",
            "MATRIXONE_PASSWORD", "ASTRA_JWT_SECRET", "ASTRA_TOKEN_ENCRYPTION_KEY",
            "ASTRA_RUNTIME_ROOT_SECRET", "MEMORIA_BASE_URL", "MEMORIA_MASTER_KEY", "MEMORIA_SELF_HOSTED_MASTER_ACCESS")
    env = {key: os.environ[key] for key in keys if key in os.environ}
    env.update({"ASTRA_CONFIG_SOURCE": "explicit-env", "ASTRA_DATABASE": args.rollback_database,
                "ASTRA_AUTO_CREATE_DATABASE": "1", "ASTRA_API_HOST": "127.0.0.1", "ASTRA_API_PORT": str(port)})
    provider = Provider()
    with tempfile.TemporaryDirectory(prefix="astra-rollback-server-") as directory:
        home = Path(directory)
        env.update({"HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
                    "XDG_CACHE_HOME": str(home / ".cache"), "XDG_DATA_HOME": str(home / ".local/share")})
        process = subprocess.Popen([str(artifacts / "0.2.12" / "astra"), "serve", "http",
                                    "--host", "127.0.0.1", "--port", str(port)],
                                   env=env, cwd=home, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            deadline = time.monotonic() + 90
            ready = False
            while time.monotonic() < deadline:
                require(process.poll() is None, "released_server_exited")
                try:
                    ready = request(origin, "/ready").get("status") == "ready"
                except (Failure, urllib.error.URLError):
                    ready = False
                if ready:
                    break
                time.sleep(0.2)
            require(ready, "released_server_readiness_timeout")
            begin_case(report, "candidate", "released_server_source_identity")
            health = request(origin, "/health")
            require(health.get("build_git_sha") == "70a5ee3ec25bb3b02d3f591675a13abc33a85159",
                    "released_server_source_mismatch")
            begin_case(report, "candidate", "released_server_bootstrap")
            token, model, username, password = bootstrap(origin, provider, "127.0.0.1")
            provider.case = "rollback-chat"
            with tempfile.TemporaryDirectory(prefix="astra-rollback-client-") as client_directory:
                client_home = Path(client_directory)
                client_env = child_environment(client_home, origin, token)
                begin_case(report, "candidate", "login_against_released_server")
                authenticate_cli(args.current_cli.resolve(), client_env, client_home, origin, username, password)
                begin_case(report, "candidate", "catalog_against_released_server")
                listed = command(args.current_cli.resolve(), client_env, client_home,
                                 [*cli_base(origin, model), "model", "list"])
                require(listed.returncode == 0 and model in listed.stdout.decode(errors="replace"), "rollback_catalog_unreadable")
                begin_case(report, "candidate", "ordinary_chat_against_released_server")
                completed(command(args.current_cli.resolve(), client_env, client_home,
                    [*one_shot_chat_base(origin, model), "--json", "--no-resume", "-m", "Reply to the fixture: " + provider.marker]), provider.marker)
                require(not provider.errors, "rollback_provider_contract_failed")
            report["cases"].append({"client": "candidate", "case": "catalog_and_chat_against_released_server",
                "server_source": "70a5ee3ec25bb3b02d3f591675a13abc33a85159", "server_version": "0.2.12", "status": "passed"})
        finally:
            provider.close()
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()


def run(args, report):
    begin_case(report, "server", "disposable_server_admission")
    origin = args.api_url.rstrip("/")
    parsed = urllib.parse.urlsplit(origin)
    require(parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "::1")
            and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
            and parsed.path == "", "disposable_loopback_server_required")
    begin_case(report, "released", "component_download_and_identity")
    artifacts = prepare(args.artifacts)
    provider = Provider()
    try:
        begin_case(report, "server", "bootstrap")
        token, model, username, password = bootstrap(origin, provider, args.provider_host)
        for baseline in baseline_document()["baselines"]:
            version = baseline["version"]
            with tempfile.TemporaryDirectory(prefix="astra-compatibility-") as directory:
                home = Path(directory)
                env = child_environment(home, origin, token)
                begin_case(report, version, "edge_component_version")
                edge_identity = command(artifacts / version / "astra-edge", env, home, ["--version"])
                require(edge_identity.returncode == 0 and version in edge_identity.stdout.decode(), "edge_version_mismatch")
                binary = artifacts / version / "astra"
                begin_case(report, version, "cli_component_version")
                identity = command(binary, env, home, ["--version"])
                require(identity.returncode == 0 and version in identity.stdout.decode(), "client_version_mismatch")
                begin_case(report, version, "profile_login")
                authenticate_cli(binary, env, home, origin, username, password)
                begin_case(report, version, "model_catalog")
                listed = command(binary, env, home, [*cli_base(origin, model), "model", "list"])
                require(listed.returncode == 0 and model in listed.stdout.decode(errors="replace"), "historical_catalog_unreadable")
                report["cases"].append({"client": version, "case": "model_catalog", "status": "passed"})
                provider.case = version + "-ordinary-chat"
                begin_case(report, version, "unsupported_schema1_execution" if version == "0.2.10" else "ordinary_chat")
                chat = command(binary, env, home, [*one_shot_chat_base(origin, model), "--json", "--no-resume", "-m", "Reply to the fixture: " + provider.marker])
                if version == "0.2.10":
                    detail = (chat.stdout + chat.stderr).decode(errors="replace")
                    require(chat.returncode != 0 and "schema v1" in detail and "upgrade" in detail.lower(), "legacy_execution_not_explicitly_rejected")
                    report["cases"].append({"client": version, "case": "unsupported_schema1_execution", "status": "passed"})
                else:
                    completed(chat, provider.marker)
                    report["cases"].append({"client": version, "case": "ordinary_chat", "status": "passed"})
                    approvals(binary, env, home, origin, token, model, provider, report, version)
                    report["cases"].append({"client": version, "case": "tool_approval_allow_and_deny", "status": "passed"})
                    begin_case(report, version, "cancel_authoritative_settlement")
                    session, cancelled_run = cancellation(binary, env, home, origin, token, model, provider)
                    provider.case = "resume-after-cancellation"
                    begin_case(report, version, "resume_after_cancellation")
                    resumed = completed(command(binary, env, home, [*one_shot_chat_base(origin, model), "--json", "--session-id", session, "-m", "Continue after cancellation: " + provider.marker]), provider.marker)
                    require(resumed["session_id"] == session and resumed["run_id"] != cancelled_run,
                            "resume_run_identity_mismatch")
                    report["cases"].append({"client": version, "case": "cancel_and_resume", "status": "passed"})
                edge_case(artifacts / version / "astra-edge", env, home, origin, token, version, model, provider, report)
                report["cases"].append({"client": version, "case": "edge_handshake_and_tool_execution" if version == "0.2.12" else "edge_schema1_rejection", "status": "passed"})
        if args.current_cli is not None:
            with tempfile.TemporaryDirectory(prefix="astra-current-client-") as directory:
                home = Path(directory)
                env = child_environment(home, origin, token)
                begin_case(report, "candidate", "cli_component_identity")
                identify_current(args.current_cli.resolve(), env, home, report)
                begin_case(report, "candidate", "profile_login")
                authenticate_cli(args.current_cli.resolve(), env, home, origin, username, password)
                provider.case = "candidate-chat"
                begin_case(report, "candidate", "ordinary_chat")
                completed(command(args.current_cli.resolve(), env, home,
                    [*one_shot_chat_base(origin, model), "--json", "--no-resume", "-m", "Reply to the fixture: " + provider.marker]), provider.marker)
                report["cases"].append({"client": "candidate", "case": "ordinary_chat", "status": "passed"})
        require(not provider.errors, "provider_contract_failed")
    finally:
        with provider.lock:
            report["provider_error_categories"] = list(provider.errors)
            report["provider_phases"] = sorted([list(phase) for phase in provider.claimed])
        provider.close()
    if args.current_cli is not None:
        rollback(args, artifacts, report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--provider-host", default="127.0.0.1", choices=("127.0.0.1", "host.docker.internal"))
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--current-cli", type=Path)
    parser.add_argument("--rollback-database")
    parser.add_argument("--disposable-server", action="store_true", required=True)
    args = parser.parse_args()
    report = {"schema": 1, "platform": "linux-amd64", "baselines": baseline_document()["baselines"],
              "server_source": os.environ.get("ASTRA_COMPAT_SERVER_SOURCE"),
              "server_image_digest": os.environ.get("ASTRA_COMPAT_SERVER_IMAGE_DIGEST"), "cases": [], "status": "failed"}
    started = time.monotonic()
    signal.signal(signal.SIGALRM, deadline_exceeded)
    signal.signal(signal.SIGTERM, deadline_exceeded)
    signal.alarm(8 * 60)
    try:
        run(args, report)
        report["status"] = "passed"
        report["active_case"] = None
        report["active_client"] = None
    except Exception as error:
        report["failure_category"] = str(error) if isinstance(error, (Failure, ArtifactError)) else type(error).__name__
        if isinstance(error, Failure) and error.diagnostics is not None:
            report["diagnostics"] = error.diagnostics
    finally:
        signal.alarm(0)
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(report, indent=2) + "\n"
        args.report.write_text(serialized)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with Path(summary).open("a") as output:
                output.write("\n### Historical client compatibility\n\n```json\n" + serialized + "```\n")
    print("Historical client compatibility: " + report["status"])
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
