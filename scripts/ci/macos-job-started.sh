#!/bin/bash
# Install root-owned outside every runner-writable path. No sourced PR code.
set -euo pipefail
/usr/bin/python3 -I -c '
import json, os, subprocess
from pathlib import Path
event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
head = event.get("pull_request", {}).get("head", {}).get("sha") or event.get("after")
if not head:
    raise SystemExit("Use a fresh pull_request_target event for self-hosted admission")
request = {"run_id": int(os.environ["GITHUB_RUN_ID"]),
           "attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "head": head}
subprocess.run(["/usr/bin/sudo", "-n", "-u", "astra-ci-admission", "/opt/astra-ci/bin/admit"],
               input=json.dumps(request), text=True, check=True, timeout=100)
'
