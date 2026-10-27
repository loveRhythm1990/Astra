#!/usr/bin/env python3
"""Resolve reviewed immutable client archives without touching an installation.

The reviewed baseline is intentionally independent of moving release channels.
Cache hits are checked again; failures never select a different client version.
"""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import tarfile
import tempfile
import urllib.request


BASELINES = Path(__file__).with_name("historical-clients.json")


class ArtifactError(RuntimeError):
    pass


def baseline_document():
    return json.loads(BASELINES.read_text())


def prepare(destination):
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise ArtifactError("historical_platform_unsupported")
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    for baseline in baseline_document()["baselines"]:
        for component, artifact in baseline["components"].items():
            archive = destination / (artifact["sha256"] + ".tar.gz")
            if not archive.exists():
                request = urllib.request.Request(artifact["url"], headers={"User-Agent": "Astra-compatibility-CI"})
                # Do not retain partial downloads under the cache key.
                with tempfile.NamedTemporaryFile(dir=destination, delete=False) as temporary:
                    temporary_path = Path(temporary.name)
                    try:
                        with urllib.request.urlopen(request, timeout=120) as response:
                            if not response.url.startswith("https://"):
                                raise ArtifactError("historical_archive_transport_changed")
                            shutil.copyfileobj(response, temporary)
                    except BaseException:
                        temporary_path.unlink(missing_ok=True)
                        raise
                temporary_path.replace(archive)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            if archive.stat().st_size != artifact["size"] or digest != artifact["sha256"]:
                raise ArtifactError("historical_archive_identity_mismatch")
            output = destination / baseline["version"] / component
            output.parent.mkdir(parents=True, exist_ok=True)
            with tarfile.open(archive, "r:gz") as bundle:
                matches = [member for member in bundle if member.isfile() and Path(member.name).name == component]
                if len(matches) != 1:
                    raise ArtifactError("historical_archive_binary_ambiguous")
                source = bundle.extractfile(matches[0])
                if source is None:
                    raise ArtifactError("historical_archive_binary_unreadable")
                with source, output.open("wb") as target:
                    shutil.copyfileobj(source, target)
            output.chmod(0o700)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.destination)
    print("Historical client archives verified and extracted.")


if __name__ == "__main__":
    main()
