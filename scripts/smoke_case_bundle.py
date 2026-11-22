"""Run the evidence workflow from a built portable archive outside the source tree."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path


def smoke(bundle: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="ctftk-bundle-") as working:
        folder = Path(working)
        directory = folder / "review"
        environment = dict(os.environ, SHIV_ROOT=str(folder / "cache"))
        command = [sys.executable, "-I", str(bundle.resolve())]

        def run(*arguments: str):
            completed = subprocess.run(command + list(arguments), cwd=folder, env=environment,
                                       capture_output=True, check=True, timeout=180)
            return json.loads(completed.stdout)

        case = ("case", "--dir", str(directory))
        doctor = run("doctor", "--json")
        root, = run(*case, "demo", "layered")
        analysis = run(*case, "analyze", root["id"])
        result = run(*case, "transform", analysis["artifacts"][2], "--recipe", "b64d")
        assert result["output_sha256"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        report = run(*case, "verify", "--replay")
        assert report["ok"] and report["replayed_runs"] == 2

        with subprocess.Popen(command + list(case) + ["serve", "--port", "0"], cwd=folder,
                              env=environment, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as server:
            startup: queue.Queue[bytes] = queue.Queue()
            threading.Thread(target=lambda: startup.put(server.stdout.readline()), daemon=True).start()
            try:
                line = startup.get(timeout=45).decode("utf-8").strip()
                if not line.startswith("CTF Toolkit Workbench"):
                    raise RuntimeError("Bundled Workbench did not start")
                url = line.split()[-1]
                with urllib.request.urlopen(url + "assets/app.js", timeout=10) as response:
                    assert response.status == 200 and b"function openArtifact" in response.read()
            finally:
                server.terminate()
                server.wait(timeout=15)
        print(f"Portable Toolkit {doctor['toolkit']}: two replayed runs and bundled browser assets")


if __name__ == "__main__":
    smoke(Path(sys.argv[1]))
