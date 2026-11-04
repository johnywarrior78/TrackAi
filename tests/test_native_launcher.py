"""Native launch regression checks, including Finder/launchd working directories."""

import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

from typer.testing import CliRunner

from app.cli import cli


def test_launcher_anchors_project_and_preserves_arguments(tmp_path):
    root = tmp_path / "A project with spaces"
    (root / "scripts").mkdir(parents=True)
    (root / ".venv" / "bin").mkdir(parents=True)
    launcher = root / "scripts" / "aivi"
    shutil.copyfile(Path("scripts/aivi"), launcher)
    # A fake interpreter observes invocation without accessing any database.
    python = root / ".venv" / "bin" / "python"
    observer = root / "observe.py"
    observer.write_text(
        "import os,sys,json\n"
        "print(json.dumps({'cwd':os.getcwd(),'args':sys.argv[1:]}))\n"
    )
    python.write_text(
        f'#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(observer))} "$@"\n'
    )
    python.chmod(0o755)
    result = subprocess.run(
        ["/bin/bash", str(launcher), "report", "--start", "value with spaces;$literal"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    observed = json.loads(result.stdout)
    assert observed["cwd"] == str(root.resolve())
    assert observed["args"] == [
        "-m",
        "app.cli",
        "report",
        "--start",
        "value with spaces;$literal",
    ]


def test_dashboard_port_and_localhost(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "app.cli.subprocess.run", lambda args, **kwargs: calls.append(args)
    )
    result = CliRunner().invoke(cli, ["dashboard", "--port", "8502"])
    assert result.exit_code == 0
    assert calls[0][calls[0].index("--server.headless") + 1] == "true"
    assert calls[0][calls[0].index("--browser.gatherUsageStats") + 1] == "false"
    assert calls[0][-4:] == ["--server.address", "127.0.0.1", "--server.port", "8502"]
    assert CliRunner().invoke(cli, ["dashboard", "--port", "0"]).exit_code != 0
