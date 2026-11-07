"""Offline native startup check using disposable data and a free local TCP port.

Run with the installed project's Python. Never changes the user's database,
reports, collection checkpoints or running dashboard.
"""

import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from urllib.error import URLError
from urllib.request import urlopen

from openpyxl import load_workbook


def main():
    root = Path(__file__).resolve().parents[1]
    launcher = root / "scripts" / "aivi"
    # Import the compiled dependencies: this detects incompatible native wheels.
    import pandas
    import psycopg
    import pyarrow

    print(
        f"Native imports OK: pandas {pandas.__version__}, "
        f"psycopg {psycopg.__version__}, pyarrow {pyarrow.__version__}",
        flush=True,
    )
    print(f"Python base: {sys.base_prefix}", flush=True)
    with TemporaryDirectory(prefix="aivi native smoke ") as temp:
        folder = Path(temp)
        env = dict(
            os.environ,
            DATABASE_URL=f"sqlite:///{folder / 'test database.db'}",
            REPORT_DIR=str(folder / "test reports"),
            LOG_DIR=str(folder / "test logs"),
            STREAMLIT_BROWSER_GATHER_USAGE_STATS="false",
            AUTO_BACKFILL="false",
        )
        for command in ("init-db", "report"):
            subprocess.run(
                [str(launcher), command],
                # Deliberately outside the project to exercise path anchoring.
                cwd=folder,
                env=env,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            print(f"CLI {command} OK from another directory", flush=True)
        reports = list((folder / "test reports").glob("*.xlsx"))
        assert len(reports) == 1, "Expected one isolated report"
        book = load_workbook(reports[0], read_only=False)
        assert len(book.sheetnames) == 8
        assert book["New Vulnerabilities"].max_row == 1
        for sheet in book:
            assert sheet.freeze_panes == "A2"
        book.close()
        print("Excel baseline workbook OK", flush=True)

        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        log_path = folder / "dashboard.log"
        with log_path.open("w") as log:
            process = subprocess.Popen(
                [str(launcher), "dashboard", "--port", str(port)],
                cwd=folder,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError(log_path.read_text())
                    try:
                        with urlopen(
                            f"http://127.0.0.1:{port}/_stcore/health", timeout=1
                        ) as response:
                            if response.status == 200 and response.read() == b"ok":
                                break
                    except (URLError, TimeoutError, ConnectionError):
                        pass
                    time.sleep(0.2)
                else:
                    raise RuntimeError(
                        "Dashboard startup timed out: " + log_path.read_text()
                    )
                print("Native dashboard HTTP health OK", flush=True)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
    print("Native startup smoke check passed; temporary services/data removed.")


if __name__ == "__main__":
    main()
