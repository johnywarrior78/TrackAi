"""No date cutoff: discover historical AI-organization credits in official CVEs.

A pinned tar snapshot is streamed from disk without extracting archive members.
Checkpoints advance after committed batches, including batches without matches.
"""

import json
import logging
from pathlib import Path
import re
import tarfile

from sqlalchemy import select
from app.database.models import Identifier, now

log = logging.getLogger("history")
MEMBER = re.compile(r"(?:^|/)cves/\d{4}/[^/]+/(CVE-\d{4}-\d{4,19})\.json$")
MAX_RECORD_BYTES = 8 * 1024 * 1024


def history_pages(adapter, checkpoint):
    from app.adapters.sources import Page

    settings = adapter.settings
    checkpoint = {k: v for k, v in checkpoint.items() if k != "cve"}
    history = dict(checkpoint.get("history", {}))
    if history.get("complete"):
        return
    tracked = set()
    with adapter.sessions() as session:
        tracked.update(
            session.scalars(select(Identifier.value).where(Identifier.kind == "CVE"))
        )
    if settings.cve_repo_path:
        folder = Path(settings.cve_repo_path).resolve() / "cves"
        if not folder.is_dir():
            raise ValueError("CVE_REPO_PATH must contain the official cves directory")
        history.setdefault("revision", str(folder))
        history["mode"] = "local"

        def objects():
            # Only a directory listing at a time; never materialize the corpus.
            for year in sorted(folder.iterdir()):
                if not year.is_dir():
                    continue
                for bucket in sorted(year.iterdir()):
                    if not bucket.is_dir():
                        continue
                    for path in sorted(bucket.glob("CVE-*.json")):
                        if path.stat().st_size > MAX_RECORD_BYTES:
                            raise ValueError("CVE record exceeds safety limit")
                        yield path.stem, lambda p=path: p.read_bytes()

        iterator = objects()
    else:
        revision = history.get("revision")
        if not revision:
            metadata = adapter.http.get(
                "https://api.github.com/repos/CVEProject/cvelistV5/commits/main"
            )
            revision = metadata["sha"]
        if not re.fullmatch("[0-9a-f]{40}", revision):
            raise ValueError("Invalid CVE snapshot revision")
        history.update(mode="archive", revision=revision)
        # Pin the revision BEFORE downloading so failure resumes the same snapshot.
        yield Page([], {**checkpoint, "history": history})
        archive = settings.cache_dir / "cve" / (revision + ".tar.gz")
        if not archive.exists():
            log.info(
                "downloading_official_cve_history",
                extra={"fields": {"revision": revision}},
            )
            adapter.http.download(
                f"https://codeload.github.com/CVEProject/cvelistV5/tar.gz/{revision}",
                archive,
                settings.cve_archive_max_bytes,
            )

        def objects():
            expanded = 0
            with tarfile.open(archive, mode="r|gz") as handle:
                for member in handle:
                    expanded += max(0, member.size)
                    if expanded > 16 * 1024**3:
                        raise ValueError("Expanded CVE archive exceeds safety limit")
                    match = MEMBER.search(member.name)
                    if not match:
                        continue
                    if not member.isfile() or member.size > MAX_RECORD_BYTES:
                        raise ValueError("Invalid CVE archive member")

                    def read(m=member):
                        with handle.extractfile(m) as content:
                            return content.read(MAX_RECORD_BYTES + 1)

                    yield match.group(1), read

        iterator = objects()
    cursor = int(history.get("scanned", 0))
    scanned = 0
    batch = []
    matched = int(history.get("matched", 0))
    for cve, read in iterator:
        scanned += 1
        if scanned <= cursor:
            continue
        data = json.loads(read())
        # Normalize only relevant records. Product mentions alone are NOT credits.
        claims = adapter.attributions(data)
        if claims or cve in tracked:
            record = adapter.normalize(data)
            batch.append(record)
            matched += 1
        if scanned % settings.history_batch_size == 0:
            history = {
                **history,
                "scanned": scanned,
                "matched": matched,
                "complete": False,
            }
            yield Page(batch, {**checkpoint, "history": history})
            log.info(
                "historical_cve_progress",
                extra={"fields": {"scanned": scanned, "matched": matched}},
            )
            batch = []
    if scanned == 0 or scanned < cursor:
        raise ValueError(
            "Empty or changed historical CVE snapshot; initialization incomplete"
        )
    history = {
        **history,
        "scanned": scanned,
        "matched": matched,
        "complete": True,
        "completed_at": now().isoformat(),
    }
    yield Page(batch, {**checkpoint, "history": history})
