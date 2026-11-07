import pytest
from app.adapters.http import PublicHTTP

URL = "https://codeload.github.com/CVEProject/cvelistV5/tar.gz/" + "a" * 40


def test_archive_streaming_restarts_when_ranges_unsupported(
    db, tmp_path, httpx_mock, monkeypatch
):
    monkeypatch.setattr("app.adapters.http.validate_url", lambda url: url)
    path = tmp_path / "archive.gz"
    path.with_suffix(".gz.part").write_bytes(b"old")
    httpx_mock.add_response(url=URL, content=b"new archive", status_code=200)
    http = PublicHTTP(db[2])
    http.download(URL, path, 1024)
    http.close()
    assert path.read_bytes() == b"new archive"
    assert httpx_mock.get_requests()[0].headers["range"] == "bytes=3-"


def test_archive_resumes_and_enforces_limit(db, tmp_path, httpx_mock, monkeypatch):
    monkeypatch.setattr("app.adapters.http.validate_url", lambda url: url)
    path = tmp_path / "archive.gz"
    path.with_suffix(".gz.part").write_bytes(b"abc")
    httpx_mock.add_response(
        url=URL,
        content=b"def",
        status_code=206,
        headers={"Content-Range": "bytes 3-5/6"},
    )
    http = PublicHTTP(db[2])
    http.download(URL, path, 6)
    assert path.read_bytes() == b"abcdef"
    http.close()
    httpx_mock.add_response(url=URL, content=b"01234567")
    http = PublicHTTP(db[2])
    with pytest.raises(ValueError):
        http.download(URL, tmp_path / "too-big.gz", 2)
    http.close()


def test_large_download_only_accepts_pinned_official_snapshot(db, tmp_path):
    http = PublicHTTP(db[2])
    with pytest.raises(ValueError):
        http.download(
            "https://codeload.github.com/other/repo/tar.gz/main", tmp_path / "bad", 100
        )
    http.close()
