from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import threading

from incidentlens.outputs.archive import DigestArchive


AT = datetime(2026, 11, 12, 2, 16, tzinfo=timezone.utc)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True, timeout=10
    ).stdout.strip()


def test_digests_in_same_minute_preserve_both_contents(tmp_path):
    archive = DigestArchive(tmp_path)
    first = archive.write("first digest", AT)
    second = archive.write("second digest", AT + timedelta(seconds=20))

    assert first != second
    assert first.read_text(encoding="utf-8") == "first digest"
    assert second.read_text(encoding="utf-8") == "second digest"


def test_concurrent_digest_writes_preserve_every_digest(tmp_path):
    archive = DigestArchive(tmp_path)
    contents = [f"digest {number}" for number in range(12)]
    with ThreadPoolExecutor(max_workers=6) as executor:
        paths = list(executor.map(lambda content: archive.write(content, AT), contents))

    assert len(set(paths)) == len(contents)
    assert [path.read_text(encoding="utf-8") for path in paths] == contents


def test_clean_sync_retries_failed_push_after_restart(tmp_path):
    repo, remote = tmp_path / "archive", tmp_path / "remote.git"
    git(tmp_path, "init", "--quiet", str(repo))
    git(repo, "remote", "add", "origin", str(remote))
    archive = DigestArchive(repo, git_push=True)
    archive.write("a digest awaiting its remote", AT)

    assert archive.sync("archive digest") is True
    committed = git(repo, "rev-parse", "HEAD")
    assert git(repo, "status", "--porcelain") == ""

    git(tmp_path, "init", "--quiet", "--bare", str(remote))
    restarted = DigestArchive(repo, git_push=True)
    assert restarted.sync("retry push") is False  # no new local commit
    assert git(remote, "rev-parse", "HEAD") == committed
    assert git(repo, "rev-list", "--count", "HEAD") == "1"


def test_concurrent_syncs_do_not_mix_staged_changes(tmp_path, monkeypatch):
    git(tmp_path, "init", "--quiet")
    archive = DigestArchive(tmp_path, git_push=True)
    archive.write_named("first.md", "first")
    first_staged = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()
    second_staged = threading.Event()
    original_git = archive._git

    def pause_after_staging(*args):
        result = original_git(*args)
        if args == ("add", "-A"):
            if not first_staged.is_set():
                first_staged.set()
                assert release_first.wait(timeout=10)
            else:
                second_staged.set()
        return result

    def second_sync():
        second_started.set()
        return archive.sync("second digest")

    monkeypatch.setattr(archive, "_git", pause_after_staging)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(archive.sync, "first digest")
        try:
            assert first_staged.wait(timeout=10)
            archive.write_named("second.md", "second")
            second = executor.submit(second_sync)
            assert second_started.wait(timeout=10)
            if second_staged.wait(timeout=0.2):
                second.result(timeout=10)
        finally:
            release_first.set()
        assert first.result(timeout=10) is True
        assert second.result(timeout=10) is True

    assert git(tmp_path, "log", "--format=%s").splitlines() == ["second digest", "first digest"]
    assert git(tmp_path, "show", "HEAD~1:first.md") == "first"
    assert git(tmp_path, "show", "HEAD:second.md") == "second"
