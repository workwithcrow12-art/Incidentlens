"""Persist digests, postmortems, and ROI reports as Markdown files with optional Git sync.

Layout:  <root>/YYYY/MM/digest-YYYYMMDD-HHMM.md
         <root>/postmortems/INC-0001.md
         <root>/reports/roi-YYYY-MM.md
"""

from __future__ import annotations

from datetime import datetime
import logging
from pathlib import Path
import subprocess
from threading import Lock

log = logging.getLogger(__name__)


class DigestArchive:
    def __init__(self, root: Path, git_push: bool = False) -> None:
        self.root = Path(root)
        self._git_push = git_push
        self._sync_lock = Lock()

    @property
    def git_push(self) -> bool:
        return self._git_push

    def write(self, markdown: str, at: datetime) -> Path:
        base = self.root / f"{at:%Y}/{at:%m}/digest-{at:%Y%m%d-%H%M}.md"
        base.parent.mkdir(parents=True, exist_ok=True)
        path, suffix = base, 2
        while True:
            try:
                with path.open("x", encoding="utf-8") as handle:
                    handle.write(markdown)
                return path
            except FileExistsError:
                path = base.with_name(f"{base.stem}-{suffix}{base.suffix}")
                suffix += 1

    def write_named(self, relative: str, markdown: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(markdown, encoding="utf-8")
        return path

    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", "-C", str(self.root), *args], capture_output=True, text=True, timeout=60)

    def sync(self, message: str) -> bool:
        """Stage and commit new changes, then push to the first remote even if the index was already clean.

        Returns True when a new local commit was created. Git failures are logged without raising.
        """
        if not self._git_push:
            return False
        with self._sync_lock:
            try:
                if not (self.root / ".git").exists():
                    log.warning("%s is not a Git repository; skipping archive sync", self.root)
                    return False
                self._git("add", "-A")
                changed = self._git("diff", "--cached", "--quiet").returncode != 0
                if changed:
                    commit = self._git(
                        "-c",
                        "user.name=IncidentLens",
                        "-c",
                        "user.email=incidentlens@localhost",
                        "commit",
                        "-m",
                        message,
                    )
                    if commit.returncode != 0:
                        log.error("git commit failed: %s", commit.stderr.strip())
                        return False
                remotes = self._git("remote").stdout.split()
                if remotes:
                    push = self._git("push", remotes[0], "HEAD")
                    if push.returncode != 0:
                        log.error("git push failed: %s", push.stderr.strip())
                return changed
            except (OSError, subprocess.SubprocessError) as exc:
                log.error("Git archive sync failed: %s", exc)
                return False
