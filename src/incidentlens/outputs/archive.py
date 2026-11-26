"""Lưu digest, postmortem và báo cáo thành file Markdown; tùy chọn commit + push lên Git.

Bố cục:  <thư mục gốc>/YYYY/MM/digest-YYYYMMDD-HHMM.md
         <thư mục gốc>/postmortems/INC-0001.md
         <thư mục gốc>/reports/roi-YYYY-MM.md
"""

from __future__ import annotations

import logging
import subprocess
from datetime import datetime
from pathlib import Path
from threading import Lock

log = logging.getLogger(__name__)


class DigestArchive:
    def __init__(self, root: Path, git_push: bool = False) -> None:
        self.root = Path(root)
        self._git_push = git_push
        self._sync_lock = Lock()

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

    def _git(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(self.root), *args], capture_output=True, text=True, timeout=60)

    def sync(self, message: str) -> bool:
        """Commit thay đổi và thử push cả khi index sạch. True nghĩa là đã tạo commit mới.

        Lỗi Git chỉ ghi log, không làm hỏng luồng chính.
        """
        if not self._git_push:
            return False
        with self._sync_lock:
            try:
                if not (self.root / ".git").exists():
                    log.warning("%s chưa phải Git repo, bỏ qua đồng bộ", self.root)
                    return False
                self._git("add", "-A")
                changed = self._git("diff", "--cached", "--quiet").returncode != 0
                if changed:
                    commit = self._git("-c", "user.name=IncidentLens", "-c", "user.email=incidentlens@localhost",
                                       "commit", "-m", message)
                    if commit.returncode != 0:
                        log.error("git commit thất bại: %s", commit.stderr.strip())
                        return False
                remotes = self._git("remote").stdout.split()
                if remotes:
                    push = self._git("push", remotes[0], "HEAD")
                    if push.returncode != 0:
                        log.error("git push thất bại: %s", push.stderr.strip())
                return changed
            except (OSError, subprocess.SubprocessError) as exc:
                log.error("Đồng bộ Git lỗi: %s", exc)
                return False
