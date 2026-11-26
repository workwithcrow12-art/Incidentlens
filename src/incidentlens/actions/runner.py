"""Hành động một chạm, có người duyệt.

Nguyên tắc an toàn:
- Chỉ chạy các hành động nằm trong danh sách cho phép (config/actions.yaml).
- Chỉ người có tên trong `approvers` mới được bấm. Danh sách rỗng = không ai được phép.
- AI không có đường nào để gọi vào đây: lối vào duy nhất là nút bấm Slack đã xác thực chữ ký.
- Lệnh chạy dạng danh sách tham số (không qua shell); tên dịch vụ được kiểm tra trước khi chèn vào.
- Mặc định tắt (IL_ACTIONS_ENABLED=false): chỉ ghi lại lệnh SẼ chạy, không chạy thật.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from incidentlens.redact import is_safe_name, redact


class ActionSpec(BaseModel):
    label: str
    command: list[str] = Field(min_length=1)
    services: list[str] = Field(default_factory=lambda: ["*"])
    approvers: list[str] = Field(default_factory=list)  # Slack user ID
    confirm: str | None = None
    timeout_seconds: int = 60

    @field_validator("command")
    @classmethod
    def _no_empty(cls, value: list[str]) -> list[str]:
        if not value[0].strip():
            raise ValueError("Lệnh không được rỗng")
        return value

    def allows(self, service: str) -> bool:
        return "*" in self.services or service in self.services


class ActionsConfig(BaseModel):
    actions: dict[str, ActionSpec] = Field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: Path) -> ActionsConfig:
        if not Path(path).exists():
            return cls()
        return cls.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})


class ActionResult(BaseModel):
    status: Literal["executed", "failed", "denied", "dry-run"]
    message: str
    exit_code: int | None = None
    output: str = ""


async def _exec(argv: list[str], timeout: int) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, f"Quá thời gian {timeout} giây, đã dừng lệnh"
    return proc.returncode or 0, out.decode(errors="replace")


class ActionRunner:
    def __init__(self, config: ActionsConfig | None = None, enabled: bool = False, executor=_exec) -> None:
        self._config = config or ActionsConfig()
        self._enabled = enabled
        self._executor = executor

    def available_for(self, service: str) -> list[tuple[str, ActionSpec]]:
        if not is_safe_name(service):
            return []
        return [(name, spec) for name, spec in self._config.actions.items() if spec.allows(service)]

    def label(self, name: str) -> str:
        spec = self._config.actions.get(name)
        return spec.label if spec else name

    async def run(self, name: str, service: str, user_id: str) -> ActionResult:
        spec = self._config.actions.get(name)
        if spec is None:
            return ActionResult(status="denied", message=f"Hành động `{name}` không nằm trong danh sách cho phép")
        if not is_safe_name(service):
            return ActionResult(status="denied", message="Tên dịch vụ không hợp lệ")
        if not spec.allows(service):
            return ActionResult(status="denied", message=f"`{name}` không được phép chạy trên `{service}`")
        if user_id not in spec.approvers:
            return ActionResult(status="denied", message="Bạn không có quyền duyệt hành động này")

        argv = [part.replace("{service}", service) for part in spec.command]
        shown = " ".join(argv)
        if not self._enabled:
            return ActionResult(status="dry-run", output=shown,
                                message=f"Chế độ thử: lệnh sẽ chạy là `{shown}` (bật IL_ACTIONS_ENABLED để chạy thật)")
        try:
            code, output = await self._executor(argv, spec.timeout_seconds)
        except OSError as exc:
            return ActionResult(status="failed", output=str(exc), message=f"Không chạy được lệnh: {exc}")
        output = redact(output)[-2000:]
        if code == 0:
            return ActionResult(status="executed", exit_code=0, output=output, message=f"Đã chạy `{shown}` thành công")
        return ActionResult(status="failed", exit_code=code, output=output,
                            message=f"Lệnh `{shown}` thất bại (mã {code})")
