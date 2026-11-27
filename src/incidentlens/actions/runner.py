"""Human-approved one-click remediation actions.

Safety invariants:
- Only actions defined in the allowlist (config/actions.yaml) can run.
- Only Slack user IDs listed in `approvers` are authorized; an empty list denies everyone.
- The LLM has no path to invoke actions: the sole entrypoint is a verified Slack interaction.
- Commands run as an argument vector without a shell, and service names are validated first.
- Disabled by default (IL_ACTIONS_ENABLED=false): records a dry-run preview without executing.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from incidentlens.redact import is_safe_name, redact

Executor = Callable[[list[str], int], Awaitable[tuple[int, str]]]


class ActionSpec(BaseModel):
    label: str
    command: list[str] = Field(min_length=1)
    services: list[str] = Field(default_factory=lambda: ["*"])
    approvers: list[str] = Field(default_factory=list)  # Slack user IDs
    confirm: str | None = None
    timeout_seconds: int = 60
    cooldown_seconds: int = Field(default=300, ge=0)
    confirm_repeat: bool = True

    @field_validator("command")
    @classmethod
    def _no_empty(cls, value: list[str]) -> list[str]:
        if not value[0].strip():
            raise ValueError("Command must not be empty")
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
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, f"Timed out after {timeout}s; process killed"
    return proc.returncode or 0, out.decode(errors="replace")


class ActionRunner:
    def __init__(
        self,
        config: ActionsConfig | None = None,
        enabled: bool = False,
        executor: Executor = _exec,
    ) -> None:
        self._config = config or ActionsConfig()
        self._enabled = enabled
        self._executor = executor

    @property
    def enabled(self) -> bool:
        return self._enabled

    def available_for(self, service: str) -> list[tuple[str, ActionSpec]]:
        if not is_safe_name(service):
            return []
        return [(name, spec) for name, spec in self._config.actions.items() if spec.allows(service)]

    def label(self, name: str) -> str:
        spec = self._config.actions.get(name)
        return spec.label if spec else name

    def cooldown_for(self, name: str) -> int:
        spec = self._config.actions.get(name)
        return spec.cooldown_seconds if spec else 0

    def requires_reconfirm(self, name: str) -> bool:
        spec = self._config.actions.get(name)
        return spec.confirm_repeat if spec else True

    def authorize(self, name: str, service: str, user_id: str) -> ActionResult | None:
        spec = self._config.actions.get(name)
        if spec is None:
            return ActionResult(status="denied", message=f"Action `{name}` is not in the allowlist")
        if not is_safe_name(service):
            return ActionResult(status="denied", message="Invalid service name")
        if not spec.allows(service):
            return ActionResult(status="denied", message=f"`{name}` is not allowed on `{service}`")
        if user_id not in spec.approvers:
            return ActionResult(status="denied", message="You are not authorized to approve this action")
        return None

    async def run(self, name: str, service: str, user_id: str) -> ActionResult:
        denied = self.authorize(name, service, user_id)
        if denied is not None:
            return denied
        spec = self._config.actions[name]
        argv = [part.replace("{service}", service) for part in spec.command]
        shown = " ".join(argv)
        if not self._enabled:
            return ActionResult(
                status="dry-run",
                output=shown,
                message=f"Dry-run: would execute `{shown}` (enable IL_ACTIONS_ENABLED to run for real)",
            )
        try:
            code, output = await self._executor(argv, spec.timeout_seconds)
        except OSError as exc:
            return ActionResult(status="failed", output=str(exc), message=f"Failed to start command: {exc}")
        output = redact(output)[-2000:]
        if code == 0:
            return ActionResult(
                status="executed", exit_code=0, output=output, message=f"Executed `{shown}` successfully"
            )
        return ActionResult(
            status="failed", exit_code=code, output=output, message=f"Command `{shown}` failed (exit code {code})"
        )
