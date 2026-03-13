from __future__ import annotations

import asyncio
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class ExecutionResult:
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float


async def run_command(
    command: list[str],
    cwd: Path,
    timeout_seconds: int,
    env_overrides: dict[str, str] | None = None,
) -> ExecutionResult:
    started_at = time.perf_counter()
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)

    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(cwd),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise TimeoutError(f"Command timed out after {timeout_seconds} seconds: {' '.join(command)}")

    return ExecutionResult(
        command=command,
        exit_code=process.returncode,
        stdout=stdout_bytes.decode("utf-8", errors="replace"),
        stderr=stderr_bytes.decode("utf-8", errors="replace"),
        duration_seconds=round(time.perf_counter() - started_at, 3),
    )
