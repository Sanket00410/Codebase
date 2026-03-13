from __future__ import annotations

import json
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from security_platform.core.binary_manager import BinaryManager
from security_platform.core.config import settings
from security_platform.core.models import (
    BinaryStatus,
    PluginRunResult,
    ReportArtifact,
    RepositorySignal,
    ScanCategory,
    ScanRequest,
    ToolExecution,
    ToolMetadata,
)
from security_platform.core.process import ExecutionResult, run_command


@dataclass(slots=True)
class ScanExecutionContext:
    scan_id: str
    repository_signal: RepositorySignal
    dependency_graph: dict
    excluded_paths: list[str] = field(default_factory=list)
    shared_artifacts: dict[str, ReportArtifact] = field(default_factory=dict)


class ScannerPlugin(ABC):
    metadata: ToolMetadata
    accepted_exit_codes: set[int] = {0}
    emits_output_file: bool = True
    output_extension: str = "json"
    media_type: str = "application/json"
    phase: int = 1

    def __init__(self, binary_manager: BinaryManager) -> None:
        self.binary_manager = binary_manager

    @abstractmethod
    def build_command(
        self,
        binary_path: Path,
        repository_path: Path,
        output_path: Path | None,
        request: ScanRequest,
        context: ScanExecutionContext,
    ) -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def parse_results(
        self,
        repository_path: Path,
        execution: ExecutionResult,
        output_path: Path | None,
        context: ScanExecutionContext,
    ) -> tuple[list, list[ReportArtifact]]:
        raise NotImplementedError

    def should_run(self, request: ScanRequest, signal: RepositorySignal) -> bool:
        if request.tools and self.metadata.name not in request.tools:
            return False
        if request.categories and self.metadata.category not in request.categories:
            return False
        return True

    def environment(
        self,
        repository_path: Path,
        request: ScanRequest,
        context: ScanExecutionContext,
    ) -> dict[str, str]:
        return {}

    async def binary_status(self) -> BinaryStatus:
        return await self.binary_manager.get_status(self.metadata.name)

    async def run(self, repository_path: Path, request: ScanRequest, context: ScanExecutionContext) -> PluginRunResult:
        binary = await self.binary_status()
        if not binary.available or not binary.resolved_path:
            raise FileNotFoundError(binary.install_hint or f"Tool {self.metadata.name} is not installed")

        output_path: Path | None = None
        with tempfile.TemporaryDirectory(prefix=f"{self.metadata.name}-", dir=settings.cache_dir) as tmp_dir:
            temp_dir = Path(tmp_dir)
            if self.emits_output_file:
                output_path = temp_dir / f"{self.metadata.name}.{self.output_extension}"
            command = self.build_command(Path(binary.resolved_path), repository_path, output_path, request, context)
            execution = await run_command(
                command,
                repository_path,
                timeout_seconds=settings.process_timeout_seconds,
                env_overrides=self.environment(repository_path, request, context),
            )
            if execution.exit_code not in self.accepted_exit_codes:
                raise RuntimeError(f"{self.metadata.name} exited with {execution.exit_code}: {execution.stderr.strip()}")
            stable_output_path = output_path
            if output_path and output_path.exists():
                raw_copy = settings.reports_dir / context.scan_id / f"{self.metadata.name}-raw{output_path.suffix}"
                raw_copy.parent.mkdir(parents=True, exist_ok=True)
                raw_copy.write_bytes(output_path.read_bytes())
                stable_output_path = raw_copy
            findings, artifacts = self.parse_results(repository_path, execution, stable_output_path, context)
            if output_path and output_path.exists():
                artifacts.append(ReportArtifact(kind=f"{self.metadata.name}-raw", path=str(stable_output_path), media_type=self.media_type))

        return PluginRunResult(
            tool=self.metadata.name,
            category=self.metadata.category,
            findings=findings,
            artifacts=artifacts,
            execution=ToolExecution(
                tool=self.metadata.name,
                category=self.metadata.category,
                command=command,
                duration_seconds=execution.duration_seconds,
                exit_code=execution.exit_code,
                stdout=execution.stdout[:10000],
                stderr=execution.stderr[:10000],
                output_files=[artifact.path for artifact in artifacts],
                binary_path=binary.resolved_path,
            ),
        )


class JsonFilePlugin(ScannerPlugin, ABC):
    def parse_results(
        self,
        repository_path: Path,
        execution: ExecutionResult,
        output_path: Path | None,
        context: ScanExecutionContext,
    ) -> tuple[list, list[ReportArtifact]]:
        if not output_path or not output_path.exists():
            raise FileNotFoundError(f"{self.metadata.name} did not create the expected output file")
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        return self.parse_payload(repository_path, payload, output_path, context)

    @abstractmethod
    def parse_payload(self, repository_path: Path, payload: dict, output_path: Path, context: ScanExecutionContext) -> tuple[list, list[ReportArtifact]]:
        raise NotImplementedError


class JsonStdoutPlugin(ScannerPlugin, ABC):
    emits_output_file = False

    def parse_results(
        self,
        repository_path: Path,
        execution: ExecutionResult,
        output_path: Path | None,
        context: ScanExecutionContext,
    ) -> tuple[list, list[ReportArtifact]]:
        payload = _parse_json_stdout(execution.stdout)
        return self.parse_payload(repository_path, payload, context)

    @abstractmethod
    def parse_payload(self, repository_path: Path, payload: dict, context: ScanExecutionContext) -> tuple[list, list[ReportArtifact]]:
        raise NotImplementedError


def _parse_json_stdout(stdout: str):
    text = stdout.strip()
    if not text:
        raise ValueError("Expected JSON on stdout but command returned an empty payload")
    if text[0] in {"{", "["}:
        return json.loads(text)

    object_index = text.find("{")
    array_index = text.find("[")
    candidates = [index for index in (object_index, array_index) if index != -1]
    if not candidates:
        raise ValueError("Unable to locate JSON payload in stdout")
    start = min(candidates)
    end = max(text.rfind("}"), text.rfind("]"))
    if end <= start:
        raise ValueError("Unable to determine JSON payload bounds in stdout")
    return json.loads(text[start : end + 1])
