from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from security_platform.ai.triage import AITriageEngine
from security_platform.core.advisories import AdvisoryManager
from security_platform.core.binary_manager import BinaryManager
from security_platform.core.config import settings
from security_platform.core.correlation import correlate_findings
from security_platform.core.models import PluginDescriptor, PluginRunResult, ScanRequest, ScanResult, ScanStatus
from security_platform.core.plugin import ScanExecutionContext
from security_platform.core.reporting import default_report_profile_ids, generate_reports, resolve_report_profile_ids
from security_platform.core.repository import analyze_repository
from security_platform.core.scoring import summarize_findings
from security_platform.core.storage import ScanStore
from security_platform.core.utils import filter_findings_by_excluded_paths
from security_platform.plugins.registry import all_plugins, plugin_descriptors


class ScanOrchestrator:
    def __init__(self) -> None:
        self.store = ScanStore(settings.db_path)
        self.binary_manager = BinaryManager(settings)
        self.advisory_manager = AdvisoryManager(self.store, self.binary_manager, settings)
        self.ai_engine = AITriageEngine(settings)
        self._tasks: dict[str, asyncio.Task] = {}

    async def create_scan(self, request: ScanRequest) -> ScanResult:
        repository_path = Path(request.repository_path).expanduser().resolve()
        if not repository_path.exists():
            raise FileNotFoundError(f"Repository does not exist: {repository_path}")
        if not repository_path.is_dir():
            raise NotADirectoryError(f"Repository path is not a directory: {repository_path}")

        signal, dependency_graph = analyze_repository(repository_path)
        scan_id = str(uuid4())
        result = ScanResult(
            scan_id=scan_id,
            status=ScanStatus.QUEUED,
            repository_path=str(repository_path),
            started_at=datetime.now(timezone.utc).isoformat(),
            repository_signal=signal,
            dependency_graph=dependency_graph,
        )
        self.store.upsert_scan(result)
        self._tasks[scan_id] = asyncio.create_task(self._execute_scan(scan_id, repository_path, request))
        return result

    async def run_scan_sync(self, request: ScanRequest) -> ScanResult:
        queued = await self.create_scan(request)
        task = self._tasks[queued.scan_id]
        await task
        final = self.store.get_scan(queued.scan_id)
        if not final:
            raise RuntimeError("Scan did not persist a result")
        return final

    async def _execute_scan(self, scan_id: str, repository_path: Path, request: ScanRequest) -> None:
        result = self.store.get_scan(scan_id)
        if not result:
            return
        result.status = ScanStatus.RUNNING
        self.store.upsert_scan(result)

        try:
            if request.update_advisories and not request.offline:
                await self.advisory_manager.update_all()

            plugins = [plugin for plugin in all_plugins(self.binary_manager) if plugin.should_run(request, result.repository_signal)]
            plugins.sort(key=lambda plugin: plugin.phase)
            if not plugins:
                raise RuntimeError("No plugins matched the requested scan categories or repository contents")
            result.total_tools = len(plugins)
            result.completed_tools = 0
            result.progress_percent = 0.0
            result.active_tools = [plugin.metadata.name for plugin in plugins]
            self.store.upsert_scan(result)

            context = ScanExecutionContext(
                scan_id=scan_id,
                repository_signal=result.repository_signal,
                dependency_graph=result.dependency_graph.model_dump(),
                excluded_paths=request.exclude_paths,
            )

            plugin_results: list[PluginRunResult] = []
            errors: list[str] = []
            for phase in sorted({plugin.phase for plugin in plugins}):
                current_plugins = [plugin for plugin in plugins if plugin.phase == phase]
                phase_results = await self._run_phase(scan_id, current_plugins, repository_path, request, context)
                for outcome in phase_results:
                    if isinstance(outcome, PluginRunResult):
                        plugin_results.append(outcome)
                    else:
                        errors.append(outcome)

            findings = [finding for plugin_result in plugin_results for finding in plugin_result.findings]
            findings = filter_findings_by_excluded_paths(findings, request.exclude_paths)
            findings = correlate_findings(findings, self.store)
            findings = await self.ai_engine.enrich_findings(repository_path, findings)
            zero_day_candidates = await self.ai_engine.detect_zero_day_candidates(repository_path, findings)
            if zero_day_candidates:
                for finding in findings[: len(zero_day_candidates)]:
                    finding.ai_triage.setdefault("zero_day_candidates", zero_day_candidates)

            result.findings = findings
            result.tools = [plugin_result.execution for plugin_result in plugin_results]
            result.artifacts = [artifact for plugin_result in plugin_results for artifact in plugin_result.artifacts]
            result.summary = summarize_findings(result.findings, result.tools)
            result.errors = errors
            result.completed_at = datetime.now(timezone.utc).isoformat()
            result.status = ScanStatus.COMPLETED
            result.completed_tools = result.total_tools
            result.progress_percent = 100.0
            result.active_tools = []
            requested_reports = request.report_profiles or request.report_formats or default_report_profile_ids()
            result.artifacts.extend(
                generate_reports(result, requested_reports, include_plus_variants=request.include_plus_report_variants)
            )
            result.artifacts = self._dedupe_artifacts(result.artifacts)
            self.store.upsert_scan(result)
        except Exception as error:
            result.status = ScanStatus.FAILED
            result.completed_at = datetime.now(timezone.utc).isoformat()
            result.active_tools = []
            result.errors.append(str(error))
            self.store.upsert_scan(result)

    async def _run_phase(self, scan_id: str, plugins, repository_path: Path, request: ScanRequest, context: ScanExecutionContext) -> list[PluginRunResult | str]:
        semaphore = asyncio.Semaphore(settings.max_concurrent_processes)
        active = {plugin.metadata.name for plugin in plugins}

        async def worker(plugin):
            async with semaphore:
                try:
                    return plugin.metadata.name, await plugin.run(repository_path, request, context)
                except Exception as error:
                    return plugin.metadata.name, f"{plugin.metadata.name}: {error}"

        outcomes: list[PluginRunResult | str] = []
        tasks = [asyncio.create_task(worker(plugin)) for plugin in plugins]
        for completed in asyncio.as_completed(tasks):
            tool_name, outcome = await completed
            active.discard(tool_name)
            self._update_progress(scan_id, tool_name, active)
            outcomes.append(outcome)
        return outcomes

    def _update_progress(self, scan_id: str, completed_tool: str, active_tools: set[str]) -> None:
        result = self.store.get_scan(scan_id)
        if not result:
            return
        result.completed_tools += 1
        result.active_tools = sorted(active_tools)
        if result.total_tools:
            result.progress_percent = round((result.completed_tools / result.total_tools) * 100, 2)
        self.store.upsert_scan(result)

    async def list_plugins(self) -> list[PluginDescriptor]:
        return await plugin_descriptors(self.binary_manager)

    async def install_tool(self, tool_name: str):
        return await self.binary_manager.install(tool_name)

    async def update_advisories(self) -> dict[str, int]:
        return await self.advisory_manager.update_all()

    async def generate_reports_for_scan(
        self,
        scan_id: str,
        profile_ids: list[str] | None = None,
        include_plus_variants: bool = False,
    ) -> list:
        result = self.store.get_scan(scan_id)
        if not result:
            raise FileNotFoundError(f"Scan not found: {scan_id}")
        requested_reports = resolve_report_profile_ids(profile_ids, include_plus_variants=include_plus_variants)
        generated = generate_reports(result, requested_reports)
        result.artifacts.extend(generated)
        result.artifacts = self._dedupe_artifacts(result.artifacts)
        self.store.upsert_scan(result)
        return generated

    @staticmethod
    def _dedupe_artifacts(artifacts):
        unique = {}
        for artifact in artifacts:
            unique[(artifact.kind, artifact.path)] = artifact
        return list(unique.values())
