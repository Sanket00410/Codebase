from __future__ import annotations

import json
from pathlib import Path

from security_platform.core.models import ReportArtifact, ScanCategory, ToolMetadata
from security_platform.core.plugin import JsonFilePlugin, ScanExecutionContext
from security_platform.core.utils import path_matches_excluded


class SyftPlugin(JsonFilePlugin):
    metadata = ToolMetadata(
        name="syft",
        display_name="Syft",
        category=ScanCategory.SBOM,
        install_strategy="github-release",
        description="SBOM generation with CycloneDX output",
    )
    phase = 0

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        command = [
            str(binary_path),
            f"dir:{repository_path}",
            "-o",
            f"cyclonedx-json={output_path}",
        ]
        for excluded in request.exclude_paths:
            normalized = excluded.replace("\\", "/").lstrip("./")
            command.extend(["--exclude", f"./{normalized}"])
            command.extend(["--exclude", f"./{normalized}/**"])
        return command

    def parse_payload(self, repository_path: Path, payload: dict, output_path: Path, context: ScanExecutionContext) -> tuple[list, list[ReportArtifact]]:
        sanitized_payload = _sanitize_sbom(payload, context.excluded_paths)
        sanitized_path = output_path.with_name("sbom-cyclonedx.json")
        sanitized_path.write_text(json.dumps(sanitized_payload, indent=2), encoding="utf-8")
        artifact = ReportArtifact(
            kind="sbom-cyclonedx",
            path=str(sanitized_path),
            media_type="application/vnd.cyclonedx+json",
        )
        context.shared_artifacts["sbom-cyclonedx"] = artifact
        return [], [artifact]


def _sanitize_sbom(payload: dict, excluded_paths: list[str]) -> dict:
    components = payload.get("components") or []
    kept_components = []
    removed_refs: set[str] = set()

    for component in components:
        if _component_matches_excluded(component, excluded_paths):
            bom_ref = component.get("bom-ref")
            if bom_ref:
                removed_refs.add(bom_ref)
            continue
        kept_components.append(component)

    sanitized = dict(payload)
    sanitized["components"] = kept_components

    if "dependencies" in sanitized:
        sanitized["dependencies"] = [
            {
                **dependency,
                "dependsOn": [ref for ref in dependency.get("dependsOn", []) if ref not in removed_refs],
            }
            for dependency in sanitized.get("dependencies", [])
            if dependency.get("ref") not in removed_refs
        ]
    return sanitized


def _component_matches_excluded(component: dict, excluded_paths: list[str]) -> bool:
    for property_entry in component.get("properties", []):
        name = property_entry.get("name") or ""
        if name.startswith("syft:location:") and name.endswith(":path"):
            if path_matches_excluded(property_entry.get("value"), excluded_paths):
                return True
    return False
