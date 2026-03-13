from __future__ import annotations

import json
import os
from pathlib import Path
from xml.etree import ElementTree

from security_platform.core.config import settings
from security_platform.core.models import DependencyGraph, DependencyNode, RepositorySignal


LANGUAGE_MARKERS: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".swift": "swift",
}


MANIFEST_FILES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pyproject.toml",
    "requirements.txt",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "Cargo.toml",
    "Cargo.lock",
    "pom.xml",
    "go.mod",
    "Gemfile.lock",
    "composer.lock",
}


CI_FILES = {
    ".gitlab-ci.yml",
    "azure-pipelines.yml",
    "Jenkinsfile",
}


def analyze_repository(repo_path: Path) -> tuple[RepositorySignal, DependencyGraph]:
    signal = RepositorySignal()
    graph = DependencyGraph()

    nodes: dict[str, DependencyNode] = {}
    edges: set[tuple[str, str]] = set()
    languages: set[str] = set()
    excluded = set(settings.default_excluded_paths)

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [directory for directory in dirs if directory not in excluded]
        root_path = Path(root)
        for filename in files:
            file_path = root_path / filename
            signal.total_files += 1
            try:
                signal.total_bytes += file_path.stat().st_size
            except OSError:
                pass

            if file_path.suffix.lower() in LANGUAGE_MARKERS:
                languages.add(LANGUAGE_MARKERS[file_path.suffix.lower()])

            relative = file_path.relative_to(repo_path).as_posix()
            if file_path.name in MANIFEST_FILES:
                signal.manifests.append(relative)
            if file_path.name in CI_FILES or relative.startswith(".github/workflows/"):
                signal.ci_files.append(relative)
            if file_path.name.lower().startswith("dockerfile") or file_path.name in {"docker-compose.yml", "docker-compose.yaml"}:
                signal.docker_files.append(relative)
            if "chart.yaml" in file_path.name.lower():
                signal.helm_charts.append(relative)
            if file_path.suffix in {".tf", ".tfvars"}:
                signal.terraform_files.append(relative)
            if file_path.suffix in {".yaml", ".yml"} and _looks_like_kubernetes(file_path):
                signal.kubernetes_files.append(relative)

    if "package-lock.json" in {Path(path).name for path in signal.manifests}:
        _load_package_lock(repo_path, nodes, edges)
    if "requirements.txt" in {Path(path).name for path in signal.manifests}:
        _load_requirements(repo_path, nodes)
    if "Pipfile.lock" in {Path(path).name for path in signal.manifests}:
        _load_pipfile_lock(repo_path, nodes)
    if "Cargo.lock" in {Path(path).name for path in signal.manifests}:
        _load_cargo_lock(repo_path, nodes)
    if "pom.xml" in {Path(path).name for path in signal.manifests}:
        _load_pom(repo_path, nodes)

    signal.languages = sorted(languages)
    graph.nodes = sorted(nodes.values(), key=lambda item: item.id)
    graph.edges = sorted(edges)
    return signal, graph


def _load_package_lock(repo_path: Path, nodes: dict[str, DependencyNode], edges: set[tuple[str, str]]) -> None:
    for file_path in repo_path.rglob("package-lock.json"):
        payload = json.loads(file_path.read_text(encoding="utf-8"))
        packages = payload.get("packages") or {}
        for key, data in packages.items():
            name = data.get("name")
            version = data.get("version")
            if not name:
                if key.startswith("node_modules/"):
                    name = key.removeprefix("node_modules/")
                else:
                    continue
            node_id = f"npm:{name}"
            node = nodes.setdefault(
                node_id,
                DependencyNode(id=node_id, ecosystem="npm", version=version, direct=key.count("node_modules") <= 1),
            )
            for dependency_name in (data.get("dependencies") or {}).keys():
                dependency_id = f"npm:{dependency_name}"
                if dependency_id not in node.dependencies:
                    node.dependencies.append(dependency_id)
                edges.add((node_id, dependency_id))


def _load_requirements(repo_path: Path, nodes: dict[str, DependencyNode]) -> None:
    for file_path in repo_path.rglob("requirements.txt"):
        for line in file_path.read_text(encoding="utf-8").splitlines():
            entry = line.strip()
            if not entry or entry.startswith("#") or entry.startswith("-"):
                continue
            if "==" in entry:
                name, version = entry.split("==", 1)
            else:
                name, version = entry, None
            node_id = f"pypi:{name.strip()}"
            nodes.setdefault(node_id, DependencyNode(id=node_id, ecosystem="pypi", version=version, direct=True))


def _load_pipfile_lock(repo_path: Path, nodes: dict[str, DependencyNode]) -> None:
    for file_path in repo_path.rglob("Pipfile.lock"):
        payload = json.loads(file_path.read_text(encoding="utf-8"))
        for section in ("default", "develop"):
            for name, data in (payload.get(section) or {}).items():
                version = str(data.get("version", "")).removeprefix("==") or None
                node_id = f"pypi:{name}"
                nodes.setdefault(node_id, DependencyNode(id=node_id, ecosystem="pypi", version=version, direct=True))


def _load_cargo_lock(repo_path: Path, nodes: dict[str, DependencyNode]) -> None:
    for file_path in repo_path.rglob("Cargo.lock"):
        package_name = None
        version = None
        for raw_line in file_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if line == "[[package]]":
                if package_name:
                    node_id = f"cargo:{package_name}"
                    nodes.setdefault(node_id, DependencyNode(id=node_id, ecosystem="cargo", version=version, direct=True))
                package_name = None
                version = None
                continue
            if line.startswith("name = "):
                package_name = line.split("=", 1)[1].strip().strip('"')
            if line.startswith("version = "):
                version = line.split("=", 1)[1].strip().strip('"')
        if package_name:
            node_id = f"cargo:{package_name}"
            nodes.setdefault(node_id, DependencyNode(id=node_id, ecosystem="cargo", version=version, direct=True))


def _load_pom(repo_path: Path, nodes: dict[str, DependencyNode]) -> None:
    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    for file_path in repo_path.rglob("pom.xml"):
        root = ElementTree.fromstring(file_path.read_text(encoding="utf-8"))
        dependencies = root.findall(".//m:dependency", namespace) or root.findall(".//dependency")
        for dependency in dependencies:
            group_id = dependency.findtext("m:groupId", default="", namespaces=namespace) or dependency.findtext("groupId", default="")
            artifact_id = dependency.findtext("m:artifactId", default="", namespaces=namespace) or dependency.findtext("artifactId", default="")
            version = dependency.findtext("m:version", default="", namespaces=namespace) or dependency.findtext("version", default="")
            if not group_id or not artifact_id:
                continue
            node_id = f"maven:{group_id}:{artifact_id}"
            nodes.setdefault(node_id, DependencyNode(id=node_id, ecosystem="maven", version=version or None, direct=True))


def _looks_like_kubernetes(file_path: Path) -> bool:
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return "apiVersion:" in content and "kind:" in content
