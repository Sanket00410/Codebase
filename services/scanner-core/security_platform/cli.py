from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

import uvicorn

from security_platform.core.config import settings
from security_platform.core.models import ScanCategory, ScanRequest
from security_platform.core.orchestrator import ScanOrchestrator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="security-platform")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="Run the local API server")
    serve.add_argument("--host", default=settings.host)
    serve.add_argument("--port", default=settings.port, type=int)

    scan = subparsers.add_parser("scan", help="Run a repository scan")
    scan.add_argument("repository_path")
    scan.add_argument("--category", action="append", choices=[item.value for item in ScanCategory])
    scan.add_argument("--tool", action="append")
    scan.add_argument("--format", action="append", default=["json", "sarif", "html"])
    scan.add_argument("--offline", action="store_true")
    scan.add_argument("--update-advisories", action="store_true")
    scan.add_argument("--no-git-history", action="store_true")

    install = subparsers.add_parser("install-tool", help="Install a scanner binary")
    install.add_argument("tool_name")

    subparsers.add_parser("update-advisories", help="Refresh advisory sources and scanner DBs")
    subparsers.add_parser("plugins", help="List scanner plugins and binary status")
    return parser


async def _run_scan(args) -> int:
    orchestrator = ScanOrchestrator()
    request = ScanRequest(
        repository_path=args.repository_path,
        categories=[ScanCategory(value) for value in args.category] if args.category else None,
        tools=args.tool,
        report_formats=args.format,
        offline=args.offline,
        update_advisories=args.update_advisories,
        include_git_history=not args.no_git_history,
    )
    result = await orchestrator.run_scan_sync(request)
    _configure_stdout()
    print(result.model_dump_json(indent=2))
    return 0 if result.status.value == "completed" else 1


async def _install_tool(args) -> int:
    orchestrator = ScanOrchestrator()
    status = await orchestrator.install_tool(args.tool_name)
    _configure_stdout()
    print(status.model_dump_json(indent=2))
    return 0


async def _update_advisories() -> int:
    orchestrator = ScanOrchestrator()
    summary = await orchestrator.update_advisories()
    _configure_stdout()
    print(json.dumps(summary, indent=2))
    return 0


async def _list_plugins() -> int:
    orchestrator = ScanOrchestrator()
    plugins = await orchestrator.list_plugins()
    _configure_stdout()
    print(json.dumps([plugin.model_dump() for plugin in plugins], indent=2))
    return 0


def _configure_stdout() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def _pid_file_path() -> Path | None:
    raw = os.getenv("SCANNER_PLATFORM_PID_FILE")
    return Path(raw) if raw else None


def _write_pid_file() -> None:
    pid_file = _pid_file_path()
    if not pid_file:
        return
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(str(os.getpid()), encoding="utf-8")


def _remove_pid_file() -> None:
    pid_file = _pid_file_path()
    if not pid_file:
        return
    try:
        pid_file.unlink(missing_ok=True)
    except OSError:
        pass


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "serve":
        _write_pid_file()
        try:
            uvicorn.run("security_platform.api.main:app", host=args.host, port=args.port, reload=False)
        finally:
            _remove_pid_file()
        return
    if args.command == "scan":
        raise SystemExit(asyncio.run(_run_scan(args)))
    if args.command == "install-tool":
        raise SystemExit(asyncio.run(_install_tool(args)))
    if args.command == "update-advisories":
        raise SystemExit(asyncio.run(_update_advisories()))
    if args.command == "plugins":
        raise SystemExit(asyncio.run(_list_plugins()))


if __name__ == "__main__":
    main()
