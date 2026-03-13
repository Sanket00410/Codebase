from __future__ import annotations

import importlib.util
import inspect
import sys
from pathlib import Path

from security_platform.core.binary_manager import BinaryManager
from security_platform.core.plugin import ScannerPlugin


def load_external_plugins(binary_manager: BinaryManager, plugin_dir: Path) -> list[ScannerPlugin]:
    plugins: list[ScannerPlugin] = []
    if not plugin_dir.exists():
        return plugins

    for plugin_file in plugin_dir.glob("*.py"):
        module_name = f"security_platform_external_{plugin_file.stem}"
        spec = importlib.util.spec_from_file_location(module_name, plugin_file)
        if not spec or not spec.loader:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        for _, class_object in inspect.getmembers(module, inspect.isclass):
            if class_object is ScannerPlugin:
                continue
            if not issubclass(class_object, ScannerPlugin):
                continue
            if class_object.__module__ != module.__name__:
                continue
            plugins.append(class_object(binary_manager))
    return plugins

