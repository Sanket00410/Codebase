from __future__ import annotations

import asyncio

from security_platform.core.binary_manager import BinaryManager
from security_platform.core.config import settings
from security_platform.core.models import PluginDescriptor
from security_platform.plugins.loader import load_external_plugins
from security_platform.plugins.bandit import BanditPlugin
from security_platform.plugins.checkov import CheckovPlugin
from security_platform.plugins.detect_secrets import DetectSecretsPlugin
from security_platform.plugins.gitleaks import GitleaksPlugin
from security_platform.plugins.grype import GrypePlugin
from security_platform.plugins.npm_audit import NpmAuditPlugin
from security_platform.plugins.osv_scanner import OsvScannerPlugin
from security_platform.plugins.semgrep import SemgrepPlugin
from security_platform.plugins.syft import SyftPlugin
from security_platform.plugins.trufflehog import TruffleHogPlugin
from security_platform.plugins.trivy import TrivyPlugin


def built_in_plugins(binary_manager: BinaryManager):
    return [
        SyftPlugin(binary_manager),
        SemgrepPlugin(binary_manager),
        BanditPlugin(binary_manager),
        GitleaksPlugin(binary_manager),
        DetectSecretsPlugin(binary_manager),
        CheckovPlugin(binary_manager),
        NpmAuditPlugin(binary_manager),
        TrivyPlugin(binary_manager),
        OsvScannerPlugin(binary_manager),
        GrypePlugin(binary_manager),
        TruffleHogPlugin(binary_manager),
    ]


def all_plugins(binary_manager: BinaryManager):
    return built_in_plugins(binary_manager) + load_external_plugins(binary_manager, settings.plugin_dir)


async def plugin_descriptors(binary_manager: BinaryManager) -> list[PluginDescriptor]:
    plugins = all_plugins(binary_manager)
    statuses = await asyncio.gather(*(plugin.binary_status() for plugin in plugins))
    descriptors: list[PluginDescriptor] = []
    for plugin, status in zip(plugins, statuses, strict=True):
        descriptors.append(
            PluginDescriptor(
                metadata=plugin.metadata,
                available=status.available,
                binary_status=status,
            )
        )
    return descriptors
