from __future__ import annotations

from pathlib import Path

from security_platform.core.models import FindingLocation, NormalizedFinding, ScanCategory, Severity, ToolMetadata
from security_platform.core.plugin import JsonFilePlugin, ScanExecutionContext
from security_platform.core.utils import normalize_path, stable_fingerprint


class EslintPlugin(JsonFilePlugin):
    metadata = ToolMetadata(
        name="eslint",
        display_name="ESLint Security",
        category=ScanCategory.SAST,
        supported_languages=["javascript", "typescript"],
        install_strategy="npm",
        description="JavaScript and TypeScript security linting with eslint-plugin-security",
    )
    accepted_exit_codes = {0, 1}

    def should_run(self, request, signal) -> bool:
        return super().should_run(request, signal) and any(language in {"javascript", "typescript"} for language in signal.languages)

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        config_path = output_path.parent / "eslint-security.config.mjs"
        config_path.write_text(self._config_contents(binary_path, request.exclude_paths), encoding="utf-8")
        return [
            str(binary_path),
            str(repository_path),
            "--format",
            "json",
            "--output-file",
            str(output_path),
            "--config",
            str(config_path),
            "--no-config-lookup",
            "--no-error-on-unmatched-pattern",
        ]

    def environment(self, repository_path: Path, request, context: ScanExecutionContext) -> dict[str, str]:
        env_root = self.binary_manager.settings.tool_envs_dir / self.metadata.name
        return {"NODE_PATH": str(env_root / "node_modules")}

    def parse_payload(self, repository_path: Path, payload: list, output_path: Path, context: ScanExecutionContext) -> tuple[list, list]:
        findings: list[NormalizedFinding] = []
        for file_result in payload or []:
            file_path = normalize_path(repository_path, file_result.get("filePath"))
            for message in file_result.get("messages") or []:
                rule_id = message.get("ruleId")
                if not rule_id or not str(rule_id).startswith("security/"):
                    continue
                message_text = str(message.get("message") or rule_id)
                severity = Severity.HIGH if int(message.get("severity") or 1) >= 2 else Severity.MEDIUM
                findings.append(
                    NormalizedFinding(
                        fingerprint=stable_fingerprint("eslint", rule_id, file_path, str(message.get("line")), str(message.get("column")), message_text),
                        source_tool="eslint",
                        category=ScanCategory.SAST,
                        severity=severity,
                        title=message_text,
                        description=f"ESLint security analysis reported {rule_id}: {message_text}",
                        rule_id=rule_id,
                        confidence=0.86 if severity == Severity.HIGH else 0.74,
                        location=FindingLocation(
                            path=file_path,
                            line=message.get("line"),
                            column=message.get("column"),
                        ),
                        tags=[tag for tag in [message.get("nodeType"), message.get("messageId")] if tag],
                        remediation="Replace dynamic or unsafe inputs with validated literal values, and avoid security-sensitive constructs reported by eslint-plugin-security.",
                        raw=message,
                    )
                )
        return findings, []

    def _config_contents(self, binary_path: Path, excluded_paths: list[str]) -> str:
        env_root = self._env_root_from_binary(binary_path)
        security_plugin = (env_root / "node_modules" / "eslint-plugin-security").resolve().as_posix()
        ts_parser = (env_root / "node_modules" / "@typescript-eslint" / "parser" / "dist" / "index.js").resolve().as_posix()
        ignore_patterns = [f"**/{item.replace('\\', '/').strip('/')}/**" for item in excluded_paths if item]
        ignores = ",\n      ".join(f'"{pattern}"' for pattern in ignore_patterns) or '"**/.git/**"'
        security_rules = """
      "security/detect-eval-with-expression": "error",
      "security/detect-new-buffer": "error",
      "security/detect-non-literal-fs-filename": "error",
      "security/detect-non-literal-regexp": "error",
      "security/detect-non-literal-require": "error",
      "security/detect-object-injection": "warn",
      "security/detect-child-process": "warn",
      "security/detect-unsafe-regex": "warn"
        """.strip()
        return f"""import {{ createRequire }} from "node:module";
const require = createRequire(import.meta.url);
const security = require("{security_plugin}");
const tsParser = require("{ts_parser}");

export default [
  {{
    files: ["**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs"],
    ignores: [
      {ignores}
    ],
    plugins: {{ security }},
    languageOptions: {{
      ecmaVersion: "latest",
      sourceType: "module",
      parserOptions: {{ ecmaFeatures: {{ jsx: true }} }},
    }},
    rules: {{
      {security_rules}
    }},
  }},
  {{
    files: ["**/*.ts", "**/*.tsx"],
    ignores: [
      {ignores}
    ],
    plugins: {{ security }},
    languageOptions: {{
      parser: tsParser,
      parserOptions: {{
        ecmaVersion: "latest",
        sourceType: "module",
        ecmaFeatures: {{ jsx: true }},
      }},
    }},
    rules: {{
      {security_rules}
    }},
  }},
];
"""

    def _env_root_from_binary(self, binary_path: Path) -> Path:
        if binary_path.parent.name == ".bin" and binary_path.parent.parent.name == "node_modules":
            return binary_path.parent.parent.parent
        return binary_path.parent
