from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from security_platform.core.config import Settings, settings
from security_platform.core.models import NormalizedFinding


class AITriageEngine:
    def __init__(self, runtime_settings: Settings = settings) -> None:
        self.settings = runtime_settings

    @property
    def enabled(self) -> bool:
        return bool(self.settings.openai_api_key or self.settings.ollama_model)

    async def enrich_findings(self, repository_path: Path, findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
        if not self.enabled:
            return findings

        enriched: list[NormalizedFinding] = []
        for finding in findings[:25]:
            response = await self._triage_finding(repository_path, finding)
            if response:
                finding.ai_triage = response
                if not finding.remediation and response.get("remediation"):
                    finding.remediation = response["remediation"]
            enriched.append(finding)
        enriched.extend(findings[25:])
        return enriched

    async def detect_zero_day_candidates(self, repository_path: Path, findings: list[NormalizedFinding]) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        suspicious = [item for item in findings if item.category.value == "sast" and not item.cve_ids][:10]
        if not suspicious:
            return []
        prompt = {
            "task": "cluster_zero_day_candidates",
            "repository_path": str(repository_path),
            "findings": [item.model_dump() for item in suspicious],
        }
        response = await self._chat_json(prompt)
        candidates = response.get("candidates", [])
        return candidates if isinstance(candidates, list) else []

    async def _triage_finding(self, repository_path: Path, finding: NormalizedFinding) -> dict[str, Any]:
        snippet = ""
        if finding.location and finding.location.path:
            file_path = repository_path / finding.location.path
            if file_path.exists():
                try:
                    snippet = file_path.read_text(encoding="utf-8", errors="ignore")[:4000]
                except OSError:
                    snippet = ""
        prompt = {
            "task": "triage_finding",
            "finding": finding.model_dump(),
            "source_snippet": snippet,
            "instructions": "Return JSON with keys priority, reasoning, remediation, exploitability, zero_day_candidate.",
        }
        return await self._chat_json(prompt)

    async def _chat_json(self, prompt: dict[str, Any]) -> dict[str, Any]:
        if self.settings.ollama_model:
            return await self._chat_ollama(prompt)
        if self.settings.openai_api_key:
            return await self._chat_openai(prompt)
        return {}

    async def _chat_ollama(self, prompt: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "model": self.settings.ollama_model,
            "format": "json",
            "stream": False,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a security triage model. Respond only with valid JSON.",
                },
                {
                    "role": "user",
                    "content": json.dumps(prompt),
                },
            ],
        }
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(f"{self.settings.ollama_base_url}/api/chat", json=payload)
            response.raise_for_status()
            content = response.json().get("message", {}).get("content", "{}")
            return json.loads(content)

    async def _chat_openai(self, prompt: dict[str, Any]) -> dict[str, Any]:
        base_url = self.settings.openai_base_url or "https://api.openai.com/v1"
        headers = {"Authorization": f"Bearer {self.settings.openai_api_key}"}
        payload = {
            "model": "gpt-4.1-mini",
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": "You are a security triage model. Respond only with valid JSON.",
                },
                {
                    "role": "user",
                    "content": json.dumps(prompt),
                },
            ],
        }
        async with httpx.AsyncClient(timeout=120.0, headers=headers) as client:
            response = await client.post(f"{base_url}/chat/completions", json=payload)
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            return json.loads(content)
