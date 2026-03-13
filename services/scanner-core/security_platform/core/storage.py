from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from security_platform.core.models import ScanResult, ScanStatus


class ScanStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    repository_path TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    payload TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_scans_started_at
                ON scans(started_at DESC);

                CREATE TABLE IF NOT EXISTS advisories (
                    advisory_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    package_name TEXT,
                    ecosystem TEXT,
                    severity TEXT,
                    payload TEXT NOT NULL,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_advisories_pkg
                ON advisories(package_name, ecosystem);
                """
            )

    def upsert_scan(self, result: ScanResult) -> None:
        payload = result.model_dump_json()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO scans (scan_id, status, repository_path, started_at, completed_at, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    status=excluded.status,
                    completed_at=excluded.completed_at,
                    payload=excluded.payload
                """,
                (
                    result.scan_id,
                    result.status.value,
                    result.repository_path,
                    result.started_at,
                    result.completed_at,
                    payload,
                ),
            )

    def get_scan(self, scan_id: str) -> ScanResult | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        return ScanResult.model_validate_json(row["payload"])

    def list_scans(self, limit: int = 20) -> list[ScanResult]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM scans ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [ScanResult.model_validate_json(row["payload"]) for row in rows]

    def set_status(self, scan_id: str, status: ScanStatus) -> None:
        existing = self.get_scan(scan_id)
        if not existing:
            return
        existing.status = status
        self.upsert_scan(existing)

    def upsert_advisory(self, advisory_id: str, source: str, package_name: str | None, ecosystem: str | None, severity: str | None, payload: dict) -> None:
        self.upsert_advisories_batch(
            [
                {
                    "advisory_id": advisory_id,
                    "source": source,
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "severity": severity,
                    "payload": payload,
                }
            ]
        )

    def upsert_advisories_batch(self, advisories: list[dict]) -> None:
        if not advisories:
            return
        rows = []
        for advisory in advisories:
            normalized_severity = advisory.get("severity")
            if isinstance(normalized_severity, (list, tuple)):
                normalized_severity = ",".join(str(item) for item in normalized_severity)
            elif normalized_severity is not None and not isinstance(normalized_severity, str):
                normalized_severity = str(normalized_severity)
            rows.append(
                (
                    advisory["advisory_id"],
                    advisory["source"],
                    advisory.get("package_name"),
                    advisory.get("ecosystem"),
                    normalized_severity,
                    json.dumps(advisory["payload"]),
                )
            )

        with self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO advisories (advisory_id, source, package_name, ecosystem, severity, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(advisory_id) DO UPDATE SET
                    source=excluded.source,
                    package_name=excluded.package_name,
                    ecosystem=excluded.ecosystem,
                    severity=excluded.severity,
                    payload=excluded.payload,
                    updated_at=CURRENT_TIMESTAMP
                """,
                rows,
            )

    def delete_advisories(self, advisory_ids: list[str]) -> None:
        if not advisory_ids:
            return
        with self._connect() as connection:
            connection.executemany(
                "DELETE FROM advisories WHERE advisory_id = ?",
                [(advisory_id,) for advisory_id in advisory_ids],
            )

    def count_advisories(self, source: str | None = None) -> int:
        query = "SELECT COUNT(*) FROM advisories"
        params: tuple[str, ...] = ()
        if source:
            query += " WHERE source = ?"
            params = (source,)
        with self._connect() as connection:
            row = connection.execute(query, params).fetchone()
        return int(row[0]) if row else 0

    def find_advisories(self, package_name: str, ecosystem: str | None = None) -> list[dict]:
        query = "SELECT payload FROM advisories WHERE package_name = ?"
        params: list[str] = [package_name]
        if ecosystem:
            query += " AND ecosystem = ?"
            params.append(ecosystem)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [json.loads(row["payload"]) for row in rows]
