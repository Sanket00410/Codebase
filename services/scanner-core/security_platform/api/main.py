from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from security_platform.core.config import settings
from security_platform.core.models import ScanRequest
from security_platform.core.orchestrator import ScanOrchestrator


app = FastAPI(title=settings.app_name, version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
orchestrator = ScanOrchestrator()


def _resolve_scan(scan_id: str | None):
    if scan_id:
        result = orchestrator.store.get_scan(scan_id)
    else:
        latest = orchestrator.store.list_scans(limit=1)
        result = latest[0] if latest else None
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/plugins")
async def list_plugins():
    return await orchestrator.list_plugins()


@app.post("/plugins/{tool_name}/install")
async def install_tool(tool_name: str):
    try:
        return await orchestrator.install_tool(tool_name)
    except Exception as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/updates/advisories")
async def update_advisories():
    try:
        return await orchestrator.update_advisories()
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error)) from error


@app.post("/scan")
async def create_scan(request: ScanRequest):
    try:
        return await orchestrator.create_scan(request)
    except Exception as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/scan/run-sync")
async def run_sync_scan(request: ScanRequest):
    try:
        return await orchestrator.run_scan_sync(request)
    except Exception as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.get("/results")
async def list_results(limit: int = 20):
    return orchestrator.store.list_scans(limit=limit)


@app.get("/results/{scan_id}")
async def get_result(scan_id: str):
    result = orchestrator.store.get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@app.get("/scan-status/{scan_id}")
async def get_status(scan_id: str):
    result = _resolve_scan(scan_id)
    return {"scan_id": result.scan_id, "status": result.status, "errors": result.errors}


@app.get("/scan-status")
async def get_latest_status(scan_id: str | None = None):
    result = _resolve_scan(scan_id)
    return {"scan_id": result.scan_id, "status": result.status, "errors": result.errors}


@app.get("/vulnerabilities/{scan_id}")
async def get_vulnerabilities(scan_id: str):
    result = _resolve_scan(scan_id)
    return result.findings


@app.get("/vulnerabilities")
async def get_latest_vulnerabilities(scan_id: str | None = None):
    result = _resolve_scan(scan_id)
    return result.findings


@app.get("/dependency-graph/{scan_id}")
async def get_dependency_graph(scan_id: str):
    result = _resolve_scan(scan_id)
    return result.dependency_graph


@app.get("/dependency-graph")
async def get_latest_dependency_graph(scan_id: str | None = None):
    result = _resolve_scan(scan_id)
    return result.dependency_graph


@app.get("/security-score/{scan_id}")
async def get_security_score(scan_id: str):
    result = _resolve_scan(scan_id)
    return {"scan_id": scan_id, "score": result.summary.score}


@app.get("/security-score")
async def get_latest_security_score(scan_id: str | None = None):
    result = _resolve_scan(scan_id)
    return {"scan_id": result.scan_id, "score": result.summary.score}


@app.get("/sbom/{scan_id}")
async def get_sbom(scan_id: str):
    result = _resolve_scan(scan_id)
    sbom_artifact = next((artifact for artifact in result.artifacts if artifact.kind == "sbom-cyclonedx"), None)
    if not sbom_artifact:
        raise HTTPException(status_code=404, detail="SBOM not available for this scan")
    return FileResponse(sbom_artifact.path, media_type=sbom_artifact.media_type, filename="sbom.cyclonedx.json")


@app.get("/sbom")
async def get_latest_sbom(scan_id: str | None = None):
    result = _resolve_scan(scan_id)
    sbom_artifact = next((artifact for artifact in result.artifacts if artifact.kind == "sbom-cyclonedx"), None)
    if not sbom_artifact:
        raise HTTPException(status_code=404, detail="SBOM not available for this scan")
    return FileResponse(sbom_artifact.path, media_type=sbom_artifact.media_type, filename="sbom.cyclonedx.json")
