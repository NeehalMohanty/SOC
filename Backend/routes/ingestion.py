from typing import Any

from fastapi import APIRouter, Request

from Backend.ingestion import TelemetryBatch, TelemetryBatchResponse, ingest_batch


router = APIRouter(prefix="/api/ingest", tags=["ingestion"])


@router.post("/batch", response_model=TelemetryBatchResponse)
def ingest_telemetry(batch: TelemetryBatch, request: Request) -> dict[str, Any]:
    """Import up to 100 records; report validation failures by zero-based index."""
    return ingest_batch(batch, request.app.state.database_path)
