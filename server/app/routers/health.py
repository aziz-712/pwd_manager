from __future__ import annotations

from fastapi import APIRouter

from ..config import get_settings
from ..schemas import HealthOut

router = APIRouter(tags=["health"])


@router.get(
    "/healthz",
    response_model=HealthOut,
    summary="Liveness probe",
    description="Unauthenticated and unrate-limited, so an orchestrator can poll it freely.",
)
def healthz() -> dict[str, str]:
    return {"status": "ok", "environment": get_settings().environment}
