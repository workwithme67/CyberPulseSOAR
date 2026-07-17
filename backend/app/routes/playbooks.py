"""
Playbook router – automated response action endpoints.

Endpoints
---------
GET    /playbooks/               List all available playbooks.
POST   /playbooks/execute        Execute a named playbook against an alert.
GET    /playbooks/executions     List all playbook execution records.
GET    /playbooks/blocked-ips    List all blocked IPs.
"""

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.models.user import User
from app.models.schemas import (
    BlockedIPResponse,
    PlaybookExecuteRequest,
    PlaybookExecutionResponse,
    PlaybookListResponse,
)
from app.routes.deps import get_current_user, require_analyst, require_any_role
from app.services import playbook_service
from app.utils.helpers import get_logger

router = APIRouter()
logger = get_logger(__name__)


# ── GET /playbooks/ ───────────────────────────────────────────────────────────
@router.get(
    "/",
    response_model=PlaybookListResponse,
    summary="List available playbooks",
    description="Returns all registered automated response playbooks.",
)
def list_playbooks(
    current_user: User = Depends(require_any_role),
) -> PlaybookListResponse:
    """Return all available playbook definitions."""
    logger.info("Playbooks list requested by user: %s", current_user.username)
    try:
        import sys, os
        _root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        if _root not in sys.path:
            sys.path.insert(0, _root)
        from playbooks import AVAILABLE_PLAYBOOKS
    except ImportError:
        AVAILABLE_PLAYBOOKS = []
    return PlaybookListResponse(playbooks=AVAILABLE_PLAYBOOKS)


# ── POST /playbooks/execute ───────────────────────────────────────────────────
@router.post(
    "/execute",
    response_model=PlaybookExecutionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Execute a playbook",
    description=(
        "Run a named automated response playbook against a security alert.\n\n"
        "**Available playbooks:** `block_ip` | `isolate_host` | `notify_soc` | `escalate`\n\n"
        "**Required role:** Admin or SOCAnalyst"
    ),
)
def execute_playbook(
    payload: PlaybookExecuteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> PlaybookExecutionResponse:
    """Execute a named playbook against an alert."""
    execution = playbook_service.execute_playbook(
        db=db,
        alert_id=payload.alert_id,
        playbook_name=payload.playbook_name,
        target=payload.target,
        executed_by=current_user.username,
        notes=payload.notes,
    )
    return execution


# ── GET /playbooks/executions ─────────────────────────────────────────────────
@router.get(
    "/executions",
    response_model=List[PlaybookExecutionResponse],
    summary="List playbook executions",
    description="Returns a history of all playbook executions, optionally filtered by alert.",
)
def list_executions(
    alert_id: Optional[str] = Query(
        default=None,
        description="Filter by alert ID (e.g. ALERT-A3F80001)",
    ),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: User = Depends(require_any_role),
) -> List[PlaybookExecutionResponse]:
    """List playbook execution history."""
    return playbook_service.get_executions(db=db, alert_id=alert_id, limit=limit)


# ── GET /playbooks/blocked-ips ────────────────────────────────────────────────
@router.get(
    "/blocked-ips",
    response_model=List[BlockedIPResponse],
    summary="List blocked IPs",
    description="Returns all IP addresses that have been blocked via the block_ip playbook.",
)
def list_blocked_ips(
    db: Session = Depends(get_db),
    _: User = Depends(require_any_role),
) -> List[BlockedIPResponse]:
    """Return all blocked IP records."""
    return playbook_service.get_blocked_ips(db=db)
