from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, status

from Backend.schemas import (
    AlertActivity,
    AlertAssignmentUpdate,
    AlertNoteCreate,
    AlertTimelineResponse,
    Alert,
    AlertHistoryListResponse,
    AlertListResponse,
    AlertRelatedEventsResponse,
    AlertStatus,
    AlertStatusUpdate,
    AlertUpdatedResponse,
    Severity,
)
from Backend.services import (
    get_alert_by_id,
    list_alert_events,
    list_alert_history,
    list_alerts,
    update_alert_status,
)
from Backend.routes.utils import validate_date_range
from Backend.investigation import add_note, assign_alert, list_timeline


router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=AlertListResponse)
def get_alerts(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    alert_status: Annotated[AlertStatus | None, Query(alias="status")] = None,
    severity: Severity | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    search: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
    sort_by: Literal["id", "timestamp", "severity", "status", "title"] = "id",
    sort_order: Literal["asc", "desc"] = "desc",
) -> dict[str, Any]:
    validate_date_range(start_time, end_time)

    normalized_search = search.strip() if search else None
    total, alerts = list_alerts(
        request.app.state.database_path,
        limit=limit,
        offset=offset,
        alert_status=alert_status,
        severity=severity,
        start_time=start_time,
        end_time=end_time,
        search=normalized_search,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    return {
        "count": len(alerts),
        "total": total,
        "limit": limit,
        "offset": offset,
        "alerts": alerts,
    }


@router.get("/{alert_id}/history", response_model=AlertHistoryListResponse)
def get_alert_history(alert_id: int, request: Request) -> dict[str, Any]:
    history = list_alert_history(alert_id, request.app.state.database_path)
    if history is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )
    return {"count": len(history), "history": history}


@router.get("/{alert_id}/events", response_model=AlertRelatedEventsResponse)
def get_alert_events(alert_id: int, request: Request) -> dict[str, Any]:
    events = list_alert_events(alert_id, request.app.state.database_path)
    if events is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )
    return {"count": len(events), "events": events}


@router.get("/{alert_id}", response_model=Alert)
def get_alert(alert_id: int, request: Request) -> dict[str, Any]:
    alert = get_alert_by_id(alert_id, request.app.state.database_path)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )
    return alert


@router.patch("/{alert_id}", response_model=AlertUpdatedResponse)
def patch_alert_status(
    alert_id: int,
    update: AlertStatusUpdate,
    request: Request,
) -> dict[str, Any]:
    alert = update_alert_status(
        alert_id,
        update.status,
        request.app.state.database_path,
        actor=update.actor,
        resolution=update.resolution,
    )
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    return {
        "message": "Alert status updated successfully",
        "alert": alert,
    }


@router.patch("/{alert_id}/assignment", response_model=AlertUpdatedResponse)
def patch_assignment(alert_id: int, update: AlertAssignmentUpdate, request: Request):
    path = request.app.state.database_path
    if not assign_alert(alert_id, update.assigned_to, update.actor, path):
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"message": "Assignment saved", "alert": get_alert_by_id(alert_id, path)}


@router.post("/{alert_id}/notes", response_model=AlertActivity, status_code=201)
def post_note(alert_id: int, note: AlertNoteCreate, request: Request):
    activity = add_note(alert_id, note.body, note.actor, request.app.state.database_path)
    if activity is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return activity


@router.get("/{alert_id}/timeline", response_model=AlertTimelineResponse)
def get_timeline(alert_id: int, request: Request,
                 limit: Annotated[int, Query(ge=1, le=100)] = 25,
                 offset: Annotated[int, Query(ge=0)] = 0):
    timeline = list_timeline(alert_id, request.app.state.database_path, limit=limit, offset=offset)
    if timeline is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return timeline
