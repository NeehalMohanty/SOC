from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator, model_validator


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SecurityEventCreate(APIModel):
    source_ip: IPvAnyAddress
    destination_ip: Optional[IPvAnyAddress] = None
    event_type: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9_.:-]+$")
    username: Optional[str] = Field(default=None, max_length=255)
    host: Optional[str] = Field(
        default=None,
        max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )
    severity: Severity = Severity.LOW
    message: Optional[str] = Field(default=None, max_length=2000)

    @field_validator("event_type", mode="before")
    @classmethod
    def normalize_event_type(cls, value: Any) -> Any:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, value: Any) -> Any:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("username", "host", "message", mode="before")
    @classmethod
    def normalize_optional_text(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        normalized = value.strip()
        if not normalized:
            return None
        return normalized

    @field_validator("host", mode="after")
    @classmethod
    def normalize_host(cls, value: Optional[str]) -> Optional[str]:
        return value.lower() if value else None


class SecurityEvent(SecurityEventCreate):
    id: int
    timestamp: str


class AlertRelatedEvent(SecurityEvent):
    relationship: Literal["trigger", "related", "grouped"]


class Alert(APIModel):
    assigned_to: str | None = None
    resolution: Literal["false_positive"] | None = None
    id: int
    event_id: int
    title: str
    description: str
    severity: Severity
    status: AlertStatus
    timestamp: str
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    category: Optional[str] = None
    confidence: Optional[int] = Field(default=None, ge=0, le=100)
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    evidence: Optional[dict[str, Any]] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    detected_at: Optional[str] = None
    detection_source: Optional[str] = None
    related_event_ids: list[int] = Field(default_factory=list)


class AlertStatusUpdate(APIModel):
    status: AlertStatus
    actor: str = Field(default="Local analyst", min_length=1, max_length=100)
    resolution: Literal["false_positive"] | None = None

    @model_validator(mode="after")
    def validate_resolution(self):
        if self.resolution is not None and self.status != AlertStatus.RESOLVED:
            raise ValueError("A false-positive resolution requires resolved status")
        return self

    @field_validator("status", mode="before")
    @classmethod
    def normalize_status(cls, value: Any) -> Any:
        return value.strip().lower() if isinstance(value, str) else value


class AlertStatusHistory(APIModel):
    id: int
    alert_id: int
    previous_status: AlertStatus
    new_status: AlertStatus
    changed_at: str


class AnalystAction(APIModel):
    actor: str = Field(min_length=1, max_length=100)


class AlertAssignmentUpdate(AnalystAction):
    assigned_to: str | None = Field(max_length=100)

    @field_validator("assigned_to", mode="before")
    @classmethod
    def normalize_assignee(cls, value: Any) -> Any:
        return (value.strip() or None) if isinstance(value, str) else value


class AlertNoteCreate(AnalystAction):
    body: str = Field(min_length=1, max_length=4000)


class AlertActivity(APIModel):
    id: int
    alert_id: int
    action: Literal["created", "status_changed", "assigned", "note_added"]
    actor: str
    details: dict[str, Any]
    created_at: str


class AlertTimelineResponse(APIModel):
    count: int
    total: int
    limit: int
    offset: int
    activities: list[AlertActivity]


class RootResponse(APIModel):
    name: str
    message: str
    version: str


class HealthResponse(APIModel):
    status: str
    database: str


class EventCreatedResponse(APIModel):
    message: str
    event_id: int
    alert_created: bool
    alert_id: Optional[int] = None
    alerts_created: int = 0
    alert_ids: list[int] = Field(default_factory=list)
    alerts_suppressed: int = 0
    grouped_alert_ids: list[int] = Field(default_factory=list)


class EventListResponse(APIModel):
    count: int
    total: int
    limit: int
    offset: int
    events: list[SecurityEvent]


class AlertListResponse(APIModel):
    count: int
    total: int
    limit: int
    offset: int
    alerts: list[Alert]


class AlertHistoryListResponse(APIModel):
    count: int
    history: list[AlertStatusHistory]


class AlertRelatedEventsResponse(APIModel):
    count: int
    events: list[AlertRelatedEvent]


class AlertUpdatedResponse(APIModel):
    message: str
    alert: Alert


class AlertStatusCounts(APIModel):
    open: int
    investigating: int
    resolved: int


class SeverityCounts(APIModel):
    critical: int
    high: int
    medium: int
    low: int


class DashboardStatsResponse(APIModel):
    total_events: int
    total_alerts: int
    alert_status: AlertStatusCounts
    severity: SeverityCounts
