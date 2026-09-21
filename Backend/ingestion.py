"""Small, explicit adapters for telemetry submitted by collectors."""

import re
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, ValidationError

from Backend.schemas import APIModel, EventCreatedResponse, SecurityEventCreate
from Backend.services import create_security_event


class TelemetryBatch(APIModel):
    source: Literal["security_event", "ssh_auth"]
    records: list[Any] = Field(min_length=1, max_length=100)


class SSHAuthRecord(APIModel):
    host: str = Field(min_length=1, max_length=255)
    message: str = Field(min_length=1, max_length=2000)


class RecordIssue(APIModel):
    field: str
    message: str


class ImportedRecord(APIModel):
    index: int
    result: EventCreatedResponse


class RejectedRecord(APIModel):
    index: int
    errors: list[RecordIssue]


class TelemetryBatchResponse(APIModel):
    source: str
    received: int
    accepted: int
    rejected: int
    results: list[ImportedRecord]
    errors: list[RejectedRecord]


# Accept the sshd MESSAGE field, without a syslog timestamp/process prefix.
SSH_AUTH_PATTERN = re.compile(
    r"(?P<outcome>Failed|Accepted) (?P<method>password|publickey) for "
    r"(?P<invalid>invalid user )?(?P<username>\S+) from (?P<ip>\S+) "
    r"port (?P<port>[0-9]{1,5}) ssh2(?::?\s[^\r\n]*)?"
)


def normalize_record(source: str, record: Any) -> SecurityEventCreate:
    if source == "security_event":
        return SecurityEventCreate.model_validate(record)
    if source != "ssh_auth":
        raise ValueError("Unsupported telemetry source")

    log = SSHAuthRecord.model_validate(record)
    match = SSH_AUTH_PATTERN.fullmatch(log.message)
    if match is None:
        raise ValueError("Unsupported SSH authentication message; submit the sshd MESSAGE field")
    if not 1 <= int(match["port"]) <= 65535:
        raise ValueError("SSH source port must be between 1 and 65535")
    failed = match["outcome"] == "Failed"
    if match["invalid"] and not failed:
        raise ValueError("Accepted authentication cannot identify an invalid user")
    return SecurityEventCreate(
        source_ip=match["ip"],
        event_type="failed_login" if failed else "successful_login",
        username=match["username"],
        host=log.host,
        severity="low",
        message=log.message,
    )


def ingest_batch(batch: TelemetryBatch, database_path: Path | str) -> dict[str, Any]:
    results = []
    errors = []
    for index, record in enumerate(batch.records):
        try:
            event = normalize_record(batch.source, record)
        except ValidationError as error:
            errors.append({
                "index": index,
                "errors": [
                    {"field": ".".join(map(str, issue["loc"])), "message": issue["msg"]}
                    for issue in error.errors(include_input=False, include_url=False)
                ],
            })
            continue
        except ValueError as error:
            errors.append({
                "index": index,
                "errors": [{"field": "message", "message": str(error)}],
            })
            continue
        # Database failures remain server errors, never malformed-record errors.
        results.append({
            "index": index,
            "result": create_security_event(event, database_path),
        })
    return {
        "source": batch.source,
        "received": len(batch.records),
        "accepted": len(results),
        "rejected": len(errors),
        "results": results,
        "errors": errors,
    }
