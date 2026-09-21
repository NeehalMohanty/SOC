# TethysGuard

TethysGuard is a cybersecurity monitoring and threat-detection platform built as a practical SOC portfolio project. The current backend receives security events, stores them in SQLite, applies explainable detection rules, creates alerts, and supports a basic analyst workflow.

## Current features

- FastAPI REST API
- SQLite event and alert storage
- Explainable detection rules for malware, port scans, unauthorized access, suspicious authentication, and brute-force activity
- Automatic alert generation
- Rule IDs, evidence, confidence, risk scores, and detection timestamps
- MITRE ATT&CK mappings for supported detections
- Threshold-based failed-login detection to reduce noisy alerts
- Multi-event correlation for brute force, repeated scans, attack sequences, and suspicious host activity
- Alert deduplication, suppression, and event grouping
- Related-event evidence for alert investigation
- Alert lookup and status updates
- Alert status audit history
- Paginated event and alert search
- Severity, status, source IP, event type, and date filters
- Dashboard statistics
- Interactive OpenAPI documentation
- Batch telemetry ingestion with per-record validation results
- SSH authentication message normalization and brute-force detection

## Project structure

```text
TethysGuard/
|-- Backend/
|   |-- routes/        # API endpoints
|   |-- config.py      # Environment-based settings
|   |-- correlation.py # Multi-event correlation rules
|   |-- database.py    # SQLite connections and schema setup
|   |-- detection.py   # Detection rules
|   |-- ingestion.py   # Telemetry adapters and batch processing
|   |-- main.py        # FastAPI application setup
|   |-- schemas.py     # Request and response models
|   `-- services.py    # Application and database operations
|-- tests/             # Automated API tests
|-- examples/          # Synthetic telemetry for local demonstrations
|-- .env.example       # Safe configuration example
|-- requirements.txt   # Runtime dependencies
`-- requirements-dev.txt
```

## Setup

Python 3.10 or newer is required.

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

### macOS or Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

## Run the backend

Run this command from the repository root:

```powershell
python -m uvicorn Backend.main:app --reload
```

Open the API documentation at <http://127.0.0.1:8000/docs>.

## Run the tests

```powershell
python -m pytest
```

The tests use temporary SQLite databases and do not modify the local development database.

## Configuration

The defaults work for local development. Optional environment variables are documented in `.env.example`:

- `TETHYSGUARD_APP_NAME`
- `TETHYSGUARD_APP_VERSION`
- `TETHYSGUARD_DATABASE_PATH`
- `TETHYSGUARD_CORS_ORIGINS`
- `TETHYSGUARD_MAX_REQUEST_BODY_BYTES`
- `TETHYSGUARD_FAILED_LOGIN_THRESHOLD`
- `TETHYSGUARD_FAILED_LOGIN_WINDOW_MINUTES`
- `TETHYSGUARD_CORRELATION_WINDOW_MINUTES`
- `TETHYSGUARD_REPEATED_SCAN_THRESHOLD`
- `TETHYSGUARD_SUSPICIOUS_HOST_THRESHOLD`
- `TETHYSGUARD_ALERT_SUPPRESSION_MINUTES`

The application reads environment variables directly. It does not automatically load `.env` files yet.

Existing installations retain access to their original database: if `Backend/tethysguard.db` does not exist, the application reuses `Backend/aegissoc.db` when present. New installations use `Backend/tethysguard.db`. Legacy `AEGISSOC_` environment variables remain supported; `TETHYSGUARD_` values take precedence. Set the database path explicitly when both files exist.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/` | API information |
| `GET` | `/health` | Health check |
| `POST` | `/api/events` | Submit a security event |
| `POST` | `/api/ingest/batch` | Import native events or SSH authentication messages |
| `GET` | `/api/events` | Retrieve events |
| `GET` | `/api/alerts` | Retrieve alerts |
| `GET` | `/api/alerts/{alert_id}` | Retrieve one alert |
| `GET` | `/api/alerts/{alert_id}/events` | Retrieve events related to an alert |
| `PATCH` | `/api/alerts/{alert_id}` | Update alert status |
| `GET` | `/api/alerts/{alert_id}/history` | Retrieve alert status history |
| `GET` | `/api/dashboard/stats` | Retrieve dashboard statistics |

## Pagination and filters

Event and alert list endpoints return at most 50 records by default and support a maximum page size of 100.

Example requests:

```text
GET /api/events?limit=25&offset=0&severity=high&sort_by=timestamp&sort_order=desc
GET /api/events?source_ip=192.0.2.10&event_type=port_scan
GET /api/alerts?status=open&severity=critical&search=malware
```

Both list responses include `count`, `total`, `limit`, and `offset` so a future frontend can build page controls correctly.

## Development status

### Phase 1 - Initial SOC backend prototype

Completed:

- FastAPI application and health endpoint
- SQLite event and alert storage
- Security event ingestion
- Rule-based detection and automatic alerts
- Alert investigation status workflow
- Dashboard statistics API

### Phase 2 - Backend foundation

Completed:

- Reproducible dependency setup
- Modular backend package structure
- Environment-based configuration
- Safer database connections and foreign-key enforcement
- Request and response schemas
- Automated API and detection tests
- Root-level run command and setup documentation

### Phase 3 - API hardening and data validation

Completed:

- Strict IP, severity, status, text-length, and payload validation
- Input normalization and unknown-field rejection
- Pagination, filtering, sorting, and search
- Additive database constraints and indexes
- Database-aware health checks
- Alert status audit history

### Phase 4 - Detection engineering

Completed:

- Explainable rule IDs and metadata
- Detection evidence and confidence
- Risk scoring
- MITRE ATT&CK mappings
- Threshold-based failed-login detection
- Multiple rule matches for one event when appropriate
- Detection tests for malware, port scans, unauthorized access, suspicious authentication, brute force, and critical events

### Phase 5 - Event correlation

Completed:

- Time-window grouping by source IP, username, and host
- Brute-force correlation across related failed-login events
- Reconnaissance followed by authentication activity detection
- Repeated network-scan correlation
- Suspicious host activity correlation
- Alert deduplication, suppression, and grouping
- Related-event storage and retrieval for investigations
- Deterministic correlation and API tests

### Phase 6 - Telemetry ingestion

Completed:

- Batch JSON ingestion through `POST /api/ingest/batch`
- Native security-event and SSH authentication adapters
- Per-record validation errors with zero-based indices
- Reuse of detection, correlation, suppression, and investigation evidence
- Synthetic SSH demo data and automated ingestion tests

The React SOC dashboard is the next planned phase. See [PROGRESS.md](PROGRESS.md) for remaining ingestion limitations.

## Import telemetry

With the backend running, submit the synthetic sample from PowerShell:

```powershell
$batch = Get-Content -Raw examples/ssh-auth-batch.json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/ingest/batch -ContentType 'application/json' -Body $batch
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/alerts
```

On a fresh database with default thresholds, five failed logins create a `TG-AUTH-001` brute-force alert. The sixth record is a successful login from a different IP and creates no alert. These are synthetic documentation IP addresses; no network traffic is generated.

Each request selects one `source` and supplies 1–100 `records`:

- `security_event`: each record uses the same fields as `POST /api/events`.
- `ssh_auth`: each record contains `host` and `message`. Supply the sshd message body, such as `Failed password for invalid user admin from 192.0.2.10 port 52101 ssh2`, without the syslog timestamp or process prefix. Supported forms are `Failed` or `Accepted`, with `password` or `publickey`; optional key details after `ssh2` are preserved. This is a deliberately limited parser, not a complete syslog collector.

Responses contain `received`, `accepted`, `rejected`, `results`, and `errors`. Each result or error identifies the original zero-based record `index`. Accepted results include event IDs, new alert IDs, and suppression/grouping details. Malformed records are rejected without storing them, while valid records continue. A valid envelope returns HTTP 200 even when every record is rejected; invalid envelopes return 422.

The existing request-size limit still applies (16 KiB by default), so split larger batches even when they contain fewer than 100 records. Events use arrival timestamps: submitting old logs together can produce correlation alerts that would not reflect their original timing. Each accepted event commits independently; a database failure returns 500 and earlier records may already be stored. Retrying records creates new events, although matching active alerts can be suppressed. Use locally until authentication and replay protection are added.
