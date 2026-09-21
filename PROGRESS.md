# TethysGuard progress

## Completed

Phases 1–5 established the modular API, validation, explainable detections, and event correlation. Detailed milestones are recorded in README.md.

## Phase 6 — Telemetry ingestion

- Added `/api/ingest/batch` for native event JSON and supported SSH authentication messages.
- Validated records individually and returned indexed success/error reports.
- Routed accepted logs through existing event storage and detection services.
- Preserved SSH message bodies as investigation evidence.
- Added a synthetic brute-force demonstration and ingestion regression tests.

Validation: all 56 tests passed, including 15 new ingestion tests. The only warning is an upstream Starlette/AnyIO deprecation notice.

### Current boundaries

- JSON submission only; no background host agent, file watcher, or syslog listener.
- Arrival-time correlation only; no historical timestamp reconstruction.
- Independent per-event commits; no batch rollback or ingestion idempotency.
- Existing body-size limit applies alongside the 100-record limit.
- Local development API; authentication is required before external exposure.

## Next phase

Build the React SOC dashboard: summary cards, filtered alert/event tables, and investigation details with status updates and related evidence.

Suggested Phase 6 commit: `feat: add batch telemetry ingestion and SSH log normalization`
