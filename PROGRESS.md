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

## Phase 7 — SOC dashboard

Added the React/TypeScript frontend with summary charts, filtered and paginated event/alert tables, and an alert investigation screen. The investigation screen retrieves evidence and related events and saves analyst status through the API. Requests use a central typed client; loading, empty, and failure states are visible. This phase uses manual refresh, not live push updates.

Validation commands: `cd Frontend`, then `npm ci`, `npm run build`, `npm run lint`, and `npm test`. Backend regression tests run with `python -m pytest` from the repository root.

Next: Phase 8 analyst investigation workflow (notes, assignment, timeline, and additional audit actions).

Suggested Phase 7 commit: `feat: add SOC dashboard and alert investigation frontend`
