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

Suggested Phase 7 commit: `feat: add SOC dashboard and alert investigation frontend`

## Phase 8 — Analyst investigation workflow

- Added analyst assignment and unassignment, displayed on the alert detail and queue screens.
- Added append-only notes, rendered as plain text.
- Added a paginated investigation timeline containing creation, notes, ownership changes, and status changes.
- Added false-positive resolution and reopening, while retaining existing database status values.
- Preserved historical status entries with an idempotent backfill labeled `Unknown (legacy)`.
- Kept workflow changes and audit entries atomic; failures roll back both.
- Added input validation, missing-alert, pagination, legacy preservation, rollback, and frontend interaction tests.

False positives are stored as resolved alerts with a separate resolution field. They remain part
of the dashboard's resolved count. Reopening clears the resolution but retains investigation history.
The schema upgrade is additive; no existing tables are replaced or data deleted.

Validation: 73 backend tests and 13 frontend tests; production build and lint pass.
A headless Edge browser check covered assignment, notes, resolution, persistence after reload,
reopening, and desktop/mobile layout using an isolated temporary database.

### Current boundaries

- Analyst and assignee names are unverified labels, not authenticated users.
- This is not a tamper-proof audit system; use locally until authentication and permissions exist.
- Notes cannot be edited or deleted through the app; corrections are follow-up notes.
- Concurrent edits use last-write-wins behavior; no optimistic conflict detection yet.
- A timed-out note submission may have been stored; refresh before retrying.
- The timeline refreshes after local changes or manually, not via live updates.

Next: Phase 9 authentication and role-based permissions.

Suggested Phase 8 commit: `feat: add analyst investigation workflow`
