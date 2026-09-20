import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from Backend.config import settings


def get_connection(database_path: Path | str | None = None) -> sqlite3.Connection:
    path = Path(database_path) if database_path is not None else settings.database_path
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def database_connection(
    database_path: Path | str | None = None,
) -> Generator[sqlite3.Connection, None, None]:
    connection = get_connection(database_path)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database(database_path: Path | str | None = None) -> None:
    with database_connection(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                destination_ip TEXT,
                event_type TEXT NOT NULL,
                username TEXT,
                host TEXT,
                severity TEXT NOT NULL CHECK (
                    severity IN ('low', 'medium', 'high', 'critical')
                ),
                message TEXT,
                timestamp TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (
                    severity IN ('low', 'medium', 'high', 'critical')
                ),
                status TEXT NOT NULL DEFAULT 'open' CHECK (
                    status IN ('open', 'investigating', 'resolved')
                ),
                timestamp TEXT NOT NULL,
                rule_id TEXT,
                rule_name TEXT,
                category TEXT,
                confidence INTEGER,
                risk_score INTEGER,
                evidence TEXT,
                mitre_tactic TEXT,
                mitre_technique_id TEXT,
                mitre_technique_name TEXT,
                detected_at TEXT,
                detection_source TEXT,
                correlation_key TEXT,
                FOREIGN KEY(event_id) REFERENCES events(id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_status_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                previous_status TEXT NOT NULL CHECK (
                    previous_status IN ('open', 'investigating', 'resolved')
                ),
                new_status TEXT NOT NULL CHECK (
                    new_status IN ('open', 'investigating', 'resolved')
                ),
                changed_at TEXT NOT NULL,
                FOREIGN KEY(alert_id) REFERENCES alerts(id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_events (
                alert_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                relationship TEXT NOT NULL DEFAULT 'related' CHECK (
                    relationship IN ('trigger', 'related', 'grouped')
                ),
                created_at TEXT NOT NULL,
                PRIMARY KEY (alert_id, event_id),
                FOREIGN KEY(alert_id) REFERENCES alerts(id),
                FOREIGN KEY(event_id) REFERENCES events(id)
            )
            """
        )

        existing_event_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(events)").fetchall()
        }
        if "host" not in existing_event_columns:
            connection.execute("ALTER TABLE events ADD COLUMN host TEXT")

        existing_alert_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(alerts)").fetchall()
        }
        detection_columns = {
            "rule_id": "TEXT",
            "rule_name": "TEXT",
            "category": "TEXT",
            "confidence": "INTEGER",
            "risk_score": "INTEGER",
            "evidence": "TEXT",
            "mitre_tactic": "TEXT",
            "mitre_technique_id": "TEXT",
            "mitre_technique_name": "TEXT",
            "detected_at": "TEXT",
            "detection_source": "TEXT",
            "correlation_key": "TEXT",
        }
        for column_name, column_type in detection_columns.items():
            if column_name not in existing_alert_columns:
                connection.execute(
                    f"ALTER TABLE alerts ADD COLUMN {column_name} {column_type}"
                )

        connection.execute(
            """
            INSERT OR IGNORE INTO alert_events (
                alert_id, event_id, relationship, created_at
            )
            SELECT id, event_id, 'trigger', timestamp FROM alerts
            """
        )
        connection.execute(
            """
            UPDATE alerts
            SET detection_source = 'rule'
            WHERE rule_id IS NOT NULL AND detection_source IS NULL
            """
        )

        indexes = (
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)",
            "CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)",
            "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)",
            "CREATE INDEX IF NOT EXISTS idx_events_host ON events(host)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_event_id ON alerts(event_id)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_risk_score ON alerts(risk_score)",
            """
            CREATE INDEX IF NOT EXISTS idx_alerts_correlation_key
            ON alerts(correlation_key)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_alert_events_event_id
            ON alert_events(event_id)
            """,
            """
            CREATE INDEX IF NOT EXISTS idx_alert_history_alert_id
            ON alert_status_history(alert_id)
            """,
        )
        for statement in indexes:
            connection.execute(statement)

        triggers = (
            """
            CREATE TRIGGER IF NOT EXISTS validate_events_severity_insert
            BEFORE INSERT ON events
            WHEN NEW.severity NOT IN ('low', 'medium', 'high', 'critical')
            BEGIN
                SELECT RAISE(ABORT, 'invalid event severity');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS validate_events_severity_update
            BEFORE UPDATE OF severity ON events
            WHEN NEW.severity NOT IN ('low', 'medium', 'high', 'critical')
            BEGIN
                SELECT RAISE(ABORT, 'invalid event severity');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS validate_alerts_values_insert
            BEFORE INSERT ON alerts
            WHEN NEW.severity NOT IN ('low', 'medium', 'high', 'critical')
                OR NEW.status NOT IN ('open', 'investigating', 'resolved')
            BEGIN
                SELECT RAISE(ABORT, 'invalid alert severity or status');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS validate_alerts_values_update
            BEFORE UPDATE OF severity, status ON alerts
            WHEN NEW.severity NOT IN ('low', 'medium', 'high', 'critical')
                OR NEW.status NOT IN ('open', 'investigating', 'resolved')
            BEGIN
                SELECT RAISE(ABORT, 'invalid alert severity or status');
            END
            """,
        )
        for statement in triggers:
            connection.execute(statement)


def database_is_available(database_path: Path | str | None = None) -> bool:
    try:
        with database_connection(database_path) as connection:
            connection.execute("SELECT 1").fetchone()
        return True
    except sqlite3.Error:
        return False
