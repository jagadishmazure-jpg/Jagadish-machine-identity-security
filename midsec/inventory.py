"""Synthetic machine-identity inventory on SQLite.

Fictional company: Thrennow Systems (invented). All people, teams, keys,
and activity are synthetic. Fixed reference date TODAY keeps every run
deterministic.
"""

from __future__ import annotations

import sqlite3
from datetime import date, datetime, timedelta

TODAY: date = date(2026, 10, 18)

SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  display_name TEXT NOT NULL,
  owner TEXT NOT NULL,
  scopes_granted TEXT NOT NULL,
  scopes_used TEXT NOT NULL,
  created TEXT NOT NULL,
  last_used TEXT,
  secret_rotated TEXT,
  vaulted INTEGER NOT NULL,
  status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS usage_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  identity_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  city TEXT,
  country TEXT,
  ip TEXT,
  action TEXT,
  success INTEGER,
  token_fp TEXT
);
CREATE TABLE IF NOT EXISTS elevations (
  id TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  duration_h REAL NOT NULL,
  risk_score REAL NOT NULL,
  needs_confirmation INTEGER NOT NULL,
  status TEXT NOT NULL,
  confirmed_by TEXT,
  decided_at TEXT
);
CREATE TABLE IF NOT EXISTS departed_owners (
  owner TEXT PRIMARY KEY,
  departed_on TEXT NOT NULL
);
"""

# id, kind, display, owner, granted, used, created, last_used, rotated, vaulted, status
_IDENTITIES = [
    ("svc-billing-01", "service_account", "Billing reconciler", "team-billing",
     "read:billing,write:billing,read:ledger,admin:billing,read:users,write:users,deploy:prod,read:secrets",
     "read:billing,write:billing",
     "2025-06-01", "2026-10-17", "2026-09-15", 1, "active"),
    ("svc-etl-legacy", "service_account", "Legacy ETL runner", "ex-chen",
     "read:warehouse,write:warehouse,read:raw",
     "read:warehouse",
     "2024-03-15", "2026-06-19", None, 0, "active"),
    ("key-mobile-app", "api_key", "Mobile app backend key", "team-mobile",
     "read:catalog,read:pricing,write:cart",
     "read:catalog,read:pricing,write:cart",
     "2026-01-10", "2026-10-18", "2026-08-01", 1, "active"),
    ("key-partner-feed", "api_key", "Partner inventory feed", "team-integrations",
     "read:inventory,write:inventory",
     "read:inventory",
     "2026-02-20", "2026-10-17", "2026-07-01", 1, "active"),
    ("oauth-crm-sync", "oauth_app", "CRM contact sync", "team-sales-ops",
     "read:contacts,write:contacts,read:deals,write:deals,admin:crm,read:reports",
     "read:contacts,write:contacts",
     "2025-11-01", "2026-10-16", "2026-09-01", 1, "active"),
    ("agent-support-copilot", "ai_agent", "Support copilot agent", "team-ai-platform",
     "read:kb,read:tickets,write:tickets,read:customers",
     "read:kb,read:tickets,write:tickets,read:customers",
     "2026-05-01", "2026-10-18", "2026-10-01", 1, "active"),
    ("agent-code-reviewer", "ai_agent", "Code review agent", "team-ai-platform",
     "read:repos,write:pr-comments",
     "read:repos",
     "2026-03-01", "2026-10-10", "2026-04-01", 1, "active"),
    ("svc-backup-01", "service_account", "Nightly backup", "team-infra",
     "read:db,write:backups",
     "read:db,write:backups",
     "2025-01-15", "2026-10-18", "2026-09-20", 1, "active"),
    ("key-iot-ingest", "api_key", "IoT telemetry ingest", "team-iot",
     "write:telemetry",
     "write:telemetry",
     "2026-04-15", "2026-10-18", "2026-09-10", 1, "active"),
    ("oauth-analytics", "oauth_app", "Analytics export", "team-data",
     "read:events,read:users",
     "read:events",
     "2025-08-01", "2026-07-10", "2026-06-01", 1, "active"),
    ("svc-deploy-01", "service_account", "Deploy runner", "team-platform",
     "deploy:prod,read:artifacts",
     "deploy:prod,read:artifacts",
     "2026-02-01", "2026-10-17", "2026-09-25", 0, "active"),
    ("agent-data-labeler", "ai_agent", "Data labeling agent", "team-ai-platform",
     "read:datasets,write:labels",
     "read:datasets,write:labels",
     "2026-06-01", "2026-10-18", "2026-09-05", 1, "active"),
    ("svc-monitoring", "service_account", "Monitoring prober", "team-infra",
     "read:metrics,read:health",
     "read:metrics,read:health",
     "2025-05-01", "2026-10-18", "2026-10-05", 1, "active"),
    ("key-webhook", "api_key", "CI webhook receiver", "team-platform",
     "write:builds",
     "write:builds",
     "2026-09-01", "2026-10-18", "2026-09-01", 1, "active"),
]

_DEPARTED = [("ex-chen", "2026-08-15")]


def _dt(day: date, hour: int = 12, minute: int = 0) -> str:
    base = datetime(day.year, day.month, day.day, hour, 0)
    return (base + timedelta(minutes=minute)).isoformat()


def _seed_events(conn: sqlite3.Connection) -> None:
    ev: list[tuple] = []

    def add(ident, day, hour, city, country, action, n=1, token_fp=None,
            minute=0, success=1):
        for i in range(n):
            ev.append((ident, _dt(day, hour, minute + i), city, country,
                       "10.0.0.%d" % (i % 250 + 1), action, success, token_fp))

    # Baselines: quiet daily heartbeat for most identities.
    for d in [date(2026, 10, d) for d in (12, 13, 14, 15, 16, 17)]:
        add("svc-billing-01", d, 9, "Chicago", "US", "reconcile", 4, "tf-bill")
        add("svc-backup-01", d, 2, "Chicago", "US", "backup", 2, "tf-backup")
        add("svc-monitoring", d, 0, "Chicago", "US", "probe", 6, "tf-mon")
        add("agent-support-copilot", d, 10, "Chicago", "US", "answer", 8, "tf-sup")
        add("key-partner-feed", d, 8, "Frankfurt", "DE", "pull", 3, "tf-partner")

    # SIG-GEO-01: key-partner-feed seen from a brand-new country.
    add("key-partner-feed", date(2026, 10, 17), 22, "Lagos", "NG",
        "pull", 5, "tf-partner")

    # SIG-SPIKE-01: key-mobile-app 15x its normal volume on 2026-10-18.
    for d in [date(2026, 10, d) for d in (14, 15, 16, 17)]:
        add("key-mobile-app", d, 11, "Chicago", "US", "catalog.read", 20,
            "tf-mobile")
    add("key-mobile-app", date(2026, 10, 18), 11, "Chicago", "US",
        "catalog.read", 300, "tf-mobile")

    # SIG-TRAVEL-01: key-iot-ingest in two far-apart cities 30 min apart.
    add("key-iot-ingest", date(2026, 10, 18), 10, "Chicago", "US",
        "telemetry.write", 2, "tf-iot", minute=0)
    add("key-iot-ingest", date(2026, 10, 18), 10, "Singapore", "SG",
        "telemetry.write", 2, "tf-iot", minute=30)

    # SIG-REUSE-01: same token fingerprint on two identities.
    add("agent-data-labeler", date(2026, 10, 18), 9, "Chicago", "US",
        "label", 4, "tf-9f2a")
    add("key-webhook", date(2026, 10, 18), 9, "Chicago", "US",
        "build.trigger", 4, "tf-9f2a")

    conn.executemany(
        "INSERT INTO usage_events (identity_id, ts, city, country, ip,"
        " action, success, token_fp) VALUES (?,?,?,?,?,?,?,?)", ev)


def seed(conn: sqlite3.Connection) -> None:
    """Create schema and load the deterministic synthetic dataset."""
    conn.executescript(SCHEMA)
    conn.executemany(
        "INSERT OR REPLACE INTO identities VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        _IDENTITIES)
    conn.executemany(
        "INSERT OR REPLACE INTO departed_owners VALUES (?,?)", _DEPARTED)
    conn.execute("DELETE FROM usage_events")
    _seed_events(conn)
    conn.execute("DELETE FROM elevations")
    conn.commit()


def connect(path: str = ":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    seed(conn)
    return conn


def days_since(iso_date: str | None, today: date = TODAY) -> int | None:
    if not iso_date:
        return None
    return (today - date.fromisoformat(iso_date)).days


def scopes(text: str) -> list[str]:
    return [s for s in (text or "").split(",") if s]
