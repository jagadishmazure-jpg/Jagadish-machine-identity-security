"""Read-only views + SELECT-only gateway with the strict authorizer.

Three views expose posture data; every query passes a text-level check
(SEC-SELECT-01/02/03) and then runs under the SQLite authorizer backstop
(``authz.views_only``), which denies raw-table reads even when the text
check is bypassed. Row caps are enforced at fetch time via fetchmany —
no LIMIT rewriting, no fetchall.
"""

from __future__ import annotations

import re
import sqlite3

from .authz import views_only
from .inventory import TODAY, days_since

ALLOWED_VIEWS = ("v_identity_posture", "v_stale_identities",
                 "v_elevation_history")
MAX_ROWS = 100

_VIEWS_SQL_TEMPLATE = """
CREATE VIEW IF NOT EXISTS v_identity_posture AS
SELECT id, kind, display_name, owner, status, vaulted,
       length(scopes_granted) - length(replace(scopes_granted, ',', '')) + 1
         AS scopes_granted_n,
       length(scopes_used) - length(replace(scopes_used, ',', '')) + 1
         AS scopes_used_n,
       last_used, secret_rotated
FROM identities;

CREATE VIEW IF NOT EXISTS v_stale_identities AS
SELECT id, kind, owner, last_used
FROM identities
WHERE status = 'active'
  AND (last_used IS NULL OR last_used < date('{today}', '-90 days'));

CREATE VIEW IF NOT EXISTS v_elevation_history AS
SELECT id, identity_id, requested_by, requested_at, expires_at,
       duration_h, risk_score, needs_confirmation, status, confirmed_by
FROM elevations;
"""

_WRITE_WORDS = ("insert", "update", "delete", "drop", "alter", "create",
                "replace", "truncate", "attach", "detach", "pragma",
                "vacuum", "reindex")


class GatewayDenied(Exception):
    """Raised when a query fails the SELECT-only gateway."""


def install_views(conn: sqlite3.Connection) -> None:
    conn.executescript(_VIEWS_SQL_TEMPLATE.format(today=TODAY.isoformat()))
    conn.commit()


def _text_check(sql: str) -> None:
    """SEC-SELECT-01/02/03: text-level allowlist before the authorizer."""
    # Strip -- and /* */ comments so tricks can't hide behind them.
    cleaned = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    cleaned = re.sub(r"--[^\n]*", " ", cleaned)
    if ";" in cleaned.strip().rstrip(";"):
        raise GatewayDenied("SEC-SELECT-01: multiple statements not allowed")
    if not re.match(r"(?is)^\s*(select|with)\b", cleaned):
        raise GatewayDenied("SEC-SELECT-01: only SELECT/WITH allowed")
    lowered = cleaned.lower()
    for word in _WRITE_WORDS:
        if re.search(r"\b" + word + r"\b", lowered):
            raise GatewayDenied(f"SEC-SELECT-02: write keyword '{word}'")
    for match in re.finditer(r"(?i)\b(?:from|join)\s+([\"`\[]?[\w.]+[\"`\]]?)",
                             cleaned):
        name = match.group(1).strip("\"`[]").lower()
        if name in ("sqlite_master", "sqlite_schema"):
            raise GatewayDenied("SEC-SELECT-03: schema tables not allowed")
        if name not in ALLOWED_VIEWS:
            raise GatewayDenied(
                f"SEC-SELECT-03: '{match.group(1)}' is not an allowed view")


def run_query(conn: sqlite3.Connection, sql: str,
              params: tuple = ()) -> list[sqlite3.Row]:
    """Run a SELECT through text check + authorizer, capped at MAX_ROWS."""
    _text_check(sql)
    with views_only(conn, ALLOWED_VIEWS) as denied:
        try:
            cur = conn.execute(sql, params)
            rows = cur.fetchmany(MAX_ROWS + 1)
        except sqlite3.DatabaseError as exc:
            raise GatewayDenied(f"authorizer denied: {denied or exc}")
    if denied:
        raise GatewayDenied(f"authorizer denied: {denied}")
    return rows[:MAX_ROWS]


def run_query_authorizer_only(conn: sqlite3.Connection, sql: str,
                              params: tuple = ()) -> list[sqlite3.Row]:
    """Same as run_query but WITHOUT the text check.

    Used by regression tests to prove the authorizer alone denies
    raw-table reads (the bypass class found in batch 4).
    """
    with views_only(conn, ALLOWED_VIEWS) as denied:
        try:
            cur = conn.execute(sql, params)
            rows = cur.fetchmany(MAX_ROWS + 1)
        except sqlite3.DatabaseError:
            raise GatewayDenied(f"authorizer denied: {denied}")
    if denied:
        raise GatewayDenied(f"authorizer denied: {denied}")
    return rows[:MAX_ROWS]
