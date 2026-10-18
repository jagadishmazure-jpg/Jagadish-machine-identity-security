"""Privileged-access controls for machine identities.

- Simulated vault: secrets are stored by reference; plaintext never appears
  in logs, sessions, or audit entries.
- Just-in-time elevation: privileged machine access is time-boxed
  (default 1 hour) and auto-expires.
- Confirmation gate: elevations whose risk score exceeds the threshold need
  a human confirmer; without one the request stays pending/denied
  (fail-closed).
"""

from __future__ import annotations

import hashlib
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from . import sprawl
from .audit import AuditLog

CONFIRM_THRESHOLD = 0.7   # risk above this needs a human confirmer
DEFAULT_DURATION_H = 1.0  # default elevation window


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Vault:
    """Reference-based secret store. Plaintext never leaves this class."""

    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}

    def store(self, identity_id: str, secret: str) -> str:
        ref = "vault://" + hashlib.sha256(
            identity_id.encode()).hexdigest()[:16]
        self._secrets[ref] = secret
        return ref

    def retrieve(self, ref: str, audit: AuditLog | None = None) -> str:
        # Retrieval is audited by reference only — never the secret.
        if audit is not None:
            audit.record("vault.retrieve", {"ref": ref})
        return self._secrets[ref]

    def has(self, ref: str) -> bool:
        return ref in self._secrets


def request_elevation(conn: sqlite3.Connection, identity_id: str,
                      requested_by: str, duration_h: float = DEFAULT_DURATION_H,
                      audit: AuditLog | None = None,
                      now: datetime | None = None) -> dict:
    """Request time-boxed privileged access for a machine identity."""
    now = now or _utcnow()
    scored = sprawl.score_identity(conn, identity_id)
    risk = scored["risk"]
    needs = 1 if risk > CONFIRM_THRESHOLD else 0
    eid = "ELV-" + uuid.uuid4().hex[:8].upper()
    expires = now + timedelta(hours=duration_h)
    status = "pending" if needs else "approved"
    conn.execute(
        "INSERT INTO elevations VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (eid, identity_id, requested_by, now.isoformat(), expires.isoformat(),
         duration_h, risk, needs, status,
         requested_by if not needs else None,
         now.isoformat() if not needs else None))
    conn.commit()
    if audit is not None:
        audit.record("elevation.requested",
                     {"id": eid, "identity": identity_id, "risk": risk,
                      "needs_confirmation": bool(needs), "status": status})
    return {"id": eid, "identity_id": identity_id, "risk": risk,
            "needs_confirmation": bool(needs), "status": status,
            "expires_at": expires.isoformat()}


def confirm_elevation(conn: sqlite3.Connection, elevation_id: str,
                      confirmer: str, audit: AuditLog | None = None,
                      now: datetime | None = None) -> dict:
    """Human confirmation for a high-risk elevation. Fail-closed."""
    now = now or _utcnow()
    row = conn.execute(
        "SELECT * FROM elevations WHERE id = ?", (elevation_id,)).fetchone()
    if row is None:
        raise KeyError(f"unknown elevation {elevation_id!r}")
    if row["status"] != "pending":
        raise ValueError(f"elevation {elevation_id} is {row['status']},"
                         " only pending elevations can be confirmed")
    if datetime.fromisoformat(row["expires_at"]) <= now:
        conn.execute("UPDATE elevations SET status='expired' WHERE id=?",
                     (elevation_id,))
        conn.commit()
        raise ValueError(f"elevation {elevation_id} already expired")
    conn.execute(
        "UPDATE elevations SET status='approved', confirmed_by=?,"
        " decided_at=? WHERE id=?",
        (confirmer, now.isoformat(), elevation_id))
    conn.commit()
    if audit is not None:
        audit.record("elevation.confirmed",
                     {"id": elevation_id, "confirmer": confirmer})
    return {"id": elevation_id, "status": "approved",
            "confirmed_by": confirmer}


def deny_elevation(conn: sqlite3.Connection, elevation_id: str,
                   decider: str, audit: AuditLog | None = None) -> dict:
    row = conn.execute(
        "SELECT status FROM elevations WHERE id = ?", (elevation_id,)).fetchone()
    if row is None:
        raise KeyError(f"unknown elevation {elevation_id!r}")
    if row["status"] != "pending":
        raise ValueError("only pending elevations can be denied")
    conn.execute("UPDATE elevations SET status='denied', confirmed_by=?,"
                 " decided_at=? WHERE id=?",
                 (decider, _utcnow().isoformat(), elevation_id))
    conn.commit()
    if audit is not None:
        audit.record("elevation.denied",
                     {"id": elevation_id, "decider": decider})
    return {"id": elevation_id, "status": "denied"}


def expire_elevations(conn: sqlite3.Connection,
                      now: datetime | None = None) -> int:
    """Mark past-expiry approved/pending elevations as expired."""
    now = now or _utcnow()
    cur = conn.execute(
        "UPDATE elevations SET status='expired'"
        " WHERE status IN ('approved','pending') AND expires_at <= ?",
        (now.isoformat(),))
    conn.commit()
    return cur.rowcount


def active_elevation(conn: sqlite3.Connection, identity_id: str,
                     now: datetime | None = None) -> dict | None:
    expire_elevations(conn, now)
    row = conn.execute(
        "SELECT * FROM elevations WHERE identity_id=? AND status='approved'"
        " ORDER BY expires_at DESC LIMIT 1", (identity_id,)).fetchone()
    return dict(row) if row else None


def session_record(conn: sqlite3.Connection, elevation_id: str) -> dict:
    """Session metadata for an elevation — never includes secrets."""
    row = conn.execute(
        "SELECT id, identity_id, requested_by, requested_at, expires_at,"
        " duration_h, risk_score, status, confirmed_by"
        " FROM elevations WHERE id = ?", (elevation_id,)).fetchone()
    if row is None:
        raise KeyError(f"unknown elevation {elevation_id!r}")
    return dict(row)
