"""Machine-identity lifecycle scoring.

Differentiator 1: every non-human identity is scored on staleness, orphaning,
over-privilege and secret age, producing a ranked remediation list. Each flag
carries a cited rule ID.
"""

from __future__ import annotations

import sqlite3

from .inventory import days_since, scopes

# Rule thresholds (documented, deterministic).
OVERPRIVILEGE_RATIO = 0.5    # SPRAWL-01: used/granted below this is over-scoped
STALE_DAYS = 90              # SPRAWL-02: unused longer than this is stale
SECRET_MAX_DAYS = 180        # SPRAWL-03: secret older than this must rotate


def least_privilege_ratio(row: sqlite3.Row) -> float:
    granted = scopes(row["scopes_granted"])
    used = set(scopes(row["scopes_used"]))
    if not granted:
        return 1.0
    return len([g for g in granted if g in used]) / len(granted)


def score_identity(conn: sqlite3.Connection, identity_id: str) -> dict:
    """Score one identity; returns components, flags and a 0..1 risk score."""
    row = conn.execute(
        "SELECT * FROM identities WHERE id = ?", (identity_id,)).fetchone()
    if row is None:
        raise KeyError(f"unknown identity {identity_id!r}")

    flags: list[str] = []
    ratio = least_privilege_ratio(row)
    if ratio < OVERPRIVILEGE_RATIO:
        flags.append("SPRAWL-01")          # over-scoped
    idle = days_since(row["last_used"])
    if idle is None or idle > STALE_DAYS:
        flags.append("SPRAWL-02")          # stale / never used
    secret_age = days_since(row["secret_rotated"])
    if secret_age is None or secret_age > SECRET_MAX_DAYS:
        flags.append("SPRAWL-03")          # stale or never-rotated secret
    orphan = conn.execute(
        "SELECT 1 FROM departed_owners WHERE owner = ?",
        (row["owner"],)).fetchone() is not None
    if orphan:
        flags.append("ORPHAN-01")
    if not row["vaulted"]:
        flags.append("VAULT-01")           # secret not in the vault

    # Composite risk: each flag adds weight, capped at 1.0.
    weights = {"SPRAWL-01": 0.25, "SPRAWL-02": 0.25, "SPRAWL-03": 0.25,
               "ORPHAN-01": 0.35, "VAULT-01": 0.20}
    risk = min(1.0, sum(weights[f] for f in flags))

    return {
        "id": row["id"],
        "kind": row["kind"],
        "owner": row["owner"],
        "status": row["status"],
        "least_privilege_ratio": round(ratio, 3),
        "days_since_use": idle,
        "days_since_rotation": secret_age,
        "orphan": orphan,
        "vaulted": bool(row["vaulted"]),
        "flags": flags,
        "risk": round(risk, 3),
    }


def remediation_list(conn: sqlite3.Connection) -> list[dict]:
    """All active identities ranked by risk, worst first."""
    ids = [r["id"] for r in conn.execute(
        "SELECT id FROM identities WHERE status = 'active'")]
    scored = [score_identity(conn, i) for i in ids]
    scored.sort(key=lambda s: (-s["risk"], s["id"]))
    return scored


def recommended_action(scored: dict) -> str:
    """Deterministic remediation suggestion for a scored identity."""
    if "ORPHAN-01" in scored["flags"] and "SPRAWL-02" in scored["flags"]:
        return "disable — orphaned and stale"
    if "SPRAWL-03" in scored["flags"]:
        return "force secret rotation"
    if "SPRAWL-01" in scored["flags"]:
        return "trim granted scopes to used scopes"
    if "VAULT-01" in scored["flags"]:
        return "move secret into the vault"
    if "SPRAWL-02" in scored["flags"]:
        return "review for decommission"
    return "no action"
