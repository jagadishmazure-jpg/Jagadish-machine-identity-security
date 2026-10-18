"""Automated response for identity threats.

Destructive actions (revoke, disable) require explicit confirmation
(RESP-CONF-01); without it they raise instead of acting. All response
actions run in dry-run mode by default so demos never mutate state unless
the caller opts in.
"""

from __future__ import annotations

import sqlite3

from .audit import AuditLog


class ConfirmationRequired(Exception):
    """Raised when a destructive action lacks explicit confirmation."""


def _require_confirmation(confirmed: bool, action: str, identity_id: str) -> None:
    if not confirmed:
        raise ConfirmationRequired(
            f"RESP-CONF-01: {action} on {identity_id} needs explicit"
            " confirmation")


def revoke_key(conn: sqlite3.Connection, identity_id: str,
               confirmed: bool = False, dry_run: bool = True,
               audit: AuditLog | None = None) -> dict:
    """Revoke an API key / credential. Destructive: needs confirmation."""
    _require_confirmation(confirmed, "revoke", identity_id)
    if dry_run:
        result = {"action": "revoke", "identity_id": identity_id,
                  "dry_run": True, "effect": "none"}
    else:
        conn.execute("UPDATE identities SET status='revoked' WHERE id=?",
                     (identity_id,))
        conn.commit()
        result = {"action": "revoke", "identity_id": identity_id,
                  "dry_run": False, "effect": "status=revoked"}
    if audit is not None:
        audit.record("response.revoke", result)
    return result


def disable_identity(conn: sqlite3.Connection, identity_id: str,
                     confirmed: bool = False, dry_run: bool = True,
                     audit: AuditLog | None = None) -> dict:
    """Disable an identity. Destructive: needs confirmation."""
    _require_confirmation(confirmed, "disable", identity_id)
    if dry_run:
        result = {"action": "disable", "identity_id": identity_id,
                  "dry_run": True, "effect": "none"}
    else:
        conn.execute("UPDATE identities SET status='disabled' WHERE id=?",
                     (identity_id,))
        conn.commit()
        result = {"action": "disable", "identity_id": identity_id,
                  "dry_run": False, "effect": "status=disabled"}
    if audit is not None:
        audit.record("response.disable", result)
    return result


def force_rotation(conn: sqlite3.Connection, identity_id: str,
                   rotated_on: str = "2026-10-18",
                   dry_run: bool = True,
                   audit: AuditLog | None = None) -> dict:
    """Force a secret rotation. Non-destructive: no confirmation needed."""
    if dry_run:
        result = {"action": "rotate", "identity_id": identity_id,
                  "dry_run": True, "effect": "none"}
    else:
        conn.execute("UPDATE identities SET secret_rotated=? WHERE id=?",
                     (rotated_on, identity_id))
        conn.commit()
        result = {"action": "rotate", "identity_id": identity_id,
                  "dry_run": False, "effect": f"secret_rotated={rotated_on}"}
    if audit is not None:
        audit.record("response.rotate", result)
    return result


def respond_to_finding(conn: sqlite3.Connection, finding: dict,
                       confirmed: bool = False, dry_run: bool = True,
                       audit: AuditLog | None = None) -> dict:
    """Map a finding to the deterministic response playbook."""
    sig = finding["signal_id"]
    ident = finding["identity_id"]
    if sig in ("SIG-TRAVEL-01", "SIG-REUSE-01"):
        # Critical: revoke the credential (needs confirmation).
        return revoke_key(conn, ident.split(",")[0], confirmed=confirmed,
                          dry_run=dry_run, audit=audit)
    if sig in ("SIG-GEO-01", "SIG-SPIKE-01"):
        # High: force rotation (no confirmation needed).
        return force_rotation(conn, ident, dry_run=dry_run, audit=audit)
    raise ValueError(f"no playbook for signal {sig}")
