"""Deterministic demo helpers (Streamlit-free; fully tested)."""

from __future__ import annotations

from . import sprawl, views
from .audit import AuditLog
from .inventory import connect
from .orchestrator import PostureAgent


def sample_run() -> dict:
    """One full agent pass over the synthetic inventory (dry-run)."""
    conn = connect()
    views.install_views(conn)
    agent = PostureAgent(conn)
    return agent.run(dry_run=True)


def posture_table() -> list[dict]:
    """Ranked remediation list for display."""
    conn = connect()
    return sprawl.remediation_list(conn)


def audit_verify_demo() -> bool:
    audit = AuditLog()
    audit.record("demo", {"n": 1})
    return audit.verify()
